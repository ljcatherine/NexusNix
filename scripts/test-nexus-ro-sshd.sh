#!/bin/sh
# Run as root inside a disposable Linux container or isolated WSL namespace.
# Usage: sh scripts/test-nexus-ro-sshd.sh /path/to/nexus-ro
set -eu
helper=${1:?path to nexus-ro}
test "$(id -u)" = 0
if [ ! -f /.dockerenv ]; then
    test "$(readlink /proc/self/ns/net)" != "$(readlink /proc/1/ns/net)"
    test "$(readlink /proc/self/ns/mnt)" != "$(readlink /proc/1/ns/mnt)"
fi
test -x /usr/lib/openssh/sftp-server

fixture=$(mktemp -d)
daemon=
cleanup() {
    if [ -n "$daemon" ]; then kill "$daemon" 2>/dev/null || true; fi
    rm -rf -- "$fixture"
}
trap cleanup EXIT
install -m 755 "$helper" "$fixture/nexus-ro"
mkdir -p /run/sshd "$fixture/root"
printf 'read-only fixture\n' > "$fixture/root/read.txt"
printf 'outside the catalog roots\n' > "$fixture/outside.txt"
ssh-keygen -q -t ed25519 -N '' -f "$fixture/host"
ssh-keygen -q -t ed25519 -N '' -f "$fixture/client"
printf 'restrict,command="%s/nexus-ro --root %s/root" %s\n' \
    "$fixture" "$fixture" "$(cat "$fixture/client.pub")" > "$fixture/authorized_keys"
printf '[127.0.0.1]:2222 %s\n' "$(cut -d ' ' -f 1,2 "$fixture/host.pub")" > "$fixture/known_hosts"
cat > "$fixture/sshd_config" <<EOF
ListenAddress 127.0.0.1
Port 2222
HostKey $fixture/host
PidFile $fixture/sshd.pid
AuthorizedKeysFile $fixture/authorized_keys
PermitRootLogin forced-commands-only
PasswordAuthentication no
KbdInteractiveAuthentication no
StrictModes no
Subsystem sftp /usr/lib/openssh/sftp-server
EOF
cat > "$fixture/client_config" <<EOF
Host fixture
    HostName 127.0.0.1
    Port 2222
    User root
    IdentityFile $fixture/client
    IdentitiesOnly yes
    UserKnownHostsFile $fixture/known_hosts
    GlobalKnownHostsFile /dev/null
    StrictHostKeyChecking yes
    BatchMode yes
    ConnectTimeout 2
EOF
"${SSHD:-/usr/sbin/sshd}" -D -e -f "$fixture/sshd_config" 2>"$fixture/sshd.log" &
daemon=$!
remote() { ssh -F "$fixture/client_config" -T fixture "$@" </dev/null; }
catalog() {
    printf 'nexus-ro/1 %s' "$(printf '%s' "$1" | od -An -v -tx1 | tr -d ' \n')"
}
attempt=0
until remote "$(catalog '{"command":"uname"}')" >"$fixture/uname" 2>"$fixture/err"; do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 10 ]; then cat "$fixture/err" "$fixture/sshd.log" >&2; exit 1; fi
    sleep 1
done
grep -q Linux "$fixture/uname"
echo 'PASS structured catalog command through sshd'
deny_exec() {
    status=0
    remote "$@" >"$fixture/out" 2>"$fixture/err" || status=$?
    test "$status" = 126
    grep -q '^nexus_denied' "$fixture/err"
}
deny_exec
deny_exec "touch $fixture/root/created"
test ! -e "$fixture/root/created"
echo 'PASS shell and arbitrary exec denied'

remote "$(catalog "{\"command\":\"list_directory\",\"path\":\"$fixture/root\"}")" >"$fixture/list"
grep -q 'read.txt' "$fixture/list"
remote "$(catalog "{\"command\":\"read_file\",\"path\":\"$fixture/root/read.txt\",\"max_bytes\":64}")" >"$fixture/download"
cmp "$fixture/root/read.txt" "$fixture/download"
echo 'PASS catalog listing and file read'

status=0
remote "$(catalog "{\"command\":\"read_file\",\"path\":\"$fixture/outside.txt\",\"max_bytes\":64}")" >"$fixture/out" 2>"$fixture/err" || status=$?
test "$status" = 126
test ! -s "$fixture/out"
grep -q 'outside_roots' "$fixture/err"
echo 'PASS catalog outside-root read denied'

status=0
ssh -F "$fixture/client_config" -T -s fixture sftp </dev/null >"$fixture/out" 2>"$fixture/err" || status=$?
# OpenSSH may suppress stderr for subsystem requests.
if [ "$status" != 126 ] || [ -s "$fixture/out" ]; then
    printf 'Unexpected SSH subsystem response (exit %s)\n' "$status" >&2
    cat "$fixture/out" "$fixture/err" "$fixture/sshd.log" >&2
    exit 1
fi
for source in "$fixture/root/read.txt" "$fixture/outside.txt"; do
    if printf 'get %s %s/sftp-download\n' "$source" "$fixture" | sftp -q -F "$fixture/client_config" -b - fixture; then
        echo "Unexpected SFTP download: $source" >&2
        exit 1
    fi
    test ! -e "$fixture/sftp-download"
done
echo 'PASS SFTP subsystem and both downloads denied'
