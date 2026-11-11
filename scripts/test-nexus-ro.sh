#!/bin/sh
# Acceptance test for the nexus-ro helper in a disposable Linux environment
# (e.g. WSL). Never run against the Debian server.
# Usage: sh scripts/test-nexus-ro.sh path/to/nexus-ro
set -u
BIN=${1:?path to nexus-ro}
T=$(mktemp -d /tmp/nexus-ro-test.XXXXXX)
trap 'rm -rf "$T"' EXIT
mkdir -p "$T/root/repo" "$T/root/.ssh"
printf 'hello\nworld\n' > "$T/root/a.txt"
printf 'secret' > "$T/root/.ssh/id_ed25519"
ln -s /etc/passwd "$T/root/link-out"
ln -s "$T/root/a.txt" "$T/root/link-in"
R="$T/root"
pass=0; fail=0
req() { printf 'nexus-ro/1 %s' "$(printf '%s' "$1" | od -An -v -tx1 | tr -d ' \n')"; }
# run NAME EXPECT_EXIT ORIGINAL [STDOUT_GREP]
run() {
  out=$(SSH_ORIGINAL_COMMAND="$3" "$BIN" --root "$R" 2>"$T/err"); code=$?
  ok=1
  [ "$code" = "$2" ] || ok=0
  if [ -n "${4:-}" ]; then printf '%s\n%s' "$out" "$(cat "$T/err")" | grep -q -- "$4" || ok=0; fi
  if [ $ok = 1 ]; then pass=$((pass+1)); echo "PASS $1"; else fail=$((fail+1)); echo "FAIL $1 (exit $code)"; echo "$out" | head -3; head -3 "$T/err"; fi
}
if command -v git >/dev/null; then
  git -C "$R/repo" init -q && printf 'x\n' > "$R/repo/f" && git -C "$R/repo" -c user.name=t -c user.email=t@t add f && git -C "$R/repo" -c user.name=t -c user.email=t@t commit -qm init
  before=$(find "$R/repo/.git" -type f -newer "$R/a.txt" | wc -l; stat -c %Y "$R/repo/.git/index")
fi
# Shells and plain commands are refused.
run "no command (interactive shell)" 126 "" "not_a_request"
SSH_ORIGINAL_COMMAND= ; unset SSH_ORIGINAL_COMMAND
out=$("$BIN" --root "$R" 2>&1); [ $? = 126 ] && { pass=$((pass+1)); echo "PASS unset command"; } || { fail=$((fail+1)); echo "FAIL unset command"; }
run "plain id" 126 "id" "not_a_request"
run "touch" 126 "touch $T/pwned" "not_a_request"
[ ! -e "$T/pwned" ] && { pass=$((pass+1)); echo "PASS touch had no effect"; } || { fail=$((fail+1)); echo "FAIL touch created a file"; }
run "scp sink" 126 "scp -t $T" "not_a_request"
run "garbage hex" 126 "nexus-ro/1 zz" "malformed"
run "unknown command" 126 "$(req '{"command":"rm_rf","path":"/"}')" "malformed"
# Catalog requests work.
run "uname" 0 "$(req '{"command":"uname"}')" "Linux"
run "os-release" 0 "$(req '{"command":"os_release"}')" "NAME="
run "metrics" 0 "$(req '{"command":"metrics"}')" "nexus_metrics"
run "read file" 0 "$(req "{\"command\":\"read_file\",\"path\":\"$R/a.txt\",\"max_bytes\":5}")" "^hello$"
run "read via in-root symlink" 0 "$(req "{\"command\":\"read_file\",\"path\":\"$R/link-in\",\"max_bytes\":100}")" "world"
run "hash file" 0 "$(req "{\"command\":\"hash_file\",\"path\":\"$R/a.txt\"}")" "$(sha256sum "$R/a.txt" | cut -c1-64)"
run "list dir" 0 "$(req "{\"command\":\"list_directory\",\"path\":\"$R\"}")" "a.txt"
run "find" 0 "$(req "{\"command\":\"find_files\",\"root\":\"$R\",\"max_depth\":3}")" "a.txt"
# Refusals after resolution.
run "symlink escaping roots" 126 "$(req "{\"command\":\"read_file\",\"path\":\"$R/link-out\",\"max_bytes\":100}")" "outside_roots"
run "outside roots" 126 "$(req '{"command":"read_file","path":"/etc/passwd","max_bytes":100}')" "outside_roots"
run "sensitive" 126 "$(req "{\"command\":\"read_file\",\"path\":\"$R/.ssh/id_ed25519\",\"max_bytes\":100}")" "sensitive"
run "unit injection" 126 "$(req '{"command":"service_status","unit":"x; touch /tmp/p"}')" "invalid"
run "dotdot" 126 "$(req "{\"command\":\"read_file\",\"path\":\"$R/../root/a.txt\",\"max_bytes\":9}")" "invalid"
if command -v git >/dev/null; then
  run "git status" 0 "$(req "{\"command\":\"git_status\",\"repo\":\"$R/repo\"}")" "branch"
  run "git log" 0 "$(req "{\"command\":\"git_log\",\"repo\":\"$R/repo\",\"count\":5}")" "init"
  run "git show" 0 "$(req "{\"command\":\"git_show_file\",\"repo\":\"$R/repo\",\"rev\":\"HEAD\",\"path\":\"f\"}")" "^x$"
  run "git rev option injection" 126 "$(req "{\"command\":\"git_show_file\",\"repo\":\"$R/repo\",\"rev\":\"--output=$T/o\",\"path\":\"f\"}")" "invalid"
  after=$(find "$R/repo/.git" -type f -newer "$R/a.txt" | wc -l; stat -c %Y "$R/repo/.git/index")
  [ "$before" = "$after" ] && { pass=$((pass+1)); echo "PASS git wrote nothing"; } || { fail=$((fail+1)); echo "FAIL git changed .git"; }
fi
run "external SFTP refused" 126 "/usr/lib/openssh/sftp-server" "not_a_request"
run "internal SFTP refused" 126 "internal-sftp" "not_a_request"
echo "passed $pass, failed $fail"
[ $fail = 0 ]
