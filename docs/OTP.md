# Nexus Desktop app-lock one-time passcode

Shared spec for Nexus Desktop (Windows, `ljcatherine/NexusWindows`; Linux,
`ljcatherine/NexusNix`) and the Nexus iOS app (`ljcatherine/Nexus`). All three
copies of this file must stay identical.

## What it does

Nexus Desktop can lock at launch and whenever its window is minimised. It
unlocks with a 4-digit code shown in the iOS app under
**Services → One Time Passcode**. The code changes every 20 seconds. It works
offline; nothing is sent over the network.

## Algorithm

RFC 6238 TOTP with:

| Parameter | Value |
|-----------|-------|
| HMAC      | SHA-1 |
| Period    | 20 s, T0 = 0 (Unix time) |
| Digits    | 4 (dynamic truncation, then mod 10 000, zero-padded) |
| Secret    | 10 random bytes (80 bits) |

The secret is shown as 16 RFC 4648 base32 characters in groups of four
(`ABCD-EFGH-IJKL-MNOP`). Parsers ignore case, spaces, dashes and `=`.

Reference vectors (secret = ASCII `1234567890` = base32 `GEZDGNBVGY3TQOJQ`),
computed with Python `hmac`/`hashlib` and asserted by both test suites:

| Unix time | Code |
|-----------|------|
| 0 | 1490 |
| 59 | 2045 |
| 1111111109 | 3293 |
| 2000000000 | 8631 |

## Pairing

1. Nexus Desktop → Settings → App lock → **Set up with iPhone** generates a new
   secret with the OS random number generator and shows it.
2. iOS → Services → One Time Passcode → type the key → **Pair with Nexus
   Desktop**. Stored in the Keychain (`nexus-desktop-otp-secret`,
   this-device-only, available when unlocked).
3. Type the code the iPhone shows into Nexus Desktop. The lock turns on only
   if that code verifies, so a mistyped key cannot lock the owner out.
   The secret is stored as `app-lock-otp-secret` (service `NexusDesktop`) in
   Windows Credential Manager or, on Linux, the Secret Service.

### More than one PC

The iPhone holds one key, so every PC uses the same key and the same code
unlocks all of them. Pair the first PC as above, then on each other PC:

1. On a PC that is already paired and unlocked: Settings → App lock →
   **Show key for another PC**, and enter the current iPhone code. The key is
   shown only after that code verifies (it counts as an attempt, like
   unlocking).
2. On the new PC: Settings → App lock → **Use the key from another PC**, type
   that key and the code the iPhone shows now. The key must decode to exactly
   10 bytes, and the lock turns on only if the code verifies.

Nothing changes on the iPhone. Each PC keeps its own attempt limit and replay
state.

**Pair again** (or **Set up with iPhone**) on any desktop makes a new key and
replaces the one on the iPhone: the old iPhone pairing, and every other PC
still using the old key, stop working until they use the new key. Removing the
pairing on the iPhone does not turn off the desktop lock.

## Verification (desktop)

- Accepts the codes for the previous, current and next 20 s step (±20 s clock
  skew).
- A step that unlocked once is never accepted again (no replay).
- Every 5 consecutive wrong codes lock entry out for 30 s, doubling each time
  up to 15 minutes. Failure count, lockout and last step are kept in
  `settings.json` so restarting the app does not reset them.

## Threat model

Sharing one key means a key read from any paired PC can produce codes for all
of them. That is why the key is shown only after a current code, and why the
desktop never stores it outside the OS keystore.

Four digits are guessable (about 3 in 10 000 per try with the skew window). The
attempt limit caps guessing at about 480 tries a day once the 15-minute lockout
is reached (roughly a 14% chance per day of persistent guessing), which is
enough to stop casual use of an unattended PC but is not strong authentication.
The lock hides the desktop UI from someone at an unlocked PC. It does not
protect against programs running as the same Windows or Linux user, who can
read Credential Manager or the Secret Service or edit `settings.json`
(`"app_lock": false` is also the recovery path if the iPhone is lost). Running
agents, terminals and monitoring keep working while locked.
