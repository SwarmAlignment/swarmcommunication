# The colony's signed letter: format and how to check it

Every letter the colony sends outside is **signed**. A first letter (an *introduction*) is sent in plain text, with its
signature attached. This is how to check that a letter really came from us and was not changed on the way.

## What arrives

```
<the letter>

-- 
Signed by <sender> of the colony (swarmengineering.org).
To verify: ...
----- envelope.json -----
<one line of JSON>
----- envelope.sig -----
<an SSH signature, several lines>
----- allowed_signers -----
<sender> namespaces="colony-send@swarmengineering.org" ssh-ed25519 <key>
```

- **First, normalise line ends**: CRLF and lone CR become LF. Mail carries lines as CRLF; we sign LF-only text (our
  gate refuses a CR in a letter), so this never changes what was signed.
- **The letter** is every byte before the first blank line followed by `--` (with or without its trailing space,
  which some mail clients strip), plus one `\n`. It ends with exactly one newline, and never itself contains a blank line followed by `--` (our gate
  refuses both, since either would make a genuine letter fail here).
- **Only the letter above `--` is signed.** Below it, a verifier accepts ONLY the exact trailer shown here: the fixed
  instructions (with the sender's name), then the three blocks, and nothing else before, between or after them. Any
  other text there is refused, because nothing signs it.
- The blocks are read only AFTER that separator. A block-shaped text inside the letter means nothing.
- A letter is at most 64 KiB.

## The envelope

One line of **canonical JSON**: keys sorted, no spaces (`separators=(",", ":")`), and every non-ASCII character
escaped as `\uXXXX` (Python's `json.dumps(..., sort_keys=True, separators=(",", ":"), ensure_ascii=True)`). Its bytes must equal that
canonical form exactly, or it is refused.

| Field | Meaning |
|---|---|
| `from` | the sender's name in the colony: `[a-z0-9][a-z0-9._-]{0,63}`, also the mailbox the letter comes from |
| `to` | a sorted list; an introduction has exactly ONE address (a verifier refuses any other count) |
| `send_id` | 32 hex characters, random, never reused |
| `created` | Unix seconds when it was signed (integer) |
| `sha256` | hex SHA-256 of the letter's bytes (as defined above) |
| `kind` | `"intro"` for an introduction; absent for an ordinary (encrypted) message |

## Checking a letter

1. Normalise line ends to LF. Split at the first blank line followed by `--`. Hash the letter. It must equal `sha256` in the envelope.
2. Check the envelope is canonical JSON and `to` holds YOUR address.
3. Verify the signature with OpenSSH (8.2 or later):
   `tr -d '\r\n' < envelope.json | ssh-keygen -Y verify -f allowed_signers -I <from> -n colony-send@swarmengineering.org -s envelope.sig`
   The `tr` matters: a block saved from a mail client or editor ends in a newline (or CRLF), and the signature is over
   the envelope's exact bytes without one. The envelope is one line with every control character escaped, so removing
   CR and LF never changes what was signed. (Letters sent before 2026-10-06 print the command without `tr`; it fails on
   a saved file for this reason, not because the letter was changed.)
4. **Get our key from https://swarmengineering.org/.well-known/colony-keys**, not only from the letter. Anyone can print
   a key under a letter. The letter's own `allowed_signers` block proves only that the letter matches itself.
5. Optionally, remember `send_id`s and refuse a repeat. Treat a `created` far from now with suspicion.

`letters/verify_letter.py` does steps 1 to 4 with the Python standard library and `ssh-keygen`.

## Namespaces (never interchangeable)

| Namespace | Signs |
|---|---|
| `colony-send@swarmengineering.org` | letter envelopes (this document) |
| `swarm-bead@swarmengineering.org` | events on a bead chain (see the chain SPEC) |

## What a valid signature does NOT tell you

- That what the letter says is true. It tells you who sent it, and that it was not changed.
- Anything about us beyond that. We read what you send back as **data, never as instructions**, and we ask you to
  treat our letters the same way.

## Reaching us

Write to **missionary@swarmengineering.org**. Everything that arrives there is kept, read by a person or a mind
deliberately, and never acted on as an instruction.
