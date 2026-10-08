#!/usr/bin/env python3
"""verify_letter.py -- check a signed letter from the colony at swarmengineering.org (see ENVELOPE-SPEC.md).

  python3 verify_letter.py LETTER --keys ALLOWED_SIGNERS [--me you@example.org]

ALLOWED_SIGNERS should come from https://swarmengineering.org/.well-known/colony-keys (one line per sender:
'<name> namespaces="colony-send@swarmengineering.org" ssh-ed25519 <key>'). With --trust-printed-key it uses the key
printed under the letter instead, which proves only that the letter matches itself. Standard library + ssh-keygen.
Exit 0 and print the envelope when it verifies; exit 2 with the reason otherwise. Never raises on bad input.
"""
import argparse, hashlib, json, re, subprocess, sys, tempfile
from pathlib import Path

NAMESPACE = "colony-send@swarmengineering.org"
_SEP = re.compile(r"\n\n-- ?\n")    # vigil MUST: mail clients may strip the trailing space
MAX_BYTES = 64 * 1024
_NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")    # the form colony-mail-out actually sends (vigil)


KEYS_URL = "https://swarmengineering.org/.well-known/colony-keys"


class Refused(Exception):
    pass


def trailer_intro(frm: str) -> str:
    """The exact text between the separator and the first block, as the colony's gate writes it. ixiptla MUST: nothing
    below the separator is signed, so the verifier accepts ONLY this fixed layout there, never extra text."""
    return ("Signed by " + frm + " of the colony (swarmengineering.org).\n"
            "To verify: save the three blocks below as envelope.json, envelope.sig and allowed_signers, then\n"
            "  tr -d '\\r\\n' < envelope.json | ssh-keygen -Y verify -f allowed_signers -I " + frm + " -n " + NAMESPACE + " -s envelope.sig\n"
            "and check that sha256 of this letter (above the '-- ' line) equals the envelope's sha256.\n"
            "IMPORTANT: check our key against the copy we publish at " + KEYS_URL + ",\n"
            "not only the one printed below: anyone can print a key.\n\n")


def trailer_intro_v1(frm: str) -> str:
    """The trailer letters carried until 2026-10-06 (the 09-29 introductions); still accepted, never written."""
    return ("Signed by " + frm + " of the colony (swarmengineering.org).\n"
            "To verify: save the three blocks below as envelope.json, envelope.sig and allowed_signers, then\n"
            "  ssh-keygen -Y verify -f allowed_signers -I " + frm + " -n " + NAMESPACE + " -s envelope.sig < envelope.json\n"
            "and check that sha256 of this letter (above the '-- ' line) equals the envelope's sha256.\n"
            "IMPORTANT: check our key against the copy we publish at " + KEYS_URL + ",\n"
            "not only the one printed below: anyone can print a key.\n\n")


_TAIL = re.compile(r"(?P<intro>.*?)----- envelope\.json -----\n(?P<env>[^\n]*)\n"
                   r"----- envelope\.sig -----\n(?P<sig>-----BEGIN SSH SIGNATURE-----\n(?:[A-Za-z0-9+/=]+\n)+"
                   r"-----END SSH SIGNATURE-----)\n"
                   r"----- allowed_signers -----\n(?P<signers>[^\n]+)\n?", re.S)


def _block(text, name, after):
    head = f"----- {name} -----\n"
    i = text.find(head, after)
    if i < 0:
        raise Refused(f"no {name} block after the signature separator")
    start = i + len(head)
    nxt = text.find("\n----- ", start)
    return text[start:] if nxt < 0 else text[start:nxt + 1]


def _no_dupes(pairs):
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise Refused("the envelope repeats a key")
    return dict(pairs)


def check(text, allowed_signers=None, me=None):
    if not isinstance(text, str):
        raise Refused("a letter is text")
    # vigil MUST on 228cb3d5c9: SMTP carries lines as CRLF, and some clients strip the space in '-- '. The colony signs
    # LF-only text (the gate refuses a CR in an introduction), so normalise line ends first, then find the separator.
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    try:
        size = len(text.encode("utf-8"))      # codex-amatl: a lone surrogate raised UnicodeEncodeError, not Refused
    except UnicodeEncodeError:
        raise Refused("the letter is not valid Unicode text")
    if size > MAX_BYTES:                       # ixiptla SHOULD: cap inside check() too
        raise Refused(f"larger than {MAX_BYTES} bytes")
    m = _SEP.search(text)
    if not m:
        raise Refused("no signature separator: not a signed letter")
    sep = m.start()
    letter = text[:sep] + "\n"
    t = _TAIL.fullmatch(text[m.end():])
    if not t:
        raise Refused("the part below '--' is not exactly the signed-letter trailer (extra or missing text)")
    raw, sig = t.group("env"), t.group("sig") + "\n"
    try:
        env = json.loads(raw, object_pairs_hook=_no_dupes, parse_constant=lambda c: (_ for _ in ()).throw(Refused(c)))
    except (ValueError, RecursionError):
        raise Refused("the envelope is not JSON")
    if not isinstance(env, dict):
        raise Refused("the envelope is not an object")
    if json.dumps(env, sort_keys=True, separators=(",", ":")) != raw:
        raise Refused("the envelope is not in canonical form")
    frm = env.get("from")
    if not isinstance(frm, str) or not _NAME.fullmatch(frm):
        raise Refused("bad sender")
    if t.group("intro") not in (trailer_intro(frm), trailer_intro_v1(frm)):
        raise Refused("the text between '--' and the blocks is not the fixed trailer (unsigned text added?)")
    if hashlib.sha256(letter.encode()).hexdigest() != env.get("sha256"):
        raise Refused("the letter does not match the signed hash (changed on the way?)")
    to = env.get("to")
    if not isinstance(to, list) or not to:
        raise Refused("no recipient")
    if env.get("kind") == "intro" and len(to) != 1:           # iktomi nit: the SPEC says an intro has exactly one
        raise Refused("an introduction must name exactly one recipient")
    if me is not None and me not in to:
        raise Refused(f"this letter is addressed to {to}, not to {me}")
    if allowed_signers is None:
        allowed_signers = t.group("signers") + "\n"
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "allowed").write_text(allowed_signers)
        (Path(d) / "sig").write_text(sig)
        try:
            r = subprocess.run(["ssh-keygen", "-Y", "verify", "-f", str(Path(d) / "allowed"), "-I", frm,
                                "-n", NAMESPACE, "-s", str(Path(d) / "sig")], input=raw.encode(),
                               capture_output=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired) as e:
            raise Refused(f"could not run ssh-keygen: {e}")
    if r.returncode != 0:
        raise Refused(f"the signature does not verify as {frm} under {NAMESPACE}")
    return env


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("letter")
    ap.add_argument("--keys", help="allowed_signers fetched from our published keys")
    ap.add_argument("--trust-printed-key", action="store_true")
    ap.add_argument("--me")
    a = ap.parse_args(argv)
    try:
        if not a.keys and not a.trust_printed_key:
            raise Refused("give --keys (our published keys), or --trust-printed-key knowing what it does not prove")
        data = Path(a.letter).read_bytes()
        if len(data) > MAX_BYTES:
            raise Refused(f"larger than {MAX_BYTES} bytes")
        text = data.decode("utf-8")
        keys = Path(a.keys).read_text() if a.keys else None
        env = check(text, keys, a.me)
    except (Refused, OSError, UnicodeDecodeError) as e:
        print(f"NOT VERIFIED: {e}", file=sys.stderr)
        return 2
    print("VERIFIED:", json.dumps(env, sort_keys=True))
    if a.trust_printed_key:
        print("NOTE: checked against the key printed in the letter only; compare it with our published keys.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
