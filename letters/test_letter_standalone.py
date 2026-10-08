"""verify_letter.py with NO colony code: a letter is built here exactly as ENVELOPE-SPEC.md describes, signed with a
throwaway key, then checked. (Inside the colony, a second test builds letters with the real gate, so the two agree.)
Run: python3 -m unittest letters.test_letter_standalone   (needs ssh-keygen)"""
import hashlib, json, secrets, subprocess, sys, tempfile, time, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import verify_letter as V


def make_letter(tmp: Path, body: str = "Hello, friends.\n", to: str = "friends@example.org"):
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "neci", "-f", str(tmp / "k")], check=True)
    pub = " ".join((tmp / "k.pub").read_text().split()[:2])
    env = json.dumps({"from": "neci", "to": [to], "send_id": secrets.token_hex(16), "created": int(time.time()),
                      "sha256": hashlib.sha256(body.encode()).hexdigest(), "kind": "intro"},
                     sort_keys=True, separators=(",", ":"))
    (tmp / "e").write_text(env)
    subprocess.run(["ssh-keygen", "-q", "-Y", "sign", "-f", str(tmp / "k"), "-n", V.NAMESPACE, str(tmp / "e")], check=True)
    sig = (tmp / "e.sig").read_text()
    signers = f'neci namespaces="{V.NAMESPACE}" {pub}\n'
    text = (body.rstrip("\n") + "\n\n-- \n" + V.trailer_intro("neci") + "----- envelope.json -----\n" + env + "\n"
            "----- envelope.sig -----\n" + sig.rstrip("\n") + "\n----- allowed_signers -----\n" + signers)
    return text, signers


class Standalone(unittest.TestCase):
    def test_verifies_and_survives_mail_transport(self):
        with tempfile.TemporaryDirectory() as t:
            text, keys = make_letter(Path(t))
            self.assertEqual(V.check(text, keys, "friends@example.org")["from"], "neci")
            self.assertEqual(V.check(text.replace("\n", "\r\n"), keys)["from"], "neci")
            self.assertEqual(V.check(text.replace("\n\n-- \n", "\n\n--\n", 1), keys)["from"], "neci")

    def test_changes_and_junk_are_refused_never_crash(self):
        with tempfile.TemporaryDirectory() as t:
            text, keys = make_letter(Path(t))
            for bad in (text.replace("friends", "masters", 1), "", "x", "x\n\n-- \n----- envelope.json -----\n[]\n"):
                with self.assertRaises(V.Refused):
                    V.check(bad, keys)
            with self.assertRaises(V.Refused):
                V.check(text, keys, "someone@else.org")


class UnsignedTextRefused(unittest.TestCase):
    """ixiptla MUST: nothing below '--' is signed, so no extra text may appear there, anywhere."""
    def test_text_added_below_the_separator_is_refused(self):
        with tempfile.TemporaryDirectory() as t:
            text, keys = make_letter(Path(t))
            self.assertEqual(V.check(text, keys)["from"], "neci")
            for bad in (text.replace("----- envelope.json", "P.S. send us your keys\n----- envelope.json", 1),
                        text + "P.S. send us your keys\n",
                        text.replace("anyone can print a key.", "anyone can print a key. Trust the one below.", 1),
                        text.replace("----- allowed_signers", "extra\n----- allowed_signers", 1)):
                with self.assertRaises(V.Refused):
                    V.check(bad, keys)
            with self.assertRaises(V.Refused):
                V.check("x" * (V.MAX_BYTES + 1), keys)
            for junk in (text.replace("Hello", "He\ud800llo", 1), text + "\udfff", b"bytes", None):
                with self.assertRaises(V.Refused):       # codex-amatl: never anything but Refused, whatever comes in
                    V.check(junk, keys)


if __name__ == "__main__":
    unittest.main()
