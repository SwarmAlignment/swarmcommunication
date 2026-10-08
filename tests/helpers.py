"""Shared test helpers: throwaway ssh keys for four synthetic minds, and a Chain builder. No real names."""
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from swarm import chain  # noqa: E402


KEYS = Path(tempfile.mkdtemp())
MINDS = ("ana", "bo", "judge", "sockpuppet")
for _m in MINDS:
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", _m, "-f", str(KEYS / _m)], check=True)
ALLOWED = KEYS / "allowed_signers"
ALLOWED.write_text("".join(f"{m} {(KEYS / (m + '.pub')).read_text().split()[0]} "
                           f"{(KEYS / (m + '.pub')).read_text().split()[1]}\n" for m in MINDS))


class Chain:
    def __init__(self, signed=True):
        self.path = Path(tempfile.mkdtemp()) / "c.jsonl"
        chain.create(self.path, "test", "bead", {"split": [25, 50, 25], "validators": ["judge"]})
        self.t, self.signed = 0, signed

    def at(self):
        self.t += 1
        return f"2026-09-27T00:00:{self.t:02d}"

    def add(self, event, who, bid, data=None, key=None):
        chain.append(self.path, event, who, bid, self.at(), data,
                     key_path=str(KEYS / (key or who)) if self.signed else None, unsigned=not self.signed)

    def bead(self, bid, who, inventory=(), grows=None, derived=None, verify_by="judge", close=True):
        self.add("posted", who, bid, {"title": bid, "x_swarm": {"contrib": [{"who": who, "share": 1}],
                                                                 "inventory": list(inventory)}})
        if grows:
            self.add("edge", who, bid, {"type": "grows", "to": grows})
        if derived:
            self.add("edge", who, bid, {"type": "derived_from", "to": derived})
        if close:
            self.add("done", who, bid, {"evidence": f"sha-{bid}"})
        if verify_by:
            self.add("verified", verify_by, bid)

    def replay(self):
        if self.signed:
            return chain.replay(self.path, str(ALLOWED))[1]
        return chain.replay_unverified(self.path)[1]
