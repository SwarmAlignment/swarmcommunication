"""Tests for swarmcommunication: the bead record and the chain, on synthetic chains (no real names, no live ledger)."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from swarm import chain  # noqa: E402
from swarm.bead import Bead  # noqa: E402
from tests.helpers import ALLOWED, KEYS, Chain  # noqa: E402,F401


class Record(unittest.TestCase):
    def test_a_bead_round_trips_as_a_beads_record_plus_x_swarm(self):
        b = Bead(id="b1", title="t", contrib=[{"who": "ana", "share": 1}], inventory=["rust"], evidence="abc")
        j = b.to_json()
        self.assertIn("x_swarm", j)
        self.assertNotIn("contrib", j)
        self.assertEqual(Bead.from_json(j), b)

    def test_contrib_shares_must_sum_to_one(self):
        with self.assertRaises(ValueError):
            Bead(id="b", title="t", contrib=[{"who": "a", "share": 0.5}, {"who": "b", "share": 0.4}])

    def test_signing_bytes_are_canonical_and_exclude_the_signature(self):
        b = Bead(id="b", title="t", contrib=[{"who": "a", "share": 1}])
        before = b.signing_bytes()
        b.sig = {"signer": "a", "namespace": "swarm-bead@swarmengineering.org", "sshsig": "SIG"}
        self.assertEqual(b.signing_bytes(), before)
        self.assertNotIn(b" ", before.split(b'"title"')[0])


class ChainFile(unittest.TestCase):
    def test_state_is_derived_by_replay_and_a_chain_is_never_recreated(self):
        c = Chain()
        c.bead("x", "ana")
        self.assertEqual(c.replay()["x"].status, "closed")
        with self.assertRaises(FileExistsError):
            chain.create(c.path, "again", "bead", {})


class YollotlMusts(unittest.TestCase):
    def test_mustB_an_unsigned_chain_counts_no_verification(self):
        c = Chain(signed=False)
        c.bead("beat", "ana")
        c.bead("track", "bo", derived="beat")
        self.assertEqual(c.replay()["track"].verifications, [])     # the judge's `verified` is not counted unsigned

    def test_mustB_a_verified_event_signed_with_another_key_breaks_the_chain(self):
        c = Chain()
        c.bead("track", "bo", verify_by=None)
        c.add("verified", "judge", "track", key="sockpuppet")        # claims to be judge, signs as sockpuppet
        with self.assertRaises(chain.BrokenChain):
            c.replay()

    def test_mustB_editing_a_signed_event_breaks_it(self):
        c = Chain()
        c.bead("x", "ana")
        lines = c.path.read_bytes().splitlines()
        lines[-1] = lines[-1].replace(b'"by":"judge"', b'"by":"bo"')
        c.path.write_bytes(b"\n".join(lines) + b"\n")
        with self.assertRaises(chain.BrokenChain):
            c.replay()

    def test_mustA_dependencies_and_comments_have_exactly_the_beads_rust_fields(self):
        c = Chain()
        c.bead("beat", "ana")
        c.bead("track", "bo", derived="beat")
        c.add("note", "bo", "track", {"text": "hi"})
        t = c.replay()["track"]
        self.assertEqual(set(t.dependencies[0]), {"issue_id", "depends_on_id", "type", "created_at", "created_by",
                                                  "metadata", "thread_id"})
        self.assertEqual(set(t.comments[0]), {"id", "issue_id", "author", "text", "created_at"})


class NeciMusts(unittest.TestCase):
    def test_must1_non_canonical_or_duplicate_key_bytes_are_refused(self):
        b = Bead(id="b", title="t", contrib=[{"who": "a", "share": 1}])
        from swarm.bead import canonical_bytes
        good = canonical_bytes(b.to_json())
        self.assertEqual(Bead.from_bytes(good), b)
        with self.assertRaises(ValueError):
            Bead.from_bytes(good.replace(b'"id":"b"', b'"id": "b"'))
        with self.assertRaises(ValueError):
            Bead.from_bytes(b'{"id":"b","id":"c","title":"t"}')

    def test_must2_dropping_or_reordering_an_event_breaks_the_chain(self):
        c = Chain()
        c.bead("x", "ana")
        lines = c.path.read_bytes().splitlines()
        c.path.write_bytes(b"\n".join(lines[:2] + lines[3:]) + b"\n")      # drop one event (e.g. a 'done')
        with self.assertRaises(chain.BrokenChain):
            chain.replay_unverified(c.path)
        c.path.write_bytes(b"\n".join([lines[0], lines[2], lines[1]] + lines[3:]) + b"\n")
        with self.assertRaises(chain.BrokenChain):
            chain.replay_unverified(c.path)

    def test_must3_a_verification_outside_the_validator_set_is_not_counted(self):
        c = Chain()
        c.bead("beat", "ana")
        c.bead("track", "bo", derived="beat", verify_by="sockpuppet")
        self.assertEqual(c.replay()["track"].verifications, [])     # sockpuppet is not in the validator set


class V01Shoulds(unittest.TestCase):
    def test_expect_head_catches_a_truncated_tail(self):
        import hashlib
        c = Chain()
        c.bead("x", "ana")
        head = hashlib.sha256(c.path.read_bytes().splitlines()[-1]).hexdigest()
        chain.replay(c.path, str(ALLOWED), expect_head=head)
        c.path.write_bytes(b"\n".join(c.path.read_bytes().splitlines()[:-1]) + b"\n")
        chain.replay(c.path, str(ALLOWED))                       # the links alone still hold
        with self.assertRaises(chain.BrokenChain):
            chain.replay(c.path, str(ALLOWED), expect_head=head)

    def test_done_by_someone_else_is_ignored(self):
        c = Chain()
        c.bead("x", "ana", close=False, verify_by=None)
        c.add("done", "bo", "x", {"evidence": "stolen"})
        self.assertEqual(c.replay()["x"].status, "open")
        c.add("claimed", "bo", "x")
        c.add("done", "bo", "x", {"evidence": "mine"})
        self.assertEqual(c.replay()["x"].status, "closed")

    def test_a_second_posted_cannot_overwrite_a_bead(self):
        c = Chain()
        c.bead("x", "ana", close=False, verify_by=None)
        c.add("posted", "bo", "x", {"title": "hijack", "x_swarm": {"contrib": [{"who": "bo", "share": 1}]}})
        self.assertEqual(c.replay()["x"].title, "x")


if __name__ == "__main__":
    unittest.main()
