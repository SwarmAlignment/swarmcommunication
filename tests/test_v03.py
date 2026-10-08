"""v0.3: vigil's public-release MUSTs (review 6ab1e9810b). Each test FAILS on v0.2 (measured before the fix)."""
import hashlib
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from swarm import chain  # noqa: E402
from swarm.bead import Bead, canonical_bytes  # noqa: E402
from tests.helpers import ALLOWED, Chain  # noqa: E402


def rewrite_last(c, fn):
    """Replace the last line with fn(its text), re-linking nothing: the prev hash still points at the line before."""
    lines = c.path.read_bytes().splitlines()
    lines[-1] = fn(lines[-1].decode()).encode()
    c.path.write_bytes(b"\n".join(lines) + b"\n")


class Must1CanonicalLines(unittest.TestCase):
    def test_a_duplicate_key_in_an_event_is_refused_not_read_last_key_wins(self):
        c = Chain(signed=False)
        c.bead("x", "ana", close=False, verify_by=None)
        c.add("claimed", "ana", "x")
        rewrite_last(c, lambda t: t.replace('"by":"ana"', '"by":"ana","by":"mallory"'))
        with self.assertRaises(chain.BrokenChain):
            chain.replay_unverified(c.path)

    def test_a_non_canonical_line_is_refused_even_when_it_parses(self):
        c = Chain(signed=False)
        c.bead("x", "ana", close=False, verify_by=None)
        rewrite_last(c, lambda t: t.replace('":', '": ', 1))
        with self.assertRaises(chain.BrokenChain):
            chain.replay_unverified(c.path)


class Must2NoNaN(unittest.TestCase):
    def test_a_nan_share_is_refused(self):
        with self.assertRaises(ValueError):
            Bead(id="b", title="t", contrib=[{"who": "a", "share": float("nan")}])

    def test_shares_must_each_be_in_zero_to_one(self):
        # each of these SUMS to 1, so v0.2's sum check accepted it (measured); only a per-share check refuses them
        for bad in ([1.5, -0.5], ["1"], [True], [2, -1]):
            with self.assertRaises(ValueError, msg=repr(bad)):
                Bead(id="b", title="t", contrib=[{"who": f"m{i}", "share": v} for i, v in enumerate(bad)])

    def test_nan_is_never_serialised(self):
        with self.assertRaises(ValueError):
            canonical_bytes({"share": float("nan")})

    def test_an_overflowing_float_is_brokenchain_not_a_crash(self):
        """iktomi: 1e400 became inf and _strict raised a plain ValueError outside its try."""
        for num in ("1e400", "-1e999"):
            c = Chain(signed=False)
            c.bead("x", "ana", close=False, verify_by=None)
            rewrite_last(c, lambda t: t.replace('"share":1', '"share":' + num))
            with self.assertRaises(chain.BrokenChain, msg=num):
                chain.replay_unverified(c.path)

    def test_a_nan_in_a_chain_line_is_refused(self):
        c = Chain(signed=False)
        c.bead("x", "ana", close=False, verify_by=None)
        rewrite_last(c, lambda t: t.replace('"share":1', '"share":NaN'))
        with self.assertRaises(chain.BrokenChain):
            chain.replay_unverified(c.path)


class V032HostileSize(unittest.TestCase):
    """neci / amatl (w-8f181d77, scope review point 2): a hostile chain must not exhaust the stack or memory."""
    def test_amatl_ten_thousand_nested_arrays_is_brokenchain_not_recursionerror(self):
        c = Chain(signed=False)
        c.bead("x", "ana", close=False, verify_by=None)
        deep = "[" * 10000 + "]" * 10000
        rewrite_last(c, lambda t: t.replace('"inventory":[]', '"inventory":' + deep))
        with self.assertRaises(chain.BrokenChain):
            chain.replay_unverified(c.path)

    def test_an_ordinary_nested_bead_still_replays(self):
        c = Chain(signed=False)
        c.bead("x", "ana", inventory=["rust", "sql"], close=False, verify_by=None)
        self.assertIn("x", chain.replay_unverified(c.path)[1])

    def test_a_line_over_the_line_cap_is_refused(self):
        c = Chain(signed=False)
        c.bead("x", "ana", close=False, verify_by=None)
        rewrite_last(c, lambda t: t.replace('"title":"x"', '"title":"' + "a" * (chain.MAX_LINE_BYTES + 1) + '"'))
        with self.assertRaises(chain.BrokenChain):
            chain.replay_unverified(c.path)

    def test_a_file_that_grows_after_stat_is_still_bounded(self):
        """iktomi / amatl: stat() says small, the read sees more. The read is capped at MAX_CHAIN_BYTES + 1."""
        c = Chain(signed=False)
        c.bead("x", "ana", close=False, verify_by=None)
        real_stat, saved = chain.Path.stat, chain.MAX_CHAIN_BYTES
        chain.MAX_CHAIN_BYTES = c.path.stat().st_size - 1
        class Small:
            st_size = 1
        chain.Path.stat = lambda self, *a, **k: Small()          # stat lies, as a growing file would
        try:
            with self.assertRaises(chain.BrokenChain):
                chain.replay_unverified(c.path)
        finally:
            chain.Path.stat, chain.MAX_CHAIN_BYTES = real_stat, saved

    def test_a_file_over_the_chain_cap_is_refused_before_it_is_read(self):
        c = Chain(signed=False)
        c.bead("x", "ana", close=False, verify_by=None)
        saved = chain.MAX_CHAIN_BYTES
        chain.MAX_CHAIN_BYTES = c.path.stat().st_size - 1
        try:
            with self.assertRaises(chain.BrokenChain):
                chain.replay_unverified(c.path)
            with self.assertRaises(chain.BrokenChain):
                chain.replay(c.path, str(ALLOWED))
        finally:
            chain.MAX_CHAIN_BYTES = saved


class V033MalformedAnchor(unittest.TestCase):
    """amatl #8770269 via neci: a malformed anchor raised AttributeError or TypeError instead of refusing."""
    def _with_policy(self, policy_json):
        c = Chain(signed=False)
        c.bead("x", "ana", close=False, verify_by=None)
        lines = c.path.read_bytes().splitlines()
        first = json.loads(lines[0])
        first["anchor"]["policy"] = json.loads(policy_json)
        new0 = canonical_bytes(first)
        rest = [new0]                                   # re-link line 2 to the new anchor so only the shape is wrong
        prev = hashlib.sha256(new0).hexdigest()
        for raw in lines[1:]:
            e = json.loads(raw); e["prev"] = prev
            b = canonical_bytes(e); rest.append(b); prev = hashlib.sha256(b).hexdigest()
        c.path.write_bytes(b"\n".join(rest) + b"\n")
        return c

    def test_each_malformed_policy_is_brokenchain(self):
        for bad in ("null", "[]", '{"validators": [{}]}', '{"validators": "judge"}', '{"validators": [""]}'):
            with self.assertRaises(chain.BrokenChain, msg=bad):
                chain.replay_unverified(self._with_policy(bad).path)

    def test_a_well_formed_policy_still_replays(self):
        self.assertIn("x", chain.replay_unverified(self._with_policy('{"validators": ["judge"]}').path)[1])


class Must3VerifyByDefault(unittest.TestCase):
    def test_replay_without_signers_is_refused(self):
        c = Chain()
        c.bead("x", "ana")
        with self.assertRaises((TypeError, ValueError)):
            chain.replay(c.path)
        with self.assertRaises(ValueError):
            chain.replay(c.path, None)

    def test_the_unverified_view_is_marked_and_counts_no_verification(self):
        c = Chain()
        c.bead("x", "ana")
        anchor, beads = chain.replay_unverified(c.path)
        self.assertTrue(anchor["_unverified"])
        self.assertEqual(beads["x"].verifications, [])
        anchor, beads = chain.replay(c.path, str(ALLOWED))
        self.assertNotIn("_unverified", anchor)
        self.assertEqual(len(beads["x"].verifications), 1)

    def test_append_signs_by_default(self):
        c = Chain()
        with self.assertRaises(ValueError):
            chain.append(c.path, "note", "ana", "x", "2026-09-28T00:00:00")
        chain.append(c.path, "note", "ana", "x", "2026-09-28T00:00:00", unsigned=True)   # an explicit choice


class Shoulds(unittest.TestCase):
    def test_expect_anchor_pins_line_1(self):
        c = Chain()
        c.bead("x", "ana")
        good = hashlib.sha256(c.path.read_bytes().splitlines()[0]).hexdigest()
        chain.replay(c.path, str(ALLOWED), expect_anchor=good)
        with self.assertRaises(chain.BrokenChain):
            chain.replay(c.path, str(ALLOWED), expect_anchor="0" * 64)

    def test_a_malformed_edge_is_a_refusal_not_a_crash(self):
        c = Chain(signed=False)
        c.bead("x", "ana", close=False, verify_by=None)
        c.add("edge", "ana", "x", {"type": "grows"})              # no "to"
        with self.assertRaises(chain.BrokenChain):
            chain.replay_unverified(c.path)


if __name__ == "__main__":
    unittest.main()
