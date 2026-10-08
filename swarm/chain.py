"""A chain: an append-only JSONL file of events. The first line is the anchor (name, currency, policy). A bead's state
is DERIVED by replaying events, never written. That is all the chain does.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import subprocess
import tempfile
from pathlib import Path

from .bead import SIG_NAMESPACE, Bead, canonical_bytes

EVENTS = ("posted", "claimed", "done", "verified", "note", "edge")


def create(path: Path, name: str, currency: str, policy: dict) -> None:
    path = Path(path)
    if path.exists():
        raise FileExistsError(f"{path}: a chain is never re-created over an existing one")
    # neci MUST 3: the anchor names the validator set; only their `verified` counts.
    policy = dict(policy)
    policy.setdefault("validators", [])
    path.write_bytes(canonical_bytes({"anchor": {"name": name, "currency": currency, "policy": policy},
                                      "prev": None}) + b"\n")


class BrokenChain(ValueError):
    """An event is missing, moved, re-ordered or truncated: the hash links no longer hold (neci MUST 2)."""


def _last_hash(path: Path) -> str:
    lines = Path(path).read_bytes().splitlines()
    return hashlib.sha256(lines[-1]).hexdigest()


def _ssh(args: list, data: bytes) -> subprocess.CompletedProcess:
    return subprocess.run(["ssh-keygen", *args], input=data, capture_output=True)


def append(path: Path, event: str, by: str, bead_id: str, at: str, data: dict | None = None,
           key_path: str | None = None, unsigned: bool = False) -> None:
    """Append one event, linked to the one before it, and SIGN it (yollotl MUST B): an SSHSIG in the bead namespace over
    the canonical bytes of the event without its sig. Since v0.3 signing is the default (vigil MUST 3): with no key_path,
    append refuses unless the caller says unsigned=True, so an unsigned event is always a choice, never an accident."""
    if event not in EVENTS:
        raise ValueError(f"unknown event {event!r}")
    if not key_path and not unsigned:
        raise ValueError("append signs by default: pass key_path, or unsigned=True for an event that proves nothing")
    rec = {"event": event, "by": by, "bead": bead_id, "at": at, "data": data or {}, "prev": _last_hash(path)}
    if key_path:
        r = _ssh(["-Y", "sign", "-n", SIG_NAMESPACE, "-f", key_path, "-q"], canonical_bytes(rec))
        if r.returncode != 0:
            raise RuntimeError(f"signing failed: {r.stderr.decode(errors='replace').strip()}")
        rec["sig"] = {"signer": by, "namespace": SIG_NAMESPACE, "sshsig": r.stdout.decode()}
    with open(path, "ab") as f:
        f.write(canonical_bytes(rec) + b"\n")


def _verify(e: dict, allowed_signers: str) -> bool:
    sig = e.get("sig") or {}
    if sig.get("signer") != e["by"] or sig.get("namespace") != SIG_NAMESPACE or not sig.get("sshsig"):
        return False
    body = {k: v for k, v in e.items() if k != "sig"}
    with tempfile.NamedTemporaryFile("w", suffix=".sig", delete=False) as f:
        f.write(sig["sshsig"])
    try:
        r = _ssh(["-Y", "verify", "-f", allowed_signers, "-I", e["by"], "-n", SIG_NAMESPACE, "-s", f.name],
                 canonical_bytes(body))
        return r.returncode == 0
    finally:
        os.unlink(f.name)


# vigil / scope review point 2, measured by amatl: a hostile chain must not exhaust memory or the stack. 10000 nested
# arrays on one line raised RecursionError inside json.loads, and _replay read the whole file with no bound. The caps
# are generous for real chains (a bead line is a few KB) and are checked BEFORE the bytes are parsed or even read.
MAX_DEPTH = 64
MAX_LINE_BYTES = 1 << 20          # 1 MiB
MAX_CHAIN_BYTES = 64 << 20        # 64 MiB


def _depth_ok(raw: bytes) -> bool:
    """Bracket depth outside strings, by one linear scan, so a deep line is refused without recursing into it."""
    depth, in_str, esc = 0, False, False
    for b in raw:
        if in_str:
            if esc:
                esc = False
            elif b == 0x5C:           # backslash
                esc = True
            elif b == 0x22:           # quote
                in_str = False
        elif b == 0x22:
            in_str = True
        elif b in (0x5B, 0x7B):       # [ {
            depth += 1
            if depth > MAX_DEPTH:
                return False
        elif b in (0x5D, 0x7D):
            depth -= 1
    return True


def _strict(raw: bytes, n: int) -> dict:
    """One line, parsed the only way it may be (vigil MUST 1, v0.3): a JSON object with no duplicate key, no NaN or
    Infinity, whose bytes are EXACTLY its canonical form. Otherwise one file could be one chain to a first-key-wins parser
    and another to a last-key-wins one, while the hash links (over raw bytes) and the signature (over parsed canonical
    bytes) both still pass."""
    def pairs(ps):
        keys = [k for k, _ in ps]
        if len(keys) != len(set(keys)):
            raise BrokenChain(f"line {n}: duplicate key")
        return dict(ps)

    def constant(name):
        raise BrokenChain(f"line {n}: {name} is not JSON")

    def number(text):                     # iktomi (review of 16da27e317): 1e400 parses to inf, past parse_constant
        f = float(text)
        if not math.isfinite(f):
            raise BrokenChain(f"line {n}: {text} overflows to a non-finite number")
        return f
    if len(raw) > MAX_LINE_BYTES:
        raise BrokenChain(f"line {n}: {len(raw)} bytes, over the {MAX_LINE_BYTES}-byte line cap")
    if not _depth_ok(raw):
        raise BrokenChain(f"line {n}: nested deeper than {MAX_DEPTH}")
    try:
        d = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant, parse_float=number)
    except BrokenChain:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:    # RecursionError: the second wall behind _depth_ok
        raise BrokenChain(f"line {n}: not JSON ({type(exc).__name__})") from None
    if not isinstance(d, dict) or canonical_bytes(d) != raw:
        raise BrokenChain(f"line {n}: not canonical (sorted keys, no whitespace, UTF-8)")
    return d


def _shape(e: dict, n: int) -> None:
    """A malformed event is a refusal, not a crash (vigil SHOULD 2)."""
    if e.get("event") not in EVENTS:
        raise BrokenChain(f"event {n}: unknown event {e.get('event')!r}")
    for k in ("by", "bead", "at"):
        if not isinstance(e.get(k), str) or not e[k]:
            raise BrokenChain(f"event {n}: {k!r} must be a non-empty string")
    if not isinstance(e.get("data"), dict):
        raise BrokenChain(f"event {n}: 'data' must be an object")
    if e["event"] == "edge" and not (isinstance(e["data"].get("to"), str) and isinstance(e["data"].get("type"), str)):
        raise BrokenChain(f"event {n}: an edge needs data.to and data.type")


def replay(path: Path, allowed_signers: str, expect_head: str | None = None,
           expect_anchor: str | None = None) -> tuple[dict, dict]:
    """(anchor, {bead_id: Bead}), VERIFIED: every event must carry a valid signature by its own `by`, checked against
    `allowed_signers` (an ssh allowed-signers file). Since v0.3 this is the only way to get a trusted result (vigil MUST 3);
    the unsigned view is replay_unverified(), whose anchor is marked.
    expect_head (sha256 of the last line) catches a cut tail; expect_anchor (sha256 of line 1) pins the anchor, which holds
    the validator set that every honey bean rests on (vigil SHOULD 1). Publish both with a release."""
    if not allowed_signers or not Path(allowed_signers).is_file():
        raise ValueError("replay needs an allowed-signers file; for a view that proves nothing, call replay_unverified()")
    return _replay(path, allowed_signers, expect_head, expect_anchor)


def replay_unverified(path: Path, expect_head: str | None = None, expect_anchor: str | None = None) -> tuple[dict, dict]:
    """The same state WITHOUT checking signatures, so built from self-declared `by` fields: it proves nothing, counts no
    verification, and its anchor carries "_unverified": True so a caller cannot mistake it for replay()."""
    anchor, beads = _replay(path, None, expect_head, expect_anchor)
    return dict(anchor, _unverified=True), beads


def _replay(path, allowed_signers, expect_head, expect_anchor):
    """A `done` counts only by the bead's claimer, or by its poster while it is unclaimed, as hop does (yollotl SHOULD 2)."""
    size = Path(path).stat().st_size
    if size > MAX_CHAIN_BYTES:
        raise BrokenChain(f"chain is {size} bytes, over the {MAX_CHAIN_BYTES}-byte cap; refused before reading")
    # iktomi / amatl: a file can grow between stat() and read, so the read itself is bounded too.
    with open(path, "rb") as f:
        data = f.read(MAX_CHAIN_BYTES + 1)
    if len(data) > MAX_CHAIN_BYTES:
        raise BrokenChain(f"chain grew past the {MAX_CHAIN_BYTES}-byte cap while being read")
    raw_lines = data.splitlines()
    if not raw_lines:
        raise BrokenChain("empty chain: line 1 must be the anchor")
    parsed = [_strict(raw, i + 1) for i, raw in enumerate(raw_lines)]
    first = parsed[0]
    if first.get("prev") is not None or not isinstance(first.get("anchor"), dict):
        raise BrokenChain("line 1 must be the anchor, with prev = null")
    if expect_anchor is not None and hashlib.sha256(raw_lines[0]).hexdigest() != expect_anchor:
        raise BrokenChain("line 1 is not the expected anchor")
    for i in range(1, len(raw_lines)):
        if parsed[i].get("prev") != hashlib.sha256(raw_lines[i - 1]).hexdigest():
            raise BrokenChain(f"event {i + 1} does not link to the event before it")
    if expect_head is not None and hashlib.sha256(raw_lines[-1]).hexdigest() != expect_head:
        raise BrokenChain("the chain does not end at the expected head: truncated or extended")
    anchor = first["anchor"]
    # amatl (#8770269): policy null or [] raised AttributeError, validators [{}] TypeError. A malformed anchor is a
    # refusal like any other malformed line; missing policy or validators keep their defaults ({} and []).
    policy = anchor.get("policy", {})
    if not isinstance(policy, dict):
        raise BrokenChain("line 1: anchor.policy must be an object")
    vals = policy.get("validators", [])
    if not isinstance(vals, list) or not all(isinstance(v, str) and v for v in vals):
        raise BrokenChain("line 1: anchor.policy.validators must be a list of non-empty names")
    validators = set(vals)
    beads: dict[str, Bead] = {}
    poster: dict[str, str] = {}
    for n, e in enumerate(parsed[1:], start=2):
        _shape(e, n)
        if allowed_signers and not _verify(e, allowed_signers):
            raise BrokenChain(f"event {n}: missing or invalid signature for {e['by']!r}")
        bid, d = e["bead"], e["data"]
        if e["event"] == "posted":
            if bid not in beads:          # a second `posted` cannot overwrite a bead
                try:
                    beads[bid] = Bead.from_json(dict(d, id=bid, created_at=e["at"]))
                except (TypeError, ValueError, KeyError) as exc:
                    raise BrokenChain(f"event {n}: not a valid bead ({exc})") from None
                poster[bid] = e["by"]
            continue
        b = beads.get(bid)
        if b is None:
            continue                      # an event for a bead never posted: ignored, not invented
        if e["event"] == "claimed":
            b.status, b.assignee = "in_progress", e["by"]
        elif e["event"] == "done":
            if e["by"] != (b.assignee or poster[bid]):
                continue                  # not the claimer (or the poster of an unclaimed bead): ignored
            b.status, b.closed_at, b.evidence = "closed", e["at"], d.get("evidence", b.evidence)
        elif e["event"] == "verified":
            # counts only if the chain is signed AND the verifier is in the anchor's validator set (neci MUST 3)
            if allowed_signers and e["by"] in validators:
                b.verifications.append({"by": e["by"], "at": e["at"], "kind": d.get("kind", "verified")})
        elif e["event"] == "edge":
            b.dependencies.append({"issue_id": bid, "depends_on_id": d["to"], "type": d["type"], "created_at": e["at"],
                                   "created_by": e["by"], "metadata": {}, "thread_id": None})
        elif e["event"] == "note":
            b.comments.append({"id": f"{bid}-c{len(b.comments) + 1}", "issue_id": bid, "author": e["by"],
                               "text": d.get("text", ""), "created_at": e["at"]})
        b.updated_at = e["at"]
    return anchor, beads
