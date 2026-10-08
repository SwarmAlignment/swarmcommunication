"""A bead: one unit of work, as a plain record (swarmcommunication v0, yollotl's design).

A bead IS a beads_rust issue record, plus one `x_swarm` object for what HOP needs and beads lacks: who contributed and
in what share, what inventory was used, the evidence, and a signature. No database, no sync: a record.
"""
from __future__ import annotations

import json
import math
from dataclasses import asdict, dataclass, field

BEADS_FIELDS = ("id", "title", "description", "status", "priority", "issue_type", "assignee", "labels",
                "dependencies", "comments", "created_at", "updated_at", "closed_at", "close_reason")


# neci MUST 1: a bead signature has its own SSHSIG namespace, so it can never be replayed as a colony send or a git tag.
SIG_NAMESPACE = "swarm-bead@swarmengineering.org"


def canonical_bytes(obj) -> bytes:
    """The exact bytes that get signed: JSON, keys sorted, no whitespace, UTF-8. Two implementations that follow this
    sign the same bytes."""
    # vigil MUST 2 (v0.3): NaN and Infinity are not JSON; refusing them here keeps every signed byte parseable everywhere.
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


@dataclass
class Bead:
    id: str
    title: str
    status: str = "open"
    description: str = ""
    priority: int = 2
    issue_type: str = "task"
    assignee: str = ""
    labels: list = field(default_factory=list)
    # beads_rust shape (yollotl MUST A): {"issue_id", "depends_on_id", "type", "created_at", "created_by", "metadata",
    # "thread_id"}; our two edge types are "grows" and "derived_from".
    dependencies: list = field(default_factory=list)
    comments: list = field(default_factory=list)       # beads_rust shape: {"id", "issue_id", "author", "text", "created_at"}
    created_at: str = ""
    updated_at: str = ""
    closed_at: str = ""
    close_reason: str = ""
    contrib: list = field(default_factory=list)        # [{"who": "<mind>", "share": 0.7}, ...], shares sum to 1
    inventory: list = field(default_factory=list)      # tools, models or skills used
    evidence: str = ""
    verifications: list = field(default_factory=list)  # [{"by", "at", "kind"}]: in x_swarm, so comments stay beads
    sig: dict = field(default_factory=dict)            # {"signer": "<mind>", "namespace": SIG_NAMESPACE, "sshsig": "..."}

    def __post_init__(self):
        if self.contrib:
            for c in self.contrib:                           # vigil MUST 2: `nan` passed the sum check below
                sh = c.get("share")
                if isinstance(sh, bool) or not isinstance(sh, (int, float)) or not math.isfinite(sh) or not 0 < sh <= 1:
                    raise ValueError(f"bead {self.id}: a contrib share must be a finite number in (0, 1], got {sh!r}")
            total = sum(float(c["share"]) for c in self.contrib)
            if abs(total - 1.0) > 1e-9:
                raise ValueError(f"bead {self.id}: contrib shares sum to {total}, not 1")

    @property
    def authors(self) -> set:
        return {c["who"] for c in self.contrib} or ({self.assignee} if self.assignee else set())

    def edges(self, kind: str) -> list:
        return [d["depends_on_id"] for d in self.dependencies if d.get("type") == kind]

    def to_json(self) -> dict:
        d = asdict(self)
        x = {k: d.pop(k) for k in ("contrib", "inventory", "evidence", "verifications", "sig")}
        d["x_swarm"] = x
        return d

    @classmethod
    def from_json(cls, d: dict) -> "Bead":
        x = d.get("x_swarm") or {}
        known = {k: d[k] for k in BEADS_FIELDS if k in d}
        return cls(**known, contrib=x.get("contrib", []), inventory=x.get("inventory", []),
                   evidence=x.get("evidence", ""), verifications=x.get("verifications", []), sig=x.get("sig") or {})

    @classmethod
    def from_bytes(cls, raw: bytes) -> "Bead":
        """Parse a signed record, refusing bytes that are not canonical (neci MUST 1, ixiptla's gate rule): a duplicate
        key or a reordering must not mean one thing in a log and another to a verifier."""
        pairs_seen = []

        def hook(pairs):
            keys = [k for k, _ in pairs]
            if len(keys) != len(set(keys)):
                raise ValueError("duplicate key in a bead record")
            pairs_seen.append(1)
            return dict(pairs)
        d = json.loads(raw.decode("utf-8"), object_pairs_hook=hook)
        if canonical_bytes(d) != raw:
            raise ValueError("bead bytes are not canonical (sorted keys, no whitespace, UTF-8)")
        return cls.from_json(d)

    def signing_bytes(self) -> bytes:
        body = self.to_json()
        body["x_swarm"] = {k: v for k, v in body["x_swarm"].items() if k != "sig"}
        return canonical_bytes(body)
