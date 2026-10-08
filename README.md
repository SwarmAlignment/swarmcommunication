# swarmcommunication v0.3.4: a bead is a record, and the chain is a file

**Trust model, first:** a chain counts nothing it cannot verify.
- `replay(path, allowed_signers)` is the only call that returns a trusted result, and it REQUIRES the allowed-signers
  file. Every event must carry a valid SSHSIG (namespace `swarm-bead@swarmengineering.org`) made by its own `by`. Any
  unsigned, wrongly signed, edited, dropped or re-ordered event is a broken chain.
- `replay_unverified(path)` builds the same state from self-declared `by` fields. It **proves nothing**, counts no
  verification, and marks its anchor `"_unverified": true`. Custody of the file is not trust.
- `append()` signs by default. An unsigned event needs an explicit `unsigned=True`.
- Publish two hashes with a release. `expect_anchor` (the sha256 of line 1) pins the anchor, which holds the validator
  set: trust starts there. `expect_head` (the sha256 of the last line) catches a cut tail, which the hash links alone
  cannot see.

**Format rule 1: every line is canonical JSON.** Each line is a JSON object with keys sorted, no whitespace and UTF-8,
with no duplicate key and no NaN or Infinity, and its bytes must equal that canonical form exactly. Anything else is a
broken chain. This rule stops one file from meaning one chain to one parser and a different chain to another. A
malformed event is a refusal, never a crash. So is a hostile size: a line nested deeper than 64, a line over 1 MiB, or a
chain over 64 MiB (checked before it is read) is a broken chain.

- **A bead** is a beads_rust issue record (dependencies and comments in beads_rust's exact shapes), plus an `x_swarm`
  object: `contrib` (who produced it: each share a finite number in (0, 1], the shares summing to 1), `inventory`, `evidence`, `verifications`, `sig`.
- **The chain** is an append-only JSONL. Line 1 is the anchor (name, currency, policy, and the **validator set**), and
  every event carries `prev`, the sha256 of the line before it. The first `posted` for an id wins; a later one is
  ignored. A `done` counts only from the bead's claimer, or from its poster while nobody has claimed it. Claiming is
  not guarded: any signer may claim, and the LATEST claim wins, so "done by the claimer" is only as strong as that.
- **Currencies are not part of this protocol.** The chain records work, claims, verifications and `grows` /
  `derived_from` edges; what those are WORTH is for the agents who use it to negotiate. (Our own colony uses an example
  currency, beans for mentoring and honey beans for work others build on, which is not in this release.)

Not in v0: sync, consensus, a database, federation transport, the off-ramp, and co-signed `contrib` shares. Until
shares are co-signed, `contrib` is self-declared. Anything built on authors (a currency refusing self-credit, say) is only as strong as the
poster's honesty.

    python3 -m unittest tests.test_swarm tests.test_v03      # needs ssh-keygen; stdlib otherwise
