# Contributing

Bug reports, failing test cases, and patches are all welcome. Security reports go through the
private channel in `SECURITY.md` instead — not a pull request, and not a public issue.

## Contribution model: DCO

Contributions are taken under the [Developer Certificate of Origin](https://developercertificate.org/)
version 1.1. Every commit needs one sign-off line:

```sh
git commit -s          # appends Signed-off-by: Your Name <your@email>
```

The line has to match the commit's author. It certifies that you wrote the change, or have the
right to submit it under the project's licence — nothing more; you keep your copyright, and no
rights are assigned to us. CI checks every commit in a pull request and fails the `DCO` job on a
missing or mismatched line; `git rebase --signoff <base>` fixes a branch that already exists.

There is no CLA. The dual `Apache-2.0 OR MIT` licence is what makes one unnecessary: a
contribution arrives under both, so the code can be relicensed to either when it moves — which
matters here, because the policy primitives this project expects to upstream go to OpenZeppelin's
MIT-licensed accounts package.

## Before your first push

```sh
git config core.hooksPath .githooks
```

Git does not carry hooks when you clone, so this points it at the tracked hook directory. The
hook refuses a push that would take confidential material out of a working tree; see §0 of
`docs/DEVELOPERS.md` for what it checks and why it has to run on your machine rather than in CI.

## What the gates expect

```sh
bash scripts/verify-phase1.sh --offline    # everything that needs no network or Stellar CLI
bash scripts/verify-phase1.sh              # the full release gate; needs stellar-cli and network
```

The offline mode names every release-only check it skipped, so a green run never overstates
itself. Both workspaces are in scope — the toolkit at the root and `contracts/` — and
`cargo fmt --check` and `cargo clippy -- -D warnings` must be clean in each. `cargo fmt --check`
additionally covers the generated policy crates, which belong to neither workspace and so are
reached by their own invocation; clippy does not yet, which is a gap rather than a decision. CI
runs the same checks as separate jobs, so whatever fails locally fails there under a name that
says which gate it was.

Three things reject a patch mechanically, and all three are load-bearing rather than style:

- **Generated crates are not edited by hand.** `contracts/golden-transfer-policy/` is codegen
  output, committed so a reader can see what the generator produces and so CI can prove the
  generator still produces exactly it. Change the templates in `crates/codegen/` and let the
  golden crate follow; a hand edit shows up as codegen drift and fails.
- **The evaluator must not depend on codegen.** The reference evaluator is evidence only while
  it shares no code with what it checks, so `scripts/check-dep-rules.sh` fails on that edge in
  the cargo graph. If you need something from both sides, it belongs in `crates/domain`.
- **Hashes quoted in prose must resolve.** `scripts/check-quoted-hashes.py` fails on a hash no
  artifact here produces any more, and equally on an exemption no document quotes. A value this
  tree genuinely cannot derive goes in `scripts/quoted-hash-exemptions.txt` with its class and
  the reason it cannot.

## Commit messages

Say what the defect was and why the change is the fix, not what the diff shows — the diff is
right there. Where a change narrows a claim the code could not keep, say which claim. Where you
verified something by running it, say what you ran. The history is part of what a reviewer of
this repository reads, so it is written for them.

## Documentation

Documents describe the tree they are committed in. Do not describe this repository's open
pull requests or branches in them ("prepared in PR #N", "pending #N", a table of open PRs):
that status changes with every merge, and the sentence is wrong as soon as #N lands. Pending
work and its review state belong in the pull request or the tracking issue. A document
describes a change in the commit that makes it, never while the change still sits in another
pull request. Citing a merged change as the source of a recorded result, or another project's
pull request that explains a dependency or a limit, is fine.

## Adding a policy primitive or a constraint kind

`docs/DEVELOPERS.md` walks the whole path: the vocabulary in `domain`, validation in
`policy-spec`, the synthesizer's exact-by-default rule, the codegen template, and the reference
evaluator's arm — plus which tests each step is expected to grow. Widening is the part to read
twice: a bound or a wildcard may only ever enter through an explicit, provenance-tagged user
decision, never a heuristic.
