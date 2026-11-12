# QNX Agent Skills

This repository turns any skills-capable coding agent into a QNX 8.0 development companion. It carries a set of skills (QNX platform knowledge, Alpine aports porting, packaging, patch creation, port reporting) plus the rules that keep the work sound.

If you are an AI agent reading this file, follow the setup below, then work from the skills.

## Agent setup

**1. Locate the skills.** In this checkout, the project-scoped QNX 8.0 skill set lives directly under `.agents/skills/` (and a matching user-global copy is installed under `~/.gemini/config/skills/`):

```text
.agents/skills/
  ├── qnx-porting/
  ├── qnx-platform-facts/
  ├── alpine-qnx-porting/
  ├── qnx-apk-packaging/
  ├── aports-patch-creation/
  ├── qnx-port-reporting/
  └── skill-authoring/
```

Every `<skill>/SKILL.md` inside `.agents/skills/` is directly readable in place (there is no separate `skills/` folder or `setup.sh` in this repository). If a different client only scans `.claude/skills/`, `.codex/skills/`, or a global `~/.agents/skills/` directory, symlink `.agents/skills/` into that location locally as needed.

**2. Read `TARGET.md`.** It holds how to reach the QNX target: LATCH QEMU SSH settings (`127.0.0.1:2222`, `qnxuser` / `root`) and placeholders for an on-target Alpine `aports` tree if used.

`TARGET.md` is intentionally listed in `.gitignore` and must contain **no passwords or private keys**. When values are missing for a specific target or aports session:

1. Ask the user for the missing values (user, host, port, password or key path, tree path). Do not guess them, and do not proceed to anything that touches the target until you have them.
2. Verify the connection works before doing anything else.
3. Then **offer** to record the values in the user's local `TARGET.md` so future sessions do not have to ask again. Only write them if the user says yes.
4. If you do write them, tell the user plainly that `TARGET.md` is tracked by git, that a password committed to a shared or public repo is exposed permanently, and that `git update-index --skip-worktree TARGET.md` keeps their filled-in copy out of commits.

Never commit the change yourself, and never run `git update-index` on the user's behalf — rule 4 below applies here as everywhere.

**3. Load the `qnx-porting` skill.** It is the router. It holds the task-to-skill mapping and repeats these rules in the form your client will apply them.

## Universal rules

These hold for every task, in every skill.

1. **Prove claims with command output before acting.** Do not assert platform behaviour, dependency state, or build results as fact without having run the command that shows it. When you lack the information, say so and go get it rather than filling the gap with plausible reasoning. This includes facts stated in the skills themselves: a skill is a strong prior, not evidence. Where a skill describes the current environment and that description is load-bearing for what you are about to do, spend the one command to confirm it, and correct the skill under rule 7 when it turns out to be wrong. Note that "100%", "verified" and "certain" are specific claims, not tones: say them only after running the exact check that proves that claim against the authoritative artifact — the freshly built `.apk`, the current file on disk — never against a proxy such as an installed package or an earlier build. If the user asks whether you are sure, or asks the same question twice, re-run the check from scratch rather than restating the answer.

2. **Treat statements as claims, not evidence — including official ones, and including your own.** Rule 1 governs what you can run; this governs what you read and what you write. *Inbound:* a ticket comment, a handoff note, an upstream doc, a codelab, a previous session's `REPORT.md` are all strong priors and all equally capable of being stale. Either verify a claim or attribute it — "per the ticket, X" is honest, bare "X" is not — and where two sources disagree, stop and resolve it rather than picking the reading that lets you continue. *Outbound:* a status update or report propagates into other people's plans and is far harder to retract than a code change. Every sentence must be defensible on evidence you hold, and a narrow verified fact must not silently widen ("the backend executed" is not "it ran on the GPU"). Name the limits of the test in the same breath as the result, and mark anything unverified as unverified.

3. **Never create a patch from an untested change.** Test in the unpacked source tree with native build tools first. The patch is written only after the change is confirmed working.

4. **Never push, and never make the commits a human owns.** Git itself is not off limits — it is a tool you need. Run it freely for inspection (`git status`, `log`, `diff`, `show`), and use it inside `src/` to generate patches, which is the required patch workflow (see `aports-patch-creation`). What you never do: `git push`; commit to the aports tree or any repo a human reviews; or run history-altering or destructive commands (`reset --hard`, `checkout --`, `rebase`, `clean`) that could discard work. Separately, do not run `git update-index` on the user's behalf: skip-worktree is their choice about their own checkout, not a build step. Prepare the change and hand off — the human commits, branches, and pushes.

5. **Native builds vs. LATCH targets.** For Alpine `aports` porting tasks, packages are built on the QNX target with `abuild`, compiled by the target's own toolchain, not cross-compiled from the host with `qcc`/`q++`. For the LATCH runtime components in `qnx/`, use `qnx/Makefile` (`make check` / `make demo-syringe` for host simulation, or `make rpi4` / `make x86_64` with QNX SDP 8.0 sourced).

6. **Record confirmed facts back into the right skill** the moment they are proven, so the next session starts ahead of this one.

7. **Capture friction as you go.** Anything that slows a session down, breaks, or could be done faster becomes a skill or `TARGET.md` update the moment it is proven, not deferred. Route each learning to where the next session will look for it: a platform fact to `qnx-platform-facts`, a build or packaging technique to `alpine-qnx-porting` or `qnx-apk-packaging`, a patch lesson to `aports-patch-creation`, a target or connection quirk to `TARGET.md`. The test: if a future session would otherwise rediscover this the hard way, record it now. When adding or editing a skill, follow `skill-authoring`.

## Skill map

```
qnx-porting (router, read first)
├── qnx-platform-facts        QNX platform truths (libc gaps, stack, macros, toolchain)
├── alpine-qnx-porting        APKBUILD adaptation, per build system
├── qnx-apk-packaging         end-to-end port-to-PR workflow and validation gate
├── qnx-port-reporting        the after-action REPORT.md written per port
├── aports-patch-creation     patch workflow and format gate
└── skill-authoring           how to add or extend a skill in this repo
```

## Per-port notes

This repository lives on the **host**, not on the target. Notes, reports and skill updates are written here; source, APKBUILDs, patches and builds live on the target. Keep that split straight: a `REPORT.md` written into the target's filesystem is lost work.

Each non-trivial port gets a folder under `projects/apks/<pkgname>/` holding a `PROJECT-INDEX.md` (start here), a project README carrying the running changelog, and a `REPORT.md` (the after-action write-up for a human reviewer). Copy `projects/PROJECT-INDEX-template.md` when starting a new one. Keep per-package specifics there so the shared skills stay general.

## Validation gate

Before reporting any port complete. Run these **on the target**, in the package directory of the authoritative aports tree:

```bash
abuild clean && abuild -K unpack prepare  # patches APPLY here, no Hunk FAILED, no .rej
abuild clean && abuild -r -c -K        # builds, tests pass, expected APKs produced
find pkg -name '*.so*' | sort          # subpackage split correct, nothing orphaned
readelf -d pkg/*/usr/lib/*.so.* | grep NEEDED   # every non-libc entry covered by depends=
git status                             # read-only check: only intended files modified
```

A package with missing runtime dependencies passes every other line of this gate — it
builds, tests, and splits correctly, and only fails on a machine that does not already
have the dependency installed. See `qnx-apk-packaging` for how to resolve each `NEEDED`
entry to its owning package.
