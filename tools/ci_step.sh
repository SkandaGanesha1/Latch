#!/usr/bin/env bash
# tools/ci_step.sh -- run one CI step, and KEEP ITS TRANSCRIPT WHEN IT FAILS.
#
# WHY THIS EXISTS
# ---------------
# On 2026-11-27 the CI job failed after 1.2 s at the "200-Tick End-to-End
# Pipeline" step, with the whole job reporting only "Process completed with
# exit code 2".  The job log could NOT be retrieved: GitHub's API demands
# admin rights for a job's logs, so from outside the repository the failure
# was undiagnosable -- the step names were readable, the REASON was not.
#
# That is the same defect this repository already fixed for its evidence
# captures ("A FAILING CAPTURE MUST KEEP ITS OWN TRANSCRIPT", AGENTS.md
# §4d): a failure whose evidence is thrown away costs the next diagnosis a
# whole cycle.  The rule generalises:
#
#     A FAILING CI STEP MUST KEEP ITS OWN TRANSCRIPT.
#
# WHAT THIS HELPER DOES
# ---------------------
#   * runs the step's script with `bash -e -x`, so the transcript shows
#     EVERY command -- the failing one is the last line before the error;
#   * tees the transcript into $RUNNER_TEMP/latch-ci-logs/, which the
#     workflow uploads as an artifact.  The artifacts API is readable
#     WITHOUT authentication on a public repository, so the transcript is
#     public;
#   * on failure, copies the transcript into $GITHUB_STEP_SUMMARY, which is
#     rendered on the job's public page, and raises the last lines as
#     workflow ERROR ANNOTATIONS, which are public as well.
#
# So a red CI job carries its own diagnosis whether or not you can read the
# raw job log.
#
# USAGE
# -----
#   bash tools/ci_step.sh <step-name> <<'EOF'
#   cd qnx
#   make check
#   EOF
#
# The exit status is the step's own: 0 on success, the script's status on
# failure.  The transcript is kept in BOTH cases -- the artifact is the
# record of what the job actually did.
set -uo pipefail

NAME="${1:-step}"
if [ "$#" -gt 0 ]; then
    shift
fi

LOG_DIR="${RUNNER_TEMP:-/tmp}/latch-ci-logs"
mkdir -p "$LOG_DIR" || exit 1
SAFE_NAME="$(printf '%s' "$NAME" | tr -c 'A-Za-z0-9_.-' '_')"
LOG="$LOG_DIR/${SAFE_NAME}.log"

SCRIPT="$(mktemp)" || exit 1
trap 'rm -f "$SCRIPT"' EXIT
cat > "$SCRIPT"

set +e
# --noprofile --norc, because GitHub's own default shell does not read the
# profile either: the runner's /etc/profile.d scripts would otherwise be
# traced as the FIRST lines of every transcript and push the interesting
# ones out of the annotation tail.
bash --noprofile --norc -e -x "$SCRIPT" 2>&1 | tee "$LOG"
RC="${PIPESTATUS[0]}"
set -e

if [ "$RC" -ne 0 ]; then
    {
        echo "### CI step FAILED: \`$NAME\` (exit $RC)"
        echo
        echo "The full transcript is in the \`latch-ci-logs\` artifact; the tail is below."
        echo
        echo '```'
        tail -n 200 "$LOG"
        echo '```'
    } >> "${GITHUB_STEP_SUMMARY:-/dev/null}"

    echo "::error title=CI step failed: $NAME::exit $RC -- the transcript is in the job summary and the latch-ci-logs artifact"

    # The annotation channel is public on a public repository, so the LAST
    # lines of the transcript -- which is where the failing command is --
    # are readable without the job log.
    tail -n 40 "$LOG" | while IFS= read -r line; do
        if [ -n "$line" ]; then
            echo "::error::$NAME: $line"
        fi
    done
fi

exit "$RC"
