# Submission handoff

The local submission draft is `docs/DEVPOST_SUBMISSION.md` and the canonical
storyboard is `docs/DEMO_VIDEO_SCRIPT.md`. Review current official
[Devpost rules](https://qnx.devpost.com/rules) before submission: the rules
ask for a publicly visible YouTube video and a codelab URL in the designated
form field for the tutorial bonus. The rules do not require making a second
project entry merely to provide that URL.

Before recording, re-run `make -C qnx evidence-governor-latency GUEST_IMAGE=/abs/path/to/Image`
on an uncontended host so `docs/evidence/governor/LATENCY.md` clears the
`verify_latency_bucket_invariant()` gate (`900 Hz ±5%` achieved rate), then
rerun `python3 tools/run_ci_locally.py`. Capture real output and label host
simulation, the offline console simulator, QEMU TCG, mock I²C, and the medical
simulation explicitly.
Do not claim physical actuation, authenticated manifest signatures, a WCET,
certification, or durable event storage. The event hash chain is made after
export, and producer epochs are not authentication credentials.

Human actions still needed: execute and sign `docs/MANUAL_ACCEPTANCE.md`,
record and publish the video, enter and review the Devpost form, and check
repository visibility and license metadata. A physical Pi, actuator and
real-board measurements require separate equipment and a separately recorded
test. No submission, publishing or physical test has been performed by this
handoff.
