# ==============================================================================
# qnx/latch_fbprobe.secpol.inc
#
# The EXPERIMENTAL feedback-transport additions for the DISPOSABLE fbprobe
# image (W4).  This file is APPENDED to qnx/latch.secpol by
# tools/generate_fbprobe_secpol.py, and only the fbprobe image is built with
# the result.
#
# WHY IT IS A SEPARATE FILE
# -------------------------
# The deployment policy (qnx/latch.secpol) is NOT modified.  Two reasons:
#
#   1. The written security-policy audit review (docs/secpol-audit-review.md)
#      states that the audit accepted NO generated rule and that
#      `qnx/latch.secpol` is untouched.  Widening the deployment policy to
#      accommodate a transport experiment would falsify that statement and
#      would be a policy change disguised as tooling.
#   2. The fbprobe image is DISPOSABLE.  Its whole purpose is to answer one
#      question -- can a host-side verdict reach a freestanding guest policy
#      without giving the guest write access to the channel -- and its extra
#      privileges must not be the ones the deployed system runs with.
#
# Everything in the deployment policy is still in force here: the actuator
# ability, the proposal node's ownership, the guest-lifecycle channel, and
# the operator shell's deliberate lack of `latch/actuator`.  The additions
# below are strictly about the feedback mailbox that feeds the verdict file.
# ==============================================================================

# The host-side publisher of the feedback frames.  It is a DEVELOPMENT-ONLY
# binary in a DISPOSABLE image: it opens the WRITE side of the feedback
# mailbox and writes frames into it.  It holds no `latch/actuator` ability,
# no `latch/propose` ability, and no right to connect to the supervisor's
# own channels -- so it cannot propose motion and cannot actuate.
# Everything it can do is write bytes into the feedback mailbox, from which
# the sink copies the latest frame into the verdict file the guest polls.
type latch_fbpump_t;

allow latch_fbpump_t self:ability {
    nonroot
};

# The feedback resource manager (`latch_fb_sink`).  It owns the three
# one-sided nodes:
#
#     /dev/latch/feedback       READ side.  Read by the recorded readcond
#                               self-test; the chosen transport does not
#                               use it.
#     /dev/latch/feedback_pub   WRITE side.  The publisher opens this,
#                               write-only.  THIS is the channel: it is the
#                               only way a frame reaches the verdict file.
#     /dev/latch/feedback_out   DISCARD side.  Unused by the chosen
#                               transport; kept so the sink's three-node
#                               shape does not change under the gates.
#
# It is also the ONLY writer of /dev/shmem/latch_feedback.img, and it
# creates that file at its final size BEFORE it registers the nodes above.
#
# The pseudo-terminal was tried first and rejected by measurement: the
# pty's open ORDER decided whether the pair could be used at all (the
# reader must open the CONTROLLER first, and a hostdev that cannot be
# opened is FATAL to the VM start), and a pty lets ANY process write into
# the channel -- the wrong property for a channel whose entire value is
# "this verdict came from the trusted supervisor".
#
# The mailbox needs the `pathspace` ability to register its own nodes, the
# same ability the pipe resource manager and `latchlog` use.
type latch_fb_sink_t;

allow latch_fb_sink_t self:ability {
    nonroot
    pathspace
    public_channel
};

# The path ownership.  The three nodes are ENUMERATED rather than wildcarded:
# the QNX security-policy language documents `*` as "a wildcard that can
# represent any name", and the unambiguous form for a fixed set of device
# names is to name them.
allow_attach latch_fb_sink_t /dev/latch/feedback;
allow_attach latch_fb_sink_t /dev/latch/feedback_pub;
allow_attach latch_fb_sink_t /dev/latch/feedback_out;

# RETAINED FOR THE REJECTED PL011 EXPERIMENT -- NOT USED BY THE CHOSEN
# TRANSPORT.  The hypervisor's feedback PL011 vdev used to open the read
# node; the PL011 host->guest injection and the virtio-console input
# direction are both dead by measurement, and the verdict file is opened
# as an ordinary read-only FILE (there is no channel-connect rule for a
# regular file).  The rule stays so the negative result remains
# reproducible, and it grants nothing the guest can reach: the resource
# manager refuses a write access on the read node in code as well.
allow qvm_host_t latch_fb_sink_t:channel connect;

# The publisher writes the feedback channel.  This is the ONLY channel the
# publisher may connect to, and it carries no actuator ability.  It may not
# open the read node: the resource manager refuses a read access on the
# publisher's node, and no policy rule lets the publisher reach the read
# node either.
allow latch_fbpump_t latch_fb_sink_t:channel connect;

# THE SUPERVISOR PUBLISHES ITS OWN VERDICTS  (W5)
# -----------------------------------------------------
# In the W5 profile the publisher is `latchd` ITSELF, and that is the whole
# point of the profile: the verdict that reaches the guest is the verdict
# of the TRUSTED SUPERVISOR, not a synthetic frame from a development-only
# tool.
#
# So `latchd_t` is allowed to connect to the feedback sink's ONE-SIDED WRITE
# node -- and to nothing else there.  The rule is deliberately narrow:
#
#   * it is a CHANNEL CONNECT, not a path rule, so `latchd` gains no
#     ability over the verdict FILE itself (which the sink owns, and which
#     the guest can only ever read through a read-only block device);
#   * `latchd` keeps every ability it had: the actuator ability, the
#     proposal node's ownership, the guest-lifecycle channel.  Nothing is
#     relaxed for the experiment;
#   * the deployment policy qnx/latch.secpol is NOT modified.  This rule
#     lives in the EXPERIMENT'S policy, and only the DISPOSABLE fbprobe and
#     fbverdict images are built with it.
#
# The rule is added HERE, in the shared experiment include, because the
# fbprobe image (W4) needs the sink too and the fbverdict image (W5) is
# the one that actually connects to it.  An allow rule for a type that
# never connects is inert.
allow latchd_t latch_fb_sink_t:channel connect;
