# LATCH v8 current workflow

The Linux guest's scripted PID 1 sends fixed-size frames over virtio-console. The unprivileged `latch-ingest` process validates framing and converts the proposals to versioned IPC messages. The QNX `latchd` resource manager runs the supervisor, checks the manifest-defined unit, timing and envelope policies, updates the authority ladder and drives either the mock or configured actuator. `latchctl` exposes status and event exports; host tools run the attack scenarios and replay exported events.

The default schema-2 contract retains the original LATCH protocol. Schema-3 contracts opt into GOVERNOR's v2 framing, lease, coherence, ladder and prechecks. The QEMU profile is an experimental QNX Hypervisor-on-QEMU configuration using mock I²C; it does not demonstrate physical actuation or a real-time bound.

The event ring is volatile. Hash chaining occurs after export and demonstrates integrity relative to a trusted retained checkpoint, not authenticity of data prior to export. Manifest SHA-256 sidecars detect mismatch, not the identity of the author.
