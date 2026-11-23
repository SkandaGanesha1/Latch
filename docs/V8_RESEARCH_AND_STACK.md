# LATCH v8 research and stack

| Component | Role | Evidence or reference |
|---|---|---|
| QNX SDP 8.0, C11 cross compiler, mkifs and secpol tools | Build supervisor, image and security policy | [QNX SDP documentation](https://www.qnx.com/developers/docs/8.0/com.qnx.doc.qnxsdp.nav/topic/bookset.html) |
| QNX resource manager and devctl | Proposal and operator interfaces | [QNX resource manager security](https://www.qnx.com/developers/docs/8.0/com.qnx.doc.security.system/topic/manual/write_resource_manager.html) |
| QNX Hypervisor and Linux ARM64 guest | Guest isolation and virtio transport | [QNX Linux guest guide](https://qnx.com/developers/docs/8.0/com.qnx.doc.hypervisor.user/topic/build/build_linux.html) |
| Host C compiler, Python 3 standard library and make | Host simulation and verification | `qnx/Makefile` and `tools/` |
| QEMU AArch64 | Experimental virtual-target demonstration | [QNX platform support](https://www.qnx.com/developers/docs/8.0/com.qnx.doc.hypervisor.user/topic/virt/support.html) |
| Devpost | Submission requirements and judging criteria | [Official rules](https://qnx.devpost.com/rules) and [resources](https://qnx.devpost.com/resources) |

QNX OS support on a QEMU target does not establish that nesting the QNX Hypervisor under QEMU is a supported Hypervisor host configuration. No physical target, certification, or clinical use is established by host simulation. The current system does not require a guest LLM or a third-party Python runtime package for its scripted demo. Confirm actual tool versions and licenses on the machine used for each evidence capture.
