# LATCH — research log

What was read, what was verified against QNX SDP 8.0 / Hypervisor 8.0 manuals, and what was deliberately not put in the image.

The build that follows from this log is [LATCH-implementation.md](LATCH-implementation.md).

Date of the pass: 5 Nov 2026. Hackathon window used throughout: submissions close 15 Dec 2026, work must be new since 2 Nov 2026, one category, public repo, OSI license, video under three minutes. Category chosen: Robotics & Medical. Source for the rules: [qnx.devpost.com](https://qnx.devpost.com/) and the rules page linked from it. Re-read the rules before you submit; do not trust this paragraph if they edit them.

---

## 1. How the sources were used

Eight local files were the brief. They are not equally useful.

| File | What it actually is | What LATCH takes from it |
| --- | --- | --- |
| `LATCH-qnx-grand-prize.md` | The product. Simplex switch, Pi 4, hypervisor, resource manager, two HA candidates, tape, five-fault video, six-week order. | This is the spec. The implementation file tightens it where the manuals disagree with the first draft (GIC version, I2C not PWM, no `mlockall` credit, no guest-supplied state). |
| `latch_master_architecture_and_tech_stack_blueprint.md` | The same idea after every newsletter and YC company was bolted on. Includes a `latch_daemon.c` that trusts guest-reported `ey` / `etheta`, stamps deadlines in the guest, never checks the ability it creates, and never writes an actuator. | Kept: APS is gone, black-channel CRC, fail closed, 0 tokens on the tick, Pi 4 vs QEMU split. Rejected: the stack in its sections 2, 3, 5, 8, 9, and the sample daemon. |
| `yc_companies-2.csv` | 6,349 companies. Filtered locally on safety, robotics, control, actuators, evals, firmware simulation. | Zero runtime dependencies. The 21 closest rows are references. See section 4. |
| `ai-companies-technical-blogs-2.md` | Labs that train policies. | Market context for the untrusted guest. Do not link their SDKs. |
| `top-100-product-company-engineering-blogs-2.md` and `company_tech_urls-2.txt` | Web-company engineering blogs (Uber, Shopify, Stripe, Netflix, …). | Patterns that survive the filter are in section 5. The blogs themselves are not components. |
| `all_links (1)-2.txt` | RAG, agents, LoRA, vLLM, LangGraph, promptfoo, leaderboards. | Useful if you were building a chatbot. You are not. One idea kept: Simon Willison's lethal trifecta, and only as the reason the guest has no actuator credential. |
| `web3-companies-links-2.md` | Wallets, chains, DEXes. | Not used. An actuator credential implemented as a token is the wrong industry and makes QNX optional. |
| `companies-2.csv` | Mostly Bay Area employers and VCs. | NVIDIA, Arm, Broadcom, Synopsys, Cadence, Mentor show up as the surrounding industry. None is a library you vendor. |

Pages were fetched when a claim would change the C code or the qvm file. The thousands of marketing sites in the CSVs were not fetched one by one. Fetching them would not change the I2C write.

Two research passes ran in parallel: one against the QNX 8.0 library and hypervisor manuals, one against the CSV. The manual pass is section 2. The CSV pass is section 4.

---

## 2. QNX facts that changed the design

Verified on the 8.0 doc set. If a sentence is not in this section, it is not something you should put in the README as a manual citation.

### Abilities

- `procmgr_ability_create(const char *name, unsigned flags)` is real. Header `<sys/procmgr.h>`. [C Library](https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.lib_ref/topic/p/procmgr_ability_create.html), [Creating abilities](https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.prog/topic/process_Ability_creating.html).
- Flags are zero or more of `PROCMGR_ADN_ROOT` and `PROCMGR_ADN_NONROOT`. They are the domains that have the ability by default. There is no "deny everyone" flag. `flags == 0` is the reading that leaves both domains out. Caller must hold `PROCMGR_AID_ABLE_CREATE`. Name form is `service/capability`, max 127.
- `procmgr_ability_lookup()` can create the ability if it is missing. Call `create` yourself at startup before any client runs, or a lookup can freeze the default domains first. The library page and the programmer's guide disagree about a second `create` with different flags. Trust the library page, and do not call `create` twice.
- Custom-ability checks use `iofunc_client_info_able()` → `ConnectClientInfoAble()`. [iofunc_client_info_able](https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.lib_ref/topic/i/iofunc_client_info_able.html), [ConnectClientInfoAble](https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.lib_ref/topic/c/connectclientinfoable.html).
- `iofunc_ability_check()` is the wrong function. It only accepts `IOFUNC_ABILITYID_CHOWN`, `DUP`, `EXEC`, `READ`. [page](https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.lib_ref/topic/i/iofunc_ability_check.html).
- The library writes `struct _client_able.flags` (1 or 0). With a non-NULL info pointer, `_NTO_CI_UNABLE` means the client is missing at least one requested ability. Free with `iofunc_client_info_ext_free()`. Check in the handler that performs the privileged operation, not earlier. The manuals say the check emits a trace used for security-policy generation.

### Time and threads

- `timer_create(CLOCK_MONOTONIC, &sigevent, &timer_t)`. The clock is not settable. Official sample uses `SIGEV_PULSE_INIT` and `MsgReceive`, and treats `rcvid == 0` as a pulse. [timer_create](https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.lib_ref/topic/t/timer_create.html).
- Pulse priority is `sigev_priority`. Priority 0 is rewritten to 1. Codes in `_PULSE_CODE_MINAVAIL` … `_PULSE_CODE_MAXAVAIL`. [sigevent](https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.lib_ref/topic/s/sigevent.html).
- Without `_NTO_CHF_FIXED_PRIORITY`, a receive thread adopts the sender's priority. [channel flags](https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.getting_started/topic/s1_msg_chanflags.html).
- Runmask buffer for `_NTO_TCTL_RUNMASK_GET_AND_SET_INHERIT`: `int size`, then `runmask[size]`, then `inherit_mask[size]`, `size = RMSK_SIZE(num_cpu)`. A nonzero mask must match a predefined cluster or `ThreadCtl` returns `EINVAL`. Built-in single-CPU clusters are `_cpu-N`. [ThreadCtl](https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.lib_ref/topic/t/threadctl.html), [affinity](https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.prog/topic/multicore_processor_affinity.html).
- Priorities: 0 idle, 1–63 unprivileged by default, up to 253 with `PROCMGR_AID_PRIORITY`, 254 clock IST, 255 IPI. No manual sentence says "250 starves the kernel". 250 is still a bad default because it starves every other user thread on that core. The pin is what isolates the guest. [priority range](https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.prog/topic/overview_Priority_range.html).
- `PTHREAD_PRIO_INHERIT` is the default mutex protocol. [pthread_mutexattr_setprotocol](https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.lib_ref/topic/p/pthread_mutexattr_setprotocol.html).
- `mlockall` on SDP 8 does nothing and always succeeds. The page says all memory is already locked for the life of the process. Do not claim it as a jitter technique. [mlockall](https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.lib_ref/topic/m/mlockall.html).

### Hypervisor

- Enable with startup `-Q enable`. [Configuring the hypervisor host](https://www.qnx.com/developers/docs/8.0/com.qnx.doc.hypervisor.user/topic/config/hyp.html).
- vCPU pin syntax that the manual actually prints: `cpu _cpu-3 sched 8r`. Also `cpu cluster _cpu-2, _cpu-3`. An unpinned `cpu` line may run anywhere. [cpu](https://www.qnx.com/developers/docs/8.0/com.qnx.doc.hypervisor.user/topic/vm/cpu.html).
- Guest thread priority does not grant the vCPU the pCPU. The `qvm` vCPU thread's priority does. [Scheduling](https://www.qnx.com/developers/docs/8.0/com.qnx.doc.hypervisor.user/topic/virt/sched.html).
- Static vCPU runmask is a documented hypervisor security property: the guest cannot change it, because it does not have the ability. [Hypervisor security](https://www.qnx.com/developers/docs/8.0/com.qnx.doc.security.system/topic/manual/dev_hypervisor.html).
- `vdev gic` supports version 2 and version 3. Default is 3. If the hardware is GICv2, version 2 must be set. `gicr` with version 2 aborts `qvm`. BCM2711 is GIC-400 (GICv2). The option form is `version 2` under `vdev gic`. [vdev gic](https://www.qnx.com/developers/docs/8.0/com.qnx.doc.hypervisor.user/topic/vdev_ref/vdev_gic.html).
- Older fact, still the reason this matters: hypervisor 8.0.0 presented a virtual GICv3 on the Pi and Ubuntu panicked. GICv2 support came back in hypervisor build 549 (12 Jun 2025). [QNX KB 501OI00000PEvha](https://www.qnx.de/support/knowledgebase.html?id=501OI00000PEvha). Confirm the build you installed is at least that.
- `vdev virtio-console` `hostdev [<|>] path` binds the character stream. `hostdev >"|command"` feeds a host process. `name` is a command node under `/dev/qvm/...`, not the data device. [vdev virtio-console](https://www.qnx.com/developers/docs/8.0/com.qnx.doc.hypervisor.user/topic/vdev_ref/vdev_virtio-console.html).
- `vdev shmem`: `allow` implies a trailing `deny *`. `deny` implies a trailing `allow *`. Use `allow` on the one region. [vdev shmem](https://www.qnx.com/developers/docs/8.0/com.qnx.doc.hypervisor.user/topic/vdev_ref/vdev_shmem.html).
- Getting-started tree (QNX guest sample, shmem and watchdog scripts, not your safety design): [gitlab.com/qnx/hypervisor/getting-started](https://gitlab.com/qnx/hypervisor/getting-started).

### BSP

- Pi 4 BSP contains startup, I2C (source), SPI (source), serial, GPIO (binary only), network (`io-sock`), SD, PCI, USB, watchdog. No PWM driver is listed. [BSP about](https://www.qnx.com/developers/docs/BSP8.0/com.qnx.doc.bsp_raspberrypi.bcm2711.rpi4_8.0/topic/release_notes.html), [release notes](https://www.qnx.com/developers/docs/BSP8.0/com.qnx.doc.bsp.releasenotes/topic/rel_sdp80.bsp.broadcom.rpi4.bcm2711.html) (build 670, notes say it coincides with SDP 8.0.5).
- That is why the actuator is a PCA9685 on I2C, not a GPIO pulse. Software PWM would make the safety story look late.

### APS

- "QNX OS 8.0 does not support adaptive partitioning." [APS view](https://www.qnx.com/developers/docs/8.0/com.qnx.doc.ide.userguide/topic/APS_view.html).
- PLMS: the `aps` keyword works on QOS 2.2.x and is not supported in SDP 8.x. [usage differences](https://www.qnx.com/developers/docs/8.0/com.qnx.doc.plms/topic/usage_differences.html).

### Resource manager shape

- `resmgr_attach` needs `PROCMGR_AID_PATHSPACE`. [resmgr_attach parameters](https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.getting_started/topic/s1_resmgr_resmgr_attach.html).
- `devctl` is the out-of-band control path. [devctl example](https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.getting_started/topic/s1_resmgr_devctl_simple.html).

### Not verified, so not in the README as fact

- A printed one-liner `vdev gic version 2` (the option exists; the sample line does not).
- GICv2's maximum vCPU count (GICv3's page says 8).
- shmem behavior when both `allow` and `deny` are omitted.
- That `sigev_priority = -1` in one resmgr sample equals `SIGEV_PULSE_PRIO_INHERIT`.
- Any PWM claim for this BSP.

---

## 3. The idea, and the sources that justify it

These are the sources behind the product, not behind a toolchain.

| Claim | Source | How it is used |
| --- | --- | --- |
| The hackathon is a six-week push for SDP 8.0 and physical AI | QNX press release, 2 Nov 2026, and Grant Courville's remarks linked from [qnx.devpost.com](https://qnx.devpost.com/) | Enter Robotics & Medical. Do not enter with a POSIX port. |
| Cars are the base; robotics, industrial, medical, physical AI are the next markets; NVIDIA is the stack underneath | John Wall, Yahoo Finance, 22 Oct 2026; John Giamatteo, CNBC, 26 Oct 2026 | The buyer in the video is a Halos integrator, not a hackathon judge. |
| Halos certifies a platform; the integrator still owns the machine safety case | NVIDIA Halos certification pages; Tuxera, "Physical AI safety after GTC Berlin", 3 Nov 2026 | LATCH is the veto, the fallback, and the tape the integrator still has to write. Do not say you certified Halos. |
| Determinism, isolation, fault recovery, scale | Justin Moon, QNX Tech Forum Korea, 22 Oct 2026 | The four things the demo shows. Scale is "same `latchd`, second plant later", not a cluster. |
| A high-performance controller you do not trust, a boring safe controller, a switch | Lui Sha, Simplex, SEI, late 1990s | The architecture. |
| Simplex across a type-1 hypervisor for a deep net | arXiv:2509.21014 (Sep 2025) | They did not use QNX. You do. |
| More than one safe candidate, context-dependent region, decision about 0.028 ms average and 4.13 ms worst case on their bench | arXiv:2610.35040 (26 Oct 2026) | You implement two candidates (HOLD, HOME) and a box, not their ellipsoid. You publish your own cycle count. You do not quote 0.028 ms as a LATCH measurement. |
| An RTOS vendor is already selling "the RTOS that runs AI" | Wind River, 23 Oct 2026, VxWorks 26.09 | Do not win by also running a model. Win by being the side that is allowed to say no. |
| QNX/Hailo physical-AI benchmark, ~9.21 µs jitter, tighter FPS than Linux PREEMPT_RT | QNX white paper, Aug 2026 | Their camera pipeline, not your servo. Do not put the number on your scorecard. |
| Developers spend a large share of time under the feature layer | QNX Under the Hood, cited from the Korea forum | The pitch: stop rebuilding this switch per program. |

The dead-man's handle (rail) and QNX message passing (1980) are the other two parents. They do not need a URL.

---

## 4. YC and lab companies — references, not dependencies

Filtered from `yc_companies-2.csv`. None of these one-liners is a free offline library you link into `latchd`. "Open source robot OS" (Cerulion) is a different OS.

| Company | Batch | One-liner | Why it is here | Use |
| --- | --- | --- | --- | --- |
| [Salus](https://www.usesalus.ai/) | W26 | Guardrails that validate an agent's action before it executes | Same sentence as LATCH, for software agents | Cite the problem. Do not call their API from the tick. |
| [Asim](https://www.asim-group.com) | F26 | Robots operating safely in the real world | The market | Ignore their stack. |
| [Avea Robotics](https://www.avearobotics.com) | S26 | Human-in-the-loop for robots | Operator button is the same idea, done with a GPIO | No SDK. |
| [Runtime.si](https://runtime.si/) | F26 | Evaluation infrastructure for robotics | You need evals | Your eval is the five-row fault menu on the Pi. |
| [Robocurve](https://robocurve.org) | S26 | Evals for robots | Same | Same. |
| [One Robot](https://www.onerobot.io/) | W26 | World models for robot evals | Guest-side research | Not in the image. |
| [Fern](https://fern.bot) | W26 | RL environments for robotics | Training | Not in the image. |
| [Simantic](https://simantic.com) | F26 | Firmware simulation for AI agents | Would be nice later | QEMU + the Pi are the simulators you have. |
| [Workers IO](https://workers.io) | F26 | Simulation for mission-critical software | Same | Same. |
| [BootLoop](https://bootloop.ai/) | S25 | Firmware tests on real hardware | Aspirational CI | A shell script that replays frames is the CI. |
| [Null Labs](https://n0labs.com) | F25 | Simulation for defense autonomy | Not your buyer this month | Skip. |
| [Standard Physics](https://standardphysics.com/) | W26 | Fast physics for control | Overkill for one servo | Skip. |
| [Godela](http://godela.ai) | S25 | AI physics engine | Same | Skip. |
| [Elodin](https://elodin.systems/) | W24 | Flight software and hardware | Cultural cousin | Skip. |
| [Tekton Dynamics](https://www.tekton-dynamics.com) | W24 | AI control layer for welding robots | They are the untrusted controller class | Skip. |
| [Cerulion](https://www.cerulion.com) | S24 | Open-source robot OS | A different product | Do not port it. |
| [Open Actuation](https://openactuation.com) | F26 | Purpose-built actuators | Hardware market | You already bought an SG90. |
| [Silica](https://silicamachines.com/) | F26 | Actuators for physical AI | Same | Same. |
| [Vassar Robotics](https://www.vassarrobotics.com) | S25 | Robot joints | Same | Same. |
| [Dreamscale Labs](https://dreamscalelabs.com) | F26 | Real-time cloud inference for robotics | Cloud on the tick is the failure mode | Do not use. |
| [Axial](https://axialcompute.com) | F25 | Physics kernels | Not needed for a box check | Skip. |
| [CTGT](https://www.ctgt.ai/) | F24 | "Deterministic layer for frontier intelligence" | Marketing cousin of the thesis | One line in the talk track if you want. No SDK. |

Untrusted-policy companies, from `ai-companies-technical-blogs-2.md`. They are who lives in the guest in a real deployment. You do not integrate them.

| Company | Site |
| --- | --- |
| Physical Intelligence | [pi.website](https://www.pi.website/) |
| Figure AI | [figure.ai](https://www.figure.ai/) |
| 1X | [1x.tech](https://www.1x.tech/) |
| Covariant | [covariant.ai](https://covariant.ai/) |
| Waymo | [waymo.com](https://waymo.com/) |
| Waabi | [waabi.ai](https://waabi.ai/) |
| Shield AI | [shield.ai](https://shield.ai/) |

Also in that file, and also not dependencies: NVIDIA (the mind), Arm and Broadcom (the SoC), Hailo (their benchmark, not your accelerator).

---

## 5. Newsletters and engineering blogs — the five patterns worth keeping

The ask was to read Hello World / Scale Engineer, Neatprompts, TLDR AI, Superhuman, ByteByteGo, The Pragmatic Engineer, and AI Breakfast, then the top-100 engineering blogs. The pattern in the bloated blueprint was to add one vendor per email. That fails the only hackathon test that matters: could you have built it without QNX?

What those sources are actually good for, after the filter:

| Pattern | Where it showed up | What it becomes in LATCH |
| --- | --- | --- |
| A load balancer does not read the payload. A gateway does. | Scale Engineer, API gateway vs load balancer; Hello World, Nov 2026 | virtio-console is the pipe. `latchd` is the gateway: it parses, rejects, and is the only writer. Do not build an API gateway product. |
| Memoryless choice chatters. | Scale Engineer, Spotify shuffle | 25 clean frames before HP is restored. Two HA candidates, not one that oscillates. |
| Cheap deterministic check in front of an expensive model. | Scale Engineer, LinkedIn moderation; every serious agent blog (Anthropic "building effective agents") | The tick is the cheap check. The model, if any, is off to the side and killable. |
| Hermetic tests, not a shared staging environment. | Scale Engineer, Slack's E2E cut | One Python liar, five faults, same binary as the demo. |
| Assume the model is compromised. Keep an emergency brake that is not the model. | Neatprompts citing Nadella; Simon Willison, lethal trifecta, [simonwillison.net/2025/Jun/16/the-lethal-trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/) | The guest has no ability and no I2C fd. HOLD does not call the guest. |
| Do not spend tokens on the hot path. | Superhuman / The Code, Nov 2026, on token budgets | 0 tokens/tick. Not a routing layer between Haiku and Sonnet. |
| Instrument before you expand scope. | Pragmatic Engineer (measure, write the design down), ByteByteGo (one diagram, one budget) | The tape and the cycle histogram are the instrumentation. The diagram is section 2 of the implementation file. |
| Shadow a new writer before you cut over. | Scale Engineer, Airbnb migration | Optional flag inside `latchd`: compute HA, still apply HP, while you tune the box. A day of work, not a dual-write platform. |

Explicitly dropped, with the reason:

| Temptation | Why it is not in the image |
| --- | --- |
| React, Dioxus, Tailwind "ChronoScope" | The judge looks at the horn. A laptop HTML file is the viewer. |
| llama.cpp, Ollama, Unsloth, Gemma, Qwen, Outlines | A port. The open-source-port category is where it dies. A scripted liar is a worse model and a better demo, because the fault is deliberate. |
| LanceDB, Mem0, bge, ParadeDB, QuestDB, Influx, s2 | Nothing is retrieved. The tape is a ring in `.bss`. |
| Langfuse, Helicone, promptfoo, garak, Cisco MCP scanner, Visa's harness | Those audit a tool-calling agent. You do not have one on the tick. |
| LiteLLM, Claude on every fault, "dreaming" distillation | A postmortem you write by reading twenty tape lines. A cloud call in the demo is a new failure mode. |
| Shopify gisting, GraphRAG, Uber's context graph | Those compress prompts. You have no prompt. |
| Formal-proof startups (Theorem, Topos, Axiom) | You will not produce a machine-checked Lyapunov proof in six weeks. Saying you did is how a safety judge bins the project. |
| Web3, wallets, agent payment protocols | Wrong trust domain, and QNX is no longer required. |
| Adaptive partitioning snippets from old blogs | Not supported on the OS you are submitting to. |
| The blueprint's `<30 µs` WCET and the paper's `0.028 ms` | Not your measurement. |

ByteByteGo, The Pragmatic Engineer, TLDR, Superhuman, and AI Breakfast were used as filters on scope, not as dependency lists. Their home pages: [bytebytego.com](https://bytebytego.com/), [blog.pragmaticengineer.com](https://blog.pragmaticengineer.com/), [tldr.tech/ai](https://tldr.tech/ai), [superhuman.ai](https://www.superhuman.ai/), [aibreakfast.beehiiv.com](https://aibreakfast.beehiiv.com/), [scaleengineer.com](https://scaleengineer.com/), [hw.glich.co](https://hw.glich.co), [neatprompts.com](https://www.neatprompts.com/).

Engineering-blog habits stolen from the top-100 list, without their stacks:

- Stripe / Razorpay: idempotency and a sequence number. That is `seq > last_seq`.
- Honeycomb / Datadog: one histogram of a thing you actually care about. That is decision cycles.
- Netflix / Hotstar: a watchdog that is boring and always on. That is two missed ticks.
- Anthropic's agent notes: the model does not hold the credential. On a robot the credential is the I2C fd.

---

## 6. What the blueprint's C got wrong

Recorded so it does not get pasted back in.

| Blueprint | Fact |
| --- | --- |
| Safety decision uses `state_est_error_y` from the guest frame | The guest is the attacker. State has to be the host's last command, or a sensor the host read. |
| `deadline_timestamp_ns` compared with host `ClockCycles` | Different clocks. Host stamps arrival. |
| `procmgr_ability_create` then `write()` with no check, mode `0666` | The ability API is real; the sample never calls `iofunc_client_info_able`. Scenario 6 is fiction relative to that file. |
| `u_applied` computed, never written | The BSP gives you I2C. Use it. |
| Mutex held across the FIFO tick | Default protocol is priority inheritance, and the 256-slot SPSC ring + Seqlock status snapshot does not block the tick on the ingest thread. |
| `mlockall` as the determinism story | On SDP 8 the call does nothing. |
| Priority 250 as a virtue | Legal, below the clock IST, and unnecessary once the vCPU is pinned at priority 8 on other cores. |
| `vdev gic` with no version, on a Pi 4 | Default version is 3. The Pi is GICv2. |
| Certified `P` matrices typed as `1.8, 0.3, …` | Not a certificate. Use a box you measured with a ruler. |
| Merkle tape, JSON status line, Rust bridge, React UI | None of that is required to pass the five done-checks. |

---

## 7. Stack decision, one page

| Concern | Choice | Evidence |
| --- | --- | --- |
| OS | QNX SDP 8.0 host | Hackathon target |
| Isolation | Hypervisor 8.0, `cpu _cpu-2 sched 8r`, `cpu _cpu-3 sched 8r`, decision on `_cpu-0` | cpu manual, security page |
| Board interrupt controller | `vdev gic` / `version 2` | vdev gic manual, BCM2711, QNX KB 501OI00000PEvha |
| Language on the tick | C, `qcc -Vgcc_ntoaarch64le`, no third-party libs | You need to read every line |
| Actuator bus | I2C + PCA9685 | BSP contents |
| Guest | Linux + Python 3 stdlib liar | Perception is not the product |
| Auth | `latch/actuator`, default domains empty, check via `iofunc_client_info_able` | Ability manuals |
| Evidence | Fixed ring, `ClockCycles` in and out | Design criterion |
| Viewer | Laptop HTML or a serial print | Not a service |
| LLM, embeddings, agent framework, web3 | Not in the image | They fail "why QNX?" |

---

## 8. Primary URL list

QNX, fetched or opened for this pass:

- https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.lib_ref/topic/p/procmgr_ability_create.html
- https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.prog/topic/process_Ability_creating.html
- https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.lib_ref/topic/p/procmgr_ability.html
- https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.lib_ref/topic/i/iofunc_client_info_able.html
- https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.lib_ref/topic/c/connectclientinfoable.html
- https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.lib_ref/topic/i/iofunc_ability_check.html
- https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.lib_ref/topic/t/timer_create.html
- https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.lib_ref/topic/s/sigevent.html
- https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.lib_ref/topic/m/msgreceivepulse.html
- https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.lib_ref/topic/t/threadctl.html
- https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.prog/topic/multicore_processor_affinity.html
- https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.prog/topic/overview_Priority_range.html
- https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.lib_ref/topic/m/mlockall.html
- https://www.qnx.com/developers/docs/8.0/com.qnx.doc.hypervisor.user/topic/vm/cpu.html
- https://www.qnx.com/developers/docs/8.0/com.qnx.doc.hypervisor.user/topic/virt/sched.html
- https://www.qnx.com/developers/docs/8.0/com.qnx.doc.hypervisor.user/topic/vdev_ref/vdev_gic.html
- https://www.qnx.com/developers/docs/8.0/com.qnx.doc.hypervisor.user/topic/vdev_ref/vdev_virtio-console.html
- https://www.qnx.com/developers/docs/8.0/com.qnx.doc.hypervisor.user/topic/vdev_ref/vdev_shmem.html
- https://www.qnx.com/developers/docs/8.0/com.qnx.doc.hypervisor.user/topic/config/hyp.html
- https://www.qnx.com/developers/docs/8.0/com.qnx.doc.security.system/topic/manual/dev_hypervisor.html
- https://www.qnx.com/developers/docs/8.0/com.qnx.doc.ide.userguide/topic/APS_view.html
- https://www.qnx.com/developers/docs/BSP8.0/com.qnx.doc.bsp.releasenotes/topic/rel_sdp80.bsp.broadcom.rpi4.bcm2711.html
- https://gitlab.com/qnx/hypervisor/getting-started
- https://qnx.devpost.com/

Papers and industry (not re-fetched line by line in this pass; they are the product rationale, and the implementation file does not depend on their code):

- https://arxiv.org/abs/2509.21014
- https://arxiv.org/abs/2610.35040
- https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/

Anything in the YC CSV, the web3 list, or `all_links (1).txt` that is not named above was considered out of scope for the binary.
