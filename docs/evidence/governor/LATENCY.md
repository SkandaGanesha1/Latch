==============================================================================
LATCH -- ON-TARGET DECISION-LATENCY MEASUREMENT (U-4)
==============================================================================
Date: 20261127-152716
Host: Linux fedora 7.3.4-300.fc45.x86_64
Target machine        : QNX OS 8.0 / ARMv8-A, QEMU `virt` (4x Cortex-A76, EL2 VHE, GICv2)
Emulation              : QEMU TCG (no KVM) -- every number below is a TCG OBSERVATION, not a worst-case execution time
Profile: qnx/latch_qemu_latency.build (the GOVERNOR image with NO evidence logger)
Contract: qnx/contracts/governor_servo.manifest (schema 3, signed)
Workload: a HOLD at 100 mrad -- the guest streams in-envelope CMD_V2 frames at 900 Hz for 2100000 ms

WHAT IS MEASURED: the trusted supervisor's own per-tick decision
latency -- the time spent inside `latch_simplex_tick()` -- sampled
ONCE PER TICK, aggregated in a histogram ON THE TARGET, and read
back through the output-only devctl `latchctl latency`.

WHAT THIS IS NOT: it is not a WCET, and it is not a claim about
physical hardware.  Under TCG the supervisor shares host cores with
the guest Linux and with QEMU itself, so the distribution includes
the host's scheduling noise.  The maxima are the INTERESTING part
of that noise: they are what the supervisor's own worst-case
behaviour looks like when the host is busy.


==============================================================================
THE MEASUREMENT
==============================================================================

Samples (every supervisor tick) : 2128376
Decision-path samples            : 1880054
Idle-path samples                : 248322
Motion evaluations               : 1880050
Cycle rate                       : 62500000 Hz

Decision-path p50                 : [160, 192) cyc ([2560, 3072) ns)
Decision-path p99                 : [768, 1024) cyc ([12288, 16384) ns)
Exact min / max (decision path)   : 223 / 139358 cyc (3568 / 2229728 ns)
Mean (decision path)              : 534.194 cyc
Exact min / max (every tick)      : 23 / 645948 cyc (368 / 10335168 ns)
Mean (every tick)                 : 499.135 cyc

Idle path                         : p50 = [63, 64) cyc ([1008, 1024) ns) | p99 = [512, 640) cyc ([8192, 10240) ns)

Samples over the manifest's timing.wcet_budget_us : 228
Samples over the decision period                  : 10
Mode ticks                                        : HP (High Performance)=2110060 HOLD (High Assurance 1)=18307 HOME (High Assurance 2)=9

--- the achieved rates, as the target reported them ---
supervisor ticks/s : 998.2
guest proposals/s  : 887.2
producer rate      : 895.2/s over the streaming window (target 900 Hz)
peak backlog       : 11 frames (ring depth 256)

The `producer rate` is the rate over the STREAMING WINDOW -- the
samples whose lease age says the producer was alive -- and it is the
one the harness checks against the guest's declared 900.  The
`guest proposals/s` above is averaged over the WHOLE harness window,
so it is lower: it includes the tail after the guest stops.

==============================================================================
HOW TO READ THE PERCENTILES
==============================================================================

A PERCENTILE HERE IS A BUCKET RANGE, NOT AN EXACT VALUE.  The
histogram has 112 buckets: the exact cycles 0..63, and above that
three sub-buckets per octave (25% resolution).  The `min` and `max`
figures ARE exact -- they are tracked separately from the histogram.

The decision path is the path that matters: it is the tick on which a
proposal was dequeued, validated, gated, checked against the signed
envelope and applied.  The idle path is the tick on which the proposal
queue was empty; it is reported because the histogram samples EVERY
tick, and a supervisor that only ever measured its idle path would
have produced a much smaller number.

==============================================================================
THE RAW TARGET REPORT (verbatim)
==============================================================================

==============================================================================
LATCH -- ON-TARGET DECISION-LATENCY MEASUREMENT (U-4)
==============================================================================
IFS                 : /home/skanda/Downloads/latch-qnx800/latch/qnx/build/nto-aarch64-le/latch_qemu_latency.ifs
Target              : QNX OS 8.0 / ARMv8-A, QEMU `virt`, TCG
Signed contract    : qnx/contracts/governor_servo.manifest
Tick floor         : 1200000 ticks
Guest soak plan    : 900 Hz for 2100000 ms
Verdict            : PASS

--- THE GUEST'S OWN CONSOLE (from /dev/shmem/guest_console.log) ---
/proc/boot/latchctl console; echo LATCOC3_$?


=== LATCH guest console: /dev/shmem/guest_console.log ===

[    0.000000] Booting Linux on physical CPU 0x0000000000 [0x414fd0b1]


[    0.000000] Linux version 6.12.0 (skanda@fedora) (aarch64-linux-gnu-gcc (GCC) 16.2.1 20260819 (Red Hat Cross 16.2.1-1), GNU ld version 2.47.20260726) #1 SMP PREEMPT Thu Nov 12 12:11:03 IST 2026


[    0.000000] KASLR disabled due to lack of seed


[    0.000000] Machine model: QVM-v8A


[    0.000000] earlycon: pl11 at MMIO 0x000000001c090000 (options '')


[    0.000000] printk: legacy bootconsole [pl11] enabled


[    0.000000] printk: debug: skip boot console de-registration.


[    0.000000] efi: UEFI not found.


[    0.000000] [Firmware Bug]: Kernel image misaligned at boot, please fix your bootloader!


[    0.000000] NUMA: Faking a node at [mem 0x0000000080000000-0x000000009fffffff]


[    0.000000] NODE_DATA(0) allocated [mem 0x9ff05680-0x9ff07cbf]


[    0.000000] Zone ranges:


[    0.000000]   DMA      [mem 0x0000000080000000-0x000000009fffffff]


[    0.000000]   DMA32    empty


[    0.000000]   Normal   empty


[    0.000000] Movable zone start for each node


[    0.000000] Early memory node ranges


[    0.000000]   node   0: [mem 0x0000000080000000-0x000000009fffffff]


[    0.000000] Initmem setup node 0 [mem 0x0000000080000000-0x000000009fffffff]


[    0.000000] cma: Reserved 32 MiB at 0x000000009d600000 on node -1


[    0.000000] psci: probing for conduit method from DT.


[    0.000000] psci: PSCIv1.1 detected in firmware.


[    0.000000] psci: Using standard PSCI v0.2 function IDs


[    0.000000] psci: MIGRATE_INFO_TYPE returned unknown type (-2080374778)


[    0.000000] psci: SMC Calling Convention v1.1


[    0.000000] percpu: Embedded 25 pages/cpu s61656 r8192 d32552 u102400


[    0.000000] pcpu-alloc: s61656 r8192 d32552 u102400 alloc=25*4096


[    0.000000] pcpu-alloc: [0] 0 [0] 1 


[    0.000000] Detected PIPT I-cache on CPU0


[    0.000000] CPU features: detected: Spectre-v4


[    0.000000] CPU features: detected: Spectre-BHB


[    0.000000] CPU features: detected: SSBS not fully self-synchronizing


[    0.000000] alternatives: applying boot alternatives


[    0.000000] Kernel command line: earlycon=pl011,0x1c090000 keep_bootcon console=ttyAMA0,115200 root=/dev/ram0 rw rdinit=/init loglevel=8


[    0.000000] Dentry cache hash table entries: 65536 (order: 7, 524288 bytes, linear)


[    0.000000] Inode-cache hash table entries: 32768 (order: 6, 262144 bytes, linear)


[    0.000000] Fallback order for Node 0: 0 


[    0.000000] Built 1 zonelists, mobility grouping on.  Total pages: 131072


[    0.000000] Policy zone: DMA


[    0.000000] mem auto-init: stack:all(zero), heap alloc:off, heap free:off


[    0.000000] software IO TLB: SWIOTLB bounce buffer size adjusted to 0MB


[    0.000000] software IO TLB: area num 2.


[    0.000000] software IO TLB: mapped [mem 0x000000009d48d000-0x000000009d50d000] (0MB)


[    0.000000] SLUB: HWalign=64, Order=0-3, MinObjects=0, CPUs=2, Nodes=1


[    0.000000] rcu: Preemptible hierarchical RCU implementation.


[    0.000000] rcu: 	RCU event tracing is enabled.


[    0.000000] rcu: 	RCU restricting CPUs from NR_CPUS=512 to nr_cpu_ids=2.


[    0.000000] 	Trampoline variant of Tasks RCU enabled.


[    0.000000] 	Tracing variant of Tasks RCU enabled.


[    0.000000] rcu: RCU calculated value of scheduler-enlistment delay is 25 jiffies.


[    0.000000] rcu: Adjusting geometry for rcu_fanout_leaf=16, nr_cpu_ids=2


[    0.000000] RCU Tasks: Setting shift to 1 and lim to 1 rcu_task_cb_adjust=1 rcu_task_cpu_ids=2.


[    0.000000] RCU Tasks Trace: Setting shift to 1 and lim to 1 rcu_task_cb_adjust=1 rcu_task_cpu_ids=2.


[    0.000000] NR_IRQS: 64, nr_irqs: 64, preallocated irqs: 0


[    0.000000] Root IRQ handler: gic_handle_irq


[    0.000000] rcu: srcu_init: Setting srcu_struct sizes based on contention.


[    0.000000] arch_timer: cp15 timer(s) running at 62.50MHz (virt).


[    0.000000] clocksource: arch_sys_counter: mask: 0x1ffffffffffffff max_cycles: 0x1cd42e208c, max_idle_ns: 881590405314 ns


[    0.000064] sched_clock: 57 bits at 63MHz, resolution 16ns, wraps every 4398046511096ns


[    0.036789] arm-pv: using stolen time PV


[    0.065628] Console: colour dummy device 80x25


[    0.091182] Calibrating delay loop (skipped), value calculated using timer frequency.. 125.00 BogoMIPS (lpj=250000)


[    0.137919] pid_max: default: 32768 minimum: 301


[    0.160580] LSM: initializing lsm=capability


[    0.183732] Mount-cache hash table entries: 1024 (order: 1, 8192 bytes, linear)


[    0.216184] Mountpoint-cache hash table entries: 1024 (order: 1, 8192 bytes, linear)


[    0.291982] cacheinfo: Unable to detect cache hierarchy for CPU 0


[    0.359628] rcu: Hierarchical SRCU implementation.


[    0.380774] rcu: 	Max phase no-delay instances is 1000.


[    0.410519] Timer migration: 1 hierarchy levels; 8 children per group; 1 crossnode level


[    0.455125] EFI services will not be available.


[    0.478632] smp: Bringing up secondary CPUs ...


[    0.514239] Detected PIPT I-cache on CPU1


[    0.517660] CPU1: Booted secondary processor 0x0000000001 [0x414fd0b1]


[    0.524358] smp: Brought up 1 node, 2 CPUs


[    0.594057] SMP: Total of 2 processors activated.


[    0.616626] CPU: All CPU(s) started at EL1


[    0.637072] CPU features: detected: 32-bit EL0 Support


[    0.660824] CPU features: detected: Data cache clean to the PoU not required for I/D coherence


[    0.699617] CPU features: detected: Common not Private translations


[    0.728180] CPU features: detected: CRC32 instructions


[    0.753067] CPU features: detected: RCpc load-acquire (LDAPR)


[    0.779763] CPU features: detected: LSE atomic instructions


[    0.806622] CPU features: detected: Privileged Access Never


[    0.833163] CPU features: detected: RAS Extension Support


[    0.857525] CPU features: detected: Speculative Store Bypassing Safe (SSBS)


[    0.901578] alternatives: applying system-wide alternatives


[    0.948023] CPU features: detected: Hardware dirty bit management on CPU0-1


[    1.002155] Memory: 439544K/524288K available (17600K kernel code, 4900K rwdata, 11872K rodata, 2880K init, 742K bss, 49940K reserved, 32768K cma-reserved)


[    1.098236] devtmpfs: initialized


[    1.143028] clocksource: jiffies: mask: 0xffffffff max_cycles: 0xffffffff, max_idle_ns: 7645041785100000 ns


[    1.188767] futex hash table entries: 512 (order: 3, 32768 bytes, linear)


[    1.222697] 23200 pages in range for non-PLT usage


[    1.222790] 514720 pages in range for PLT usage


[    1.250872] pinctrl core: initialized pinctrl subsystem


[    1.307640] DMI not present or invalid.


[    1.376461] NET: Registered PF_NETLINK/PF_ROUTE protocol family


[    1.423855] DMA: preallocated 128 KiB GFP_KERNEL pool for atomic allocations


[    1.458903] DMA: preallocated 128 KiB GFP_KERNEL|GFP_DMA pool for atomic allocations


[    1.496351] DMA: preallocated 128 KiB GFP_KERNEL|GFP_DMA32 pool for atomic allocations


[    1.532854] audit: initializing netlink subsys (disabled)


[    1.563353] audit: type=2000 audit(0.432:1): state=initialized audit_enabled=0 res=1


[    1.569216] thermal_sys: Registered thermal governor 'step_wise'


[    1.602626] thermal_sys: Registered thermal governor 'power_allocator'


[    1.635937] cpuidle: using governor menu


[    1.690224] hw-breakpoint: found 6 breakpoint and 4 watchpoint registers.


[    1.724425] ASID allocator initialised with 65536 entries


[    1.762250] Serial: AMBA PL011 UART driver


[    1.813664] 1c090000.uart: ttyAMA0 at MMIO 0x1c090000 (irq = 13, base_baud = 0) is a PL011 rev3


[    1.856487] printk: legacy console [ttyAMA0] enabled


[    1.856487] printk: legacy console [ttyAMA0] enabled


[    1.924458] HugeTLB: registered 1.00 GiB page size, pre-allocated 0 pages


[    1.924458] HugeTLB: registered 1.00 GiB page size, pre-allocated 0 pages


[    1.983069] HugeTLB: 0 KiB vmemmap can be freed for a 1.00 GiB page


[    1.983069] HugeTLB: 0 KiB vmemmap can be freed for a 1.00 GiB page


[    2.036139] HugeTLB: registered 32.0 MiB page size, pre-allocated 0 pages


[    2.036139] HugeTLB: registered 32.0 MiB page size, pre-allocated 0 pages


[    2.094834] HugeTLB: 0 KiB vmemmap can be freed for a 32.0 MiB page


[    2.094834] HugeTLB: 0 KiB vmemmap can be freed for a 32.0 MiB page


[    2.147555] HugeTLB: registered 2.00 MiB page size, pre-allocated 0 pages


[    2.147555] HugeTLB: registered 2.00 MiB page size, pre-allocated 0 pages


[    2.206058] HugeTLB: 0 KiB vmemmap can be freed for a 2.00 MiB page


[    2.206058] HugeTLB: 0 KiB vmemmap can be freed for a 2.00 MiB page


[    2.258584] HugeTLB: registered 64.0 KiB page size, pre-allocated 0 pages


[    2.258584] HugeTLB: registered 64.0 KiB page size, pre-allocated 0 pages


[    2.318697] HugeTLB: 0 KiB vmemmap can be freed for a 64.0 KiB page


[    2.318697] HugeTLB: 0 KiB vmemmap can be freed for a 64.0 KiB page


[    2.393705] ACPI: Interpreter disabled.


[    2.393705] ACPI: Interpreter disabled.


[    2.438823] iommu: Default domain type: Translated


[    2.438823] iommu: Default domain type: Translated


[    2.486210] iommu: DMA domain TLB invalidation policy: strict mode


[    2.486210] iommu: DMA domain TLB invalidation policy: strict mode


[    2.544353] SCSI subsystem initialized


[    2.544353] SCSI subsystem initialized


[    2.583197] libata version 3.00 loaded.


[    2.583197] libata version 3.00 loaded.


[    2.620566] usbcore: registered new interface driver usbfs


[    2.620566] usbcore: registered new interface driver usbfs


[    2.669760] usbcore: registered new interface driver hub


[    2.669760] usbcore: registered new interface driver hub


[    2.719300] usbcore: registered new device driver usb


[    2.719300] usbcore: registered new device driver usb


[    2.766408] pps_core: LinuxPPS API ver. 1 registered


[    2.766408] pps_core: LinuxPPS API ver. 1 registered


[    2.810817] pps_core: Software ver. 5.3.6 - Copyright 2005-2007 Rodolfo Giometti <giometti@linux.it>


[    2.810817] pps_core: Software ver. 5.3.6 - Copyright 2005-2007 Rodolfo Giometti <giometti@linux.it>


[    2.890857] PTP clock support registered


[    2.890857] PTP clock support registered


[    2.927109] EDAC MC: Ver: 3.0.0


[    2.927109] EDAC MC: Ver: 3.0.0


[    2.961264] scmi_core: SCMI protocol bus registered


[    2.961264] scmi_core: SCMI protocol bus registered


[    3.012155] FPGA manager framework


[    3.012155] FPGA manager framework


[    3.043572] Advanced Linux Sound Architecture Driver Initialized.


[    3.043572] Advanced Linux Sound Architecture Driver Initialized.


[    3.113220] vgaarb: loaded


[    3.113220] vgaarb: loaded


[    3.146233] clocksource: Switched to clocksource arch_sys_counter


[    3.146233] clocksource: Switched to clocksource arch_sys_counter


[    3.214613] VFS: Disk quotas dquot_6.6.0


[    3.214613] VFS: Disk quotas dquot_6.6.0


[    3.251298] VFS: Dquot-cache hash table entries: 512 (order 0, 4096 bytes)


[    3.251298] VFS: Dquot-cache hash table entries: 512 (order 0, 4096 bytes)


[    3.319638] pnp: PnP ACPI: disabled


[    3.319638] pnp: PnP ACPI: disabled


[    3.503283] NET: Registered PF_INET protocol family


[    3.503283] NET: Registered PF_INET protocol family


[    3.558151] IP idents hash table entries: 8192 (order: 4, 65536 bytes, linear)


[    3.558151] IP idents hash table entries: 8192 (order: 4, 65536 bytes, linear)


[    3.631525] tcp_listen_portaddr_hash hash table entries: 256 (order: 0, 4096 bytes, linear)


[    3.631525] tcp_listen_portaddr_hash hash table entries: 256 (order: 0, 4096 bytes, linear)


[    3.707487] Table-perturb hash table entries: 65536 (order: 6, 262144 bytes, linear)


[    3.707487] Table-perturb hash table entries: 65536 (order: 6, 262144 bytes, linear)


[    3.782521] TCP established hash table entries: 4096 (order: 3, 32768 bytes, linear)


[    3.782521] TCP established hash table entries: 4096 (order: 3, 32768 bytes, linear)


[    3.850419] TCP bind hash table entries: 4096 (order: 5, 131072 bytes, linear)


[    3.850419] TCP bind hash table entries: 4096 (order: 5, 131072 bytes, linear)


[    3.914631] TCP: Hash tables configured (established 4096 bind 4096)


[    3.914631] TCP: Hash tables configured (established 4096 bind 4096)


[    3.970783] UDP hash table entries: 256 (order: 1, 8192 bytes, linear)


[    3.970783] UDP hash table entries: 256 (order: 1, 8192 bytes, linear)


[    4.026675] UDP-Lite hash table entries: 256 (order: 1, 8192 bytes, linear)


[    4.026675] UDP-Lite hash table entries: 256 (order: 1, 8192 bytes, linear)


[    4.087785] NET: Registered PF_UNIX/PF_LOCAL protocol family


[    4.087785] NET: Registered PF_UNIX/PF_LOCAL protocol family


[    4.147531] RPC: Registered named UNIX socket transport module.


[    4.147531] RPC: Registered named UNIX socket transport module.


[    4.198608] RPC: Registered udp transport module.


[    4.198608] RPC: Registered udp transport module.


[    4.240069] RPC: Registered tcp transport module.


[    4.240069] RPC: Registered tcp transport module.


[    4.281822] RPC: Registered tcp-with-tls transport module.


[    4.281822] RPC: Registered tcp-with-tls transport module.


[    4.328853] RPC: Registered tcp NFSv4.1 backchannel transport module.


[    4.328853] RPC: Registered tcp NFSv4.1 backchannel transport module.


[    4.383130] PCI: CLS 0 bytes, default 64


[    4.383130] PCI: CLS 0 bytes, default 64


[    4.423240] kvm [1]: HYP mode not available


[    4.424506] Unpacking initramfs...


[    4.447225] Initialise system trusted keyrings


[    4.423240] kvm [1]: HYP mode not available


[    4.424506] Unpacking initramfs...


[    4.447225] Initialise system trusted keyrings


[    4.547532] workingset: timestamp_bits=42 max_order=17 bucket_order=0


[    4.547532] workingset: timestamp_bits=42 max_order=17 bucket_order=0


[    4.608581] squashfs: version 4.0 (2009/01/31) Phillip Lougher


[    4.608581] squashfs: version 4.0 (2009/01/31) Phillip Lougher


[    4.666220] NFS: Registering the id_resolver key type


[    4.666220] NFS: Registering the id_resolver key type


[    4.713719] Key type id_resolver registered


[    4.713719] Key type id_resolver registered


[    4.751872] Key type id_legacy registered


[    4.751872] Key type id_legacy registered


[    4.791144] nfs4filelayout_init: NFSv4 File Layout Driver Registering...


[    4.791144] nfs4filelayout_init: NFSv4 File Layout Driver Registering...


[    4.849705] nfs4flexfilelayout_init: NFSv4 Flexfile Layout Driver Registering...


[    4.849705] nfs4flexfilelayout_init: NFSv4 Flexfile Layout Driver Registering...


[    4.914771] 9p: Installing v9fs 9p2000 file system support


[    4.914771] 9p: Installing v9fs 9p2000 file system support


[    5.015064] Key type asymmetric registered


[    5.015064] Key type asymmetric registered


[    5.050609] Asymmetric key parser 'x509' registered


[    5.050609] Asymmetric key parser 'x509' registered


[    5.093782] Block layer SCSI generic (bsg) driver version 0.4 loaded (major 245)


[    5.093782] Block layer SCSI generic (bsg) driver version 0.4 loaded (major 245)


[    5.157412] io scheduler mq-deadline registered


[    5.157412] io scheduler mq-deadline registered


[    5.196598] io scheduler kyber registered


[    5.196598] io scheduler kyber registered


[    5.231959] io scheduler bfq registered


[    5.231959] io scheduler bfq registered


[    5.302008] ledtrig-cpu: registered to indicate activity on CPUs


[    5.302008] ledtrig-cpu: registered to indicate activity on CPUs


[    5.491910] Serial: 8250/16550 driver, 4 ports, IRQ sharing enabled


[    5.491910] Serial: 8250/16550 driver, 4 ports, IRQ sharing enabled


[    5.567115] msm_serial: driver initialized


[    5.567115] msm_serial: driver initialized


[    5.604183] SuperH (H)SCI(F) driver initialized


[    5.604183] SuperH (H)SCI(F) driver initialized


[    5.644104] STM32 USART driver initialized


[    5.644104] STM32 USART driver initialized


[    5.744118] loop: module loaded


[    5.744118] loop: module loaded


[    5.777626] megasas: 07.727.03.00-rc1


[    5.777626] megasas: 07.727.03.00-rc1


[    5.836182] tun: Universal TUN/TAP device driver, 1.6


[    5.836182] tun: Universal TUN/TAP device driver, 1.6


[    5.887827] thunder_xcv, ver 1.0


[    5.887827] thunder_xcv, ver 1.0


[    5.921869] thunder_bgx, ver 1.0


[    5.921869] thunder_bgx, ver 1.0


[    5.954767] nicpf, ver 1.0


[    5.954767] nicpf, ver 1.0


[    5.983961] hns3: Hisilicon Ethernet Network Driver for Hip08 Family - version


[    5.983961] hns3: Hisilicon Ethernet Network Driver for Hip08 Family - version


[    6.047837] hns3: Copyright (c) 2017 Huawei Corporation.


[    6.047837] hns3: Copyright (c) 2017 Huawei Corporation.


[    6.095946] hclge is initializing


[    6.095946] hclge is initializing


[    6.126308] e1000: Intel(R) PRO/1000 Network Driver


[    6.126308] e1000: Intel(R) PRO/1000 Network Driver


[    6.170168] e1000: Copyright (c) 1999-2006 Intel Corporation.


[    6.170168] e1000: Copyright (c) 1999-2006 Intel Corporation.


[    6.221965] e1000e: Intel(R) PRO/1000 Network Driver


[    6.221965] e1000e: Intel(R) PRO/1000 Network Driver


[    6.265690] e1000e: Copyright(c) 1999 - 2015 Intel Corporation.


[    6.265690] e1000e: Copyright(c) 1999 - 2015 Intel Corporation.


[    6.320712] igb: Intel(R) Gigabit Ethernet Network Driver


[    6.320712] igb: Intel(R) Gigabit Ethernet Network Driver


[    6.371581] igb: Copyright (c) 2007-2014 Intel Corporation.


[    6.371581] igb: Copyright (c) 2007-2014 Intel Corporation.


[    6.419343] igbvf: Intel(R) Gigabit Virtual Function Network Driver


[    6.419343] igbvf: Intel(R) Gigabit Virtual Function Network Driver


[    6.471869] igbvf: Copyright (c) 2009 - 2012 Intel Corporation.


[    6.471869] igbvf: Copyright (c) 2009 - 2012 Intel Corporation.


[    6.527088] sky2: driver version 1.30


[    6.527088] sky2: driver version 1.30


[    6.575313] VFIO - User Level meta-driver version: 0.3


[    6.575313] VFIO - User Level meta-driver version: 0.3


[    6.632926] usbcore: registered new interface driver usb-storage


[    6.632926] usbcore: registered new interface driver usb-storage


[    6.695266] i2c_dev: i2c /dev entries driver


[    6.695266] i2c_dev: i2c /dev entries driver


[    6.751463] sdhci: Secure Digital Host Controller Interface driver


[    6.751463] sdhci: Secure Digital Host Controller Interface driver


[    6.806166] sdhci: Copyright(c) Pierre Ossman


[    6.806166] sdhci: Copyright(c) Pierre Ossman


[    6.856086] Synopsys Designware Multimedia Card Interface Driver


[    6.856086] Synopsys Designware Multimedia Card Interface Driver


[    6.920224] sdhci-pltfm: SDHCI platform and OF driver helper


[    6.920224] sdhci-pltfm: SDHCI platform and OF driver helper


[    6.980708] usbcore: registered new interface driver usbhid


[    6.980708] usbcore: registered new interface driver usbhid


[    7.032040] usbhid: USB HID core driver


[    7.032040] usbhid: USB HID core driver


[    7.083714] hw perfevents: enabled with armv8_pmuv3 PMU driver, 7 (0,8000003f) counters available


[    7.083714] hw perfevents: enabled with armv8_pmuv3 PMU driver, 7 (0,8000003f) counters available


[    7.188566] NET: Registered PF_PACKET protocol family


[    7.188566] NET: Registered PF_PACKET protocol family


[    7.242928] 9pnet: Installing 9P2000 support


[    7.242928] 9pnet: Installing 9P2000 support


[    7.286031] Key type dns_resolver registered


[    7.286031] Key type dns_resolver registered


[    7.362087] registered taskstats version 1


[    7.362087] registered taskstats version 1


[    7.405510] Loading compiled-in X.509 certificates


[    7.405510] Loading compiled-in X.509 certificates


[    7.473923] Demotion targets for Node 0: null


[    7.473923] Demotion targets for Node 0: null


[    7.526635] clk: Disabling unused clocks


[    7.526635] clk: Disabling unused clocks


[    7.568156] PM: genpd: Disabling unused power domains


[    7.568156] PM: genpd: Disabling unused power domains


[    7.618386] ALSA device list:


[    7.618386] ALSA device list:


[    7.649636]   No soundcards found.


[    7.649636]   No soundcards found.


[    7.762709] Freeing unused kernel memory: 2880K


[    7.762709] Freeing unused kernel memory: 2880K


[    7.806718] Run /init as init process


[    7.806718] Run /init as init process


[    7.840702]   with arguments:


[    7.840702]   with arguments:


[    7.866648]     /init


[    7.866648]     /init


[    7.888661]   with environment:


[    7.888661]   with environment:


[    7.918502]     HOME=/


[    7.918502]     HOME=/


[    7.940123]     TERM=linux


[    7.940123]     TERM=linux


[    8.006072] 


[    8.006072] === LATCH Linux 6.12 Guest Userspace (/init) Alive ===


[    8.006072] 


[    8.006072] 


[    8.006072] === LATCH Linux 6.12 Guest Userspace (/init) Alive ===


[    8.006072] 


[    8.085761] [guest] PID 1 = this binary. The in-guest policy IS /init.


[    8.085761] 


[    8.085761] [guest] PID 1 = this binary. The in-guest policy IS /init.


[    8.085761] 


[    8.156792] [guest] /dev/hvc0 opened! Configuring raw mode for GOVERNOR wire v2...


[    8.156792] 


[    8.156792] [guest] /dev/hvc0 opened! Configuring raw mode for GOVERNOR wire v2...


[    8.156792] 


[    8.238559] [LATENCY] soak: 900 Hz in-envelope CMD_V2 stream for 2100000 ms


[    8.238559] 


[    8.238559] [LATENCY] soak: 900 Hz in-envelope CMD_V2 stream for 2100000 ms


[    8.238559] 


[    8.312014] [LATENCY] the plant is walked to 100 mrad on a 5 mrad staircase, then holds


[    8.312014] 


[    8.312014] [LATENCY] the plant is walked to 100 mrad on a 5 mrad staircase, then holds


[    8.312014] 


[    8.396229] [LATENCY] the console stays quiet until the soak ends


[    8.396229] 


[    8.396229] [LATENCY] the console stays quiet until the soak ends


[    8.396229] 


LATCOC3_0

#

--- THE SOAK'S RATES, AS THE TARGET REPORTED THEM ---
supervisor ticks/s  : 998.2
guest proposals/s   : 887.2
proposals per tick  : 0.889
peak backlog        : 11 frames (ring depth 256)
wall-clock seconds  : 2110.4
producer rate       : 895.2/s over the streaming window (target 900 Hz)

--- THE SUPERVISOR'S STATUS, SAMPLED DURING THE SOAK ---
tick         proposals    rung         drops      backlog    overruns   decision_lat theta    vel      alive 
21688        7832         HP           0          5          7          168          100      0        yes   
41748        25780        HP           0          5          15         117          100      0        yes   
61815        43797        HP           0          5          19         1289         100      0        yes   
81896        61712        HP           0          5          27         201          100      0        yes   
101955       79692        HP           0          6          30         119          100      0        yes   
122029       97728        HP           0          7          34         315          100      0        yes   
142076       115732       HP           0          8          36         131          100      0        yes   
162041       133640       HP           0          9          40         227          100      0        yes   
182073       151628       HP           0          9          40         97           100      0        yes   
202130       169660       HP           0          9          45         87           100      0        yes   
222207       187645       HP           0          9          49         2211         100      0        yes   
242303       205692       HP           0          9          52         968          100      0        yes   
262368       223704       HP           0          9          53         278          100      0        yes   
282388       241589       HP           0          9          62         1259         100      0        yes   
302450       259541       HP           0          10         67         2285         100      0        yes   
322554       277576       HP           0          10         69         237          100      0        yes   
342615       295528       HP           0          10         70         91           100      0        yes   
362685       313535       HP           0          10         72         442          100      0        yes   
382767       331465       HP           0          10         72         941          100      0        yes   
402844       349396       HP           0          10         76         89           100      0        yes   
422912       367412       HP           0          10         76         129          100      0        yes   
443023       385408       HP           0          10         77         209          100      0        yes   
463046       403184       HP           0          10         85         212          100      0        yes   
483116       421220       HP           0          10         85         94           100      0        yes   
503206       439256       HP           0          10         86         160          100      0        yes   
523255       457280       HP           0          10         88         138          100      0        yes   
543335       475328       HP           0          10         88         145          100      0        yes   
563378       493300       HP           0          10         89         122          100      0        yes   
583423       511196       HP           0          10         95         149          100      0        yes   
603483       529225       HP           0          11         96         1039         100      0        yes   
623544       547252       HP           0          11         96         92           100      0        yes   
643562       565144       HP           0          11         101        140          100      0        yes   
663655       583160       HP           0          11         102        114          100      0        yes   
683736       601164       HP           0          11         102        142          100      0        yes   
703825       619148       HP           0          11         102        879          100      0        yes   
723853       636976       HP           0          11         106        125          100      0        yes   
743956       655008       HP           0          11         107        122          100      0        yes   
764003       673035       HP           0          11         108        365          100      0        yes   
784072       691053       HP           0          11         109        2698         100      0        yes   
804177       709088       HP           0          11         112        158          100      0        yes   
824224       727112       HP           0          11         114        130          100      0        yes   
844305       745140       HP           0          11         114        171          100      0        yes   
864378       763176       HP           0          11         115        141          100      0        yes   
884442       781184       HP           0          11         117        98           100      0        yes   
904521       799216       HP           0          11         120        486          100      0        yes   
924598       817232       HP           0          11         122        193          100      0        yes   
944589       835148       HP           0          11         129        106          100      0        yes   
964678       853216       HP           0          11         129        510          100      0        yes   
984729       871224       HP           0          11         129        131          100      0        yes   
1004796      889244       HP           0          11         130        118          100      0        yes   
1024864      907280       HP           0          11         130        95           100      0        yes   
1044919      925288       HP           0          11         131        109          100      0        yes   
1064987      943272       HP           0          11         131        157          100      0        yes   
1085080      961340       HP           0          11         131        146          100      0        yes   
1105156      979365       HP           0          11         132        1007         100      0        yes   
1125200      997301       HP           0          11         133        1330         100      0        yes   
1145260      1015348      HP           0          11         135        151          100      0        yes   
1165350      1033373      HP           0          11         136        657          100      0        yes   
1185406      1051364      HP           0          11         137        529          100      0        yes   
1205471      1069384      HP           0          11         138        472          100      0        yes   
1225549      1087384      HP           0          11         138        166          100      0        yes   
1245650      1105376      HP           0          11         138        185          100      0        yes   
1265672      1123304      HP           0          11         140        269          100      0        yes   
1285752      1141309      HP           0          11         142        1091         100      0        yes   
1305787      1159272      HP           0          11         144        108          100      0        yes   
1325858      1177248      HP           0          11         147        212          100      0        yes   
1345942      1195280      HP           0          11         150        130          100      0        yes   
1366001      1213288      HP           0          11         151        165          100      0        yes   
1386064      1231316      HP           0          11         153        130          100      0        yes   
1406097      1249277      HP           0          11         157        2241         100      0        yes   
1426145      1267240      HP           0          11         159        158          100      0        yes   
1446199      1285228      HP           0          11         163        140          100      0        yes   
1466278      1303221      HP           0          11         166        1240         100      0        yes   
1486354      1321225      HP           0          11         168        1127         100      0        yes   
1506429      1339245      HP           0          11         170        1171         100      0        yes   
1526474      1357208      HP           0          11         173        204          100      0        yes   
1546539      1375224      HP           0          11         174        116          100      0        yes   
1566545      1393100      HP           0          11         177        248          100      0        yes   
1586604      1411060      HP           0          11         178        136          100      0        yes   
1606676      1429056      HP           0          11         179        118          100      0        yes   
1626728      1447052      HP           0          11         181        663          100      0        yes   
1646791      1465052      HP           0          11         182        178          100      0        yes   
1666861      1483073      HP           0          11         182        2487         100      0        yes   
1686950      1501113      HP           0          11         182        1154         100      0        yes   
1707032      1519136      HP           0          11         184        94           100      0        yes   
1727071      1537040      HP           0          11         184        730          100      0        yes   
1747137      1555040      HP           0          11         184        125          100      0        yes   
1767185      1573045      HP           0          11         186        1044         100      0        yes   
1787261      1591060      HP           0          11         187        131          100      0        yes   
1807342      1609023      HP           0          11         192        649          100      0        yes   
1827452      1627057      HP           0          11         194        2721         100      0        yes   
1847500      1645028      HP           0          11         195        1145         100      0        yes   
1867578      1663044      HP           0          11         196        125          100      0        yes   
1887532      1680767      HP           0          11         204        428          100      0        yes   
1907604      1698776      HP           0          11         205        95           100      0        yes   
1927678      1716780      HP           0          11         206        137          100      0        yes   
1947721      1734800      HP           0          11         207        187          100      0        yes   
1967782      1752797      HP           0          11         209        1221         100      0        yes   
1987844      1770816      HP           0          11         209        108          100      0        yes   
2007892      1788833      HP           0          11         213        3064         100      0        yes   
2027936      1806804      HP           0          11         216        83           100      0        yes   
2047989      1824788      HP           0          11         219        119          100      0        yes   
2068074      1842808      HP           0          11         220        106          100      0        yes   
2088150      1860848      HP           0          11         221        124          100      0        yes   
2108231      1878876      HP           0          11         223        114          100      0        yes   
2128285      1880054      LATCH        0          11         227        94           0        0        no    

--- THE LATENCY DISTRIBUTION (latchctl latency, verbatim) ---
/proc/boot/latchctl latency; echo LATCOC110_$?


=== LATCH Supervisor Decision-Latency Distribution ===

Samples (ticks)       : 2128376

Decision-path samples : 1880054 (a proposal was dequeued)

Idle-path samples     : 248322 (the proposal queue was empty)

Motion evaluations    : 1880050 (of the decision-path samples)

Cycle rate            : 62500000 Hz

First / last tick     : 1 / 2128376

Min / Max (decision)  : 223 / 139358 cyc (3568 / 2229728 ns)

Mean (decision)       : 534.194 cyc

Min / Max (all ticks) : 23 / 645948 cyc (368 / 10335168 ns)

Mean (all ticks)      : 499.135 cyc

Decision path         : p50 = [160, 192) cyc ([2560, 3072) ns) | p99 = [768, 1024) cyc ([12288, 16384) ns)

Idle path             : p50 = [63, 64) cyc ([1008, 1024) ns) | p99 = [512, 640) cyc ([8192, 10240) ns)

Histogram shape      : decision path 28 non-empty buckets | idle path 68 non-empty buckets (of 112)

Over budget           : 228 samples (over the manifest's timing.wcet_budget_us)

Over tick period      : 10 samples (over the decision period)

Mode ticks            : HP (High Performance)=2110060 HOLD (High Assurance 1)=18307 HOME (High Assurance 2)=9

LATCOC110_0

#

--- THE FINAL SUPERVISOR STATUS ---
/proc/boot/latchctl status; echo LATCOC111_$?


=== LATCH Simplex Supervisor Status ===

Tick Counter         : 2128477 ticks

Current Mode         : HOLD (High Assurance 1)

Actuator Angle       : 0 mrad

Velocity / Omega     : 0 mrad/tick | 0 mrad/s

Last Proposed Angle  : 100 mrad (seq=1880054)

Decision Latency     : last = 820 cyc (13120 ns) | max = 645948 cyc (10335168 ns)

Proposals Received   : 1880054

Wire Faults Caught   : 0

Envelope Vetoes      : 0

Ring Drops / WCET    : 0 drops | 227 overruns

Proposal Backlog     : peak 11 frames | 0 over limit

EPERM Rejections     : 0

Operator Hold Locked : NO

Active Fault Bits    : 0x0000 (NONE)

Latched Fault Bits   : 0x2000 (HEARTBEAT)

Clean Streak         : 0 frames

GOVERNOR             : enabled | rung=LATCH (5)

V2 Session / Lease   : active | 84 ticks left | lease age 18916 ticks

Warm-up / Agent      : 4 heartbeats | state 1

Recovery Clean       : 0 accepted commands

Deadline Misses      : 10 overruns

HOMEOSTAT            : disabled | scale_q8=256 (256=unity) | v_max ceiling=0 | stress epochs=0

Lease Owner          : valid | producer tag 1 | session dead YES

Foreign / Takeovers  : 0 frames | 0 takeovers

Session Epoch        : bound | 0x24C60D14

Rate / Shrink        : 40 tokens | active=0 v_max=0 scale_q8=255

Coherence            : valid | counter=1880054

Manifest SHA-256     : a29b81341077ac0e4276d91b5ff703c700243db69b674f7cbb466c0689ddc53b

LATCOC111_0

#

==============================================================================
WHAT THIS DOES NOT PROVE
==============================================================================

* This is NOT a WCET and must never be quoted as one.  It is the
  observed distribution of one emulated target under TCG, where the
  supervisor shares host cores with the guest and with QEMU.
* It is NOT a measurement of the Raspberry Pi 4B target, and not a
  measurement of the host-sim.  The host-sim's latency is load
  dependent and is deliberately not quoted anywhere.
* The samples over the manifest's budget are the HOST's noise, not
  the supervisor's logic: under TCG the decision thread can be
  preempted by the host for longer than the tick period.
* The workload is a HOLD at 100 mrad: the plant stands still and the
  supervisor keeps deciding.  It is the workload this profile was
  built to measure, and it is not every workload.

