==============================================================================
LATCH -- ON-TARGET DECISION-LATENCY MEASUREMENT (U-4)
==============================================================================
Date: 20261127-084147
Host: Linux fedora 7.3.4-300.fc45.x86_64
Target machine        : QNX OS 8.0 / ARMv8-A, QEMU `virt` (4x Cortex-A76, EL2 VHE, GICv2)
Emulation              : QEMU TCG (no KVM) -- every number below is a TCG OBSERVATION, not a worst-case execution time
Profile: qnx/latch_qemu_latency.build (the GOVERNOR image with NO evidence logger)
Contract: qnx/contracts/governor_servo.manifest (schema 3, signed)
Workload: 900 Hz for 2100000 ms

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

Samples (every supervisor tick) : 2129049
Decision-path samples            : 1890224
Idle-path samples                : 238825
Motion evaluations               : 1890220
Cycle rate                       : 62500000 Hz

Decision-path p50                 : [160, 192) cyc ([2560, 3072) ns
Decision-path p99                 : [768, 1024) cyc ([12288, 16384) ns
Exact min / max (decision path)   : 223 / 261336 cyc (3568 / 4181376 ns)
Mean (decision path)              : 542.869 cyc
Exact min / max (every tick)      : 20 / 261336 cyc (320 / 4181376 ns)
Mean (every tick)                 : 510.018 cyc

Idle path                         : p50 = [64, 80) cyc ([1024, 1280) ns) | p99 = [512, 640) cyc ([8192, 10240) ns)

Samples over the manifest's timing.wcet_budget_us : 202
Samples over the decision period                  : 8
Mode ticks                                        : HP (High Performance)=2109735 HOLD (High Assurance 1)=19305 HOME (High Assurance 2)=9

--- the achieved rates, as the target reported them ---
supervisor ticks/s : 998.5
guest proposals/s  : 891.5
peak backlog       : 72 frames (ring depth 256)

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


[    0.000085] sched_clock: 57 bits at 63MHz, resolution 16ns, wraps every 4398046511096ns


[    0.034111] arm-pv: using stolen time PV


[    0.060918] Console: colour dummy device 80x25


[    0.082431] Calibrating delay loop (skipped), value calculated using timer frequency.. 125.00 BogoMIPS (lpj=250000)


[    0.125183] pid_max: default: 32768 minimum: 301


[    0.146469] LSM: initializing lsm=capability


[    0.168343] Mount-cache hash table entries: 1024 (order: 1, 8192 bytes, linear)


[    0.198372] Mountpoint-cache hash table entries: 1024 (order: 1, 8192 bytes, linear)


[    0.267761] cacheinfo: Unable to detect cache hierarchy for CPU 0


[    0.327804] rcu: Hierarchical SRCU implementation.


[    0.348127] rcu: 	Max phase no-delay instances is 1000.


[    0.375253] Timer migration: 1 hierarchy levels; 8 children per group; 1 crossnode level


[    0.414973] EFI services will not be available.


[    0.437850] smp: Bringing up secondary CPUs ...


[    0.467778] Detected PIPT I-cache on CPU1


[    0.471051] CPU1: Booted secondary processor 0x0000000001 [0x414fd0b1]


[    0.478956] smp: Brought up 1 node, 2 CPUs


[    0.542281] SMP: Total of 2 processors activated.


[    0.562920] CPU: All CPU(s) started at EL1


[    0.582385] CPU features: detected: 32-bit EL0 Support


[    0.603919] CPU features: detected: Data cache clean to the PoU not required for I/D coherence


[    0.639878] CPU features: detected: Common not Private translations


[    0.667480] CPU features: detected: CRC32 instructions


[    0.691529] CPU features: detected: RCpc load-acquire (LDAPR)


[    0.718544] CPU features: detected: LSE atomic instructions


[    0.741803] CPU features: detected: Privileged Access Never


[    0.767439] CPU features: detected: RAS Extension Support


[    0.790096] CPU features: detected: Speculative Store Bypassing Safe (SSBS)


[    0.827218] alternatives: applying system-wide alternatives


[    0.867001] CPU features: detected: Hardware dirty bit management on CPU0-1


[    0.919756] Memory: 439544K/524288K available (17600K kernel code, 4900K rwdata, 11872K rodata, 2880K init, 742K bss, 49940K reserved, 32768K cma-reserved)


[    1.009642] devtmpfs: initialized


[    1.050078] clocksource: jiffies: mask: 0xffffffff max_cycles: 0xffffffff, max_idle_ns: 7645041785100000 ns


[    1.095559] futex hash table entries: 512 (order: 3, 32768 bytes, linear)


[    1.127016] 23200 pages in range for non-PLT usage


[    1.127143] 514720 pages in range for PLT usage


[    1.151917] pinctrl core: initialized pinctrl subsystem


[    1.201331] DMI not present or invalid.


[    1.258567] NET: Registered PF_NETLINK/PF_ROUTE protocol family


[    1.299418] DMA: preallocated 128 KiB GFP_KERNEL pool for atomic allocations


[    1.331543] DMA: preallocated 128 KiB GFP_KERNEL|GFP_DMA pool for atomic allocations


[    1.366326] DMA: preallocated 128 KiB GFP_KERNEL|GFP_DMA32 pool for atomic allocations


[    1.399518] audit: initializing netlink subsys (disabled)


[    1.428949] audit: type=2000 audit(0.396:1): state=initialized audit_enabled=0 res=1


[    1.436292] thermal_sys: Registered thermal governor 'step_wise'


[    1.467153] thermal_sys: Registered thermal governor 'power_allocator'


[    1.497204] cpuidle: using governor menu


[    1.548395] hw-breakpoint: found 6 breakpoint and 4 watchpoint registers.


[    1.581769] ASID allocator initialised with 65536 entries


[    1.616731] Serial: AMBA PL011 UART driver


[    1.659982] 1c090000.uart: ttyAMA0 at MMIO 0x1c090000 (irq = 13, base_baud = 0) is a PL011 rev3


[    1.699803] printk: legacy console [ttyAMA0] enabled


[    1.699803] printk: legacy console [ttyAMA0] enabled


[    1.765299] HugeTLB: registered 1.00 GiB page size, pre-allocated 0 pages


[    1.765299] HugeTLB: registered 1.00 GiB page size, pre-allocated 0 pages


[    1.818791] HugeTLB: 0 KiB vmemmap can be freed for a 1.00 GiB page


[    1.818791] HugeTLB: 0 KiB vmemmap can be freed for a 1.00 GiB page


[    1.867785] HugeTLB: registered 32.0 MiB page size, pre-allocated 0 pages


[    1.867785] HugeTLB: registered 32.0 MiB page size, pre-allocated 0 pages


[    1.922245] HugeTLB: 0 KiB vmemmap can be freed for a 32.0 MiB page


[    1.922245] HugeTLB: 0 KiB vmemmap can be freed for a 32.0 MiB page


[    1.973172] HugeTLB: registered 2.00 MiB page size, pre-allocated 0 pages


[    1.973172] HugeTLB: registered 2.00 MiB page size, pre-allocated 0 pages


[    2.025024] HugeTLB: 0 KiB vmemmap can be freed for a 2.00 MiB page


[    2.025024] HugeTLB: 0 KiB vmemmap can be freed for a 2.00 MiB page


[    2.075281] HugeTLB: registered 64.0 KiB page size, pre-allocated 0 pages


[    2.075281] HugeTLB: registered 64.0 KiB page size, pre-allocated 0 pages


[    2.128192] HugeTLB: 0 KiB vmemmap can be freed for a 64.0 KiB page


[    2.128192] HugeTLB: 0 KiB vmemmap can be freed for a 64.0 KiB page


[    2.195657] ACPI: Interpreter disabled.


[    2.195657] ACPI: Interpreter disabled.


[    2.235185] iommu: Default domain type: Translated


[    2.235185] iommu: Default domain type: Translated


[    2.277212] iommu: DMA domain TLB invalidation policy: strict mode


[    2.277212] iommu: DMA domain TLB invalidation policy: strict mode


[    2.331335] SCSI subsystem initialized


[    2.331335] SCSI subsystem initialized


[    2.367216] libata version 3.00 loaded.


[    2.367216] libata version 3.00 loaded.


[    2.399281] usbcore: registered new interface driver usbfs


[    2.399281] usbcore: registered new interface driver usbfs


[    2.442379] usbcore: registered new interface driver hub


[    2.442379] usbcore: registered new interface driver hub


[    2.484084] usbcore: registered new device driver usb


[    2.484084] usbcore: registered new device driver usb


[    2.525724] pps_core: LinuxPPS API ver. 1 registered


[    2.525724] pps_core: LinuxPPS API ver. 1 registered


[    2.564472] pps_core: Software ver. 5.3.6 - Copyright 2005-2007 Rodolfo Giometti <giometti@linux.it>


[    2.564472] pps_core: Software ver. 5.3.6 - Copyright 2005-2007 Rodolfo Giometti <giometti@linux.it>


[    2.635492] PTP clock support registered


[    2.635492] PTP clock support registered


[    2.667411] EDAC MC: Ver: 3.0.0


[    2.667411] EDAC MC: Ver: 3.0.0


[    2.697306] scmi_core: SCMI protocol bus registered


[    2.697306] scmi_core: SCMI protocol bus registered


[    2.743270] FPGA manager framework


[    2.743270] FPGA manager framework


[    2.772000] Advanced Linux Sound Architecture Driver Initialized.


[    2.772000] Advanced Linux Sound Architecture Driver Initialized.


[    2.833338] vgaarb: loaded


[    2.833338] vgaarb: loaded


[    2.861047] clocksource: Switched to clocksource arch_sys_counter


[    2.861047] clocksource: Switched to clocksource arch_sys_counter


[    2.918425] VFS: Disk quotas dquot_6.6.0


[    2.918425] VFS: Disk quotas dquot_6.6.0


[    2.951254] VFS: Dquot-cache hash table entries: 512 (order 0, 4096 bytes)


[    2.951254] VFS: Dquot-cache hash table entries: 512 (order 0, 4096 bytes)


[    3.006929] pnp: PnP ACPI: disabled


[    3.006929] pnp: PnP ACPI: disabled


[    3.175259] NET: Registered PF_INET protocol family


[    3.175259] NET: Registered PF_INET protocol family


[    3.217866] IP idents hash table entries: 8192 (order: 4, 65536 bytes, linear)


[    3.217866] IP idents hash table entries: 8192 (order: 4, 65536 bytes, linear)


[    3.285386] tcp_listen_portaddr_hash hash table entries: 256 (order: 0, 4096 bytes, linear)


[    3.285386] tcp_listen_portaddr_hash hash table entries: 256 (order: 0, 4096 bytes, linear)


[    3.355743] Table-perturb hash table entries: 65536 (order: 6, 262144 bytes, linear)


[    3.355743] Table-perturb hash table entries: 65536 (order: 6, 262144 bytes, linear)


[    3.420129] TCP established hash table entries: 4096 (order: 3, 32768 bytes, linear)


[    3.420129] TCP established hash table entries: 4096 (order: 3, 32768 bytes, linear)


[    3.481237] TCP bind hash table entries: 4096 (order: 5, 131072 bytes, linear)


[    3.481237] TCP bind hash table entries: 4096 (order: 5, 131072 bytes, linear)


[    3.537998] TCP: Hash tables configured (established 4096 bind 4096)


[    3.537998] TCP: Hash tables configured (established 4096 bind 4096)


[    3.590580] UDP hash table entries: 256 (order: 1, 8192 bytes, linear)


[    3.590580] UDP hash table entries: 256 (order: 1, 8192 bytes, linear)


[    3.642579] UDP-Lite hash table entries: 256 (order: 1, 8192 bytes, linear)


[    3.642579] UDP-Lite hash table entries: 256 (order: 1, 8192 bytes, linear)


[    3.699012] NET: Registered PF_UNIX/PF_LOCAL protocol family


[    3.699012] NET: Registered PF_UNIX/PF_LOCAL protocol family


[    3.750435] RPC: Registered named UNIX socket transport module.


[    3.750435] RPC: Registered named UNIX socket transport module.


[    3.798589] RPC: Registered udp transport module.


[    3.798589] RPC: Registered udp transport module.


[    3.842763] RPC: Registered tcp transport module.


[    3.842763] RPC: Registered tcp transport module.


[    3.885108] RPC: Registered tcp-with-tls transport module.


[    3.885108] RPC: Registered tcp-with-tls transport module.


[    3.933591] RPC: Registered tcp NFSv4.1 backchannel transport module.


[    3.933591] RPC: Registered tcp NFSv4.1 backchannel transport module.


[    3.986320] PCI: CLS 0 bytes, default 64


[    3.986320] PCI: CLS 0 bytes, default 64


[    4.024063] Unpacking initramfs...


[    4.024063] Unpacking initramfs...


[    4.053559] kvm [1]: HYP mode not available


[    4.053559] kvm [1]: HYP mode not available


[    4.097732] Initialise system trusted keyrings


[    4.097732] Initialise system trusted keyrings


[    4.139972] workingset: timestamp_bits=42 max_order=17 bucket_order=0


[    4.139972] workingset: timestamp_bits=42 max_order=17 bucket_order=0


[    4.195202] squashfs: version 4.0 (2009/01/31) Phillip Lougher


[    4.195202] squashfs: version 4.0 (2009/01/31) Phillip Lougher


[    4.249902] NFS: Registering the id_resolver key type


[    4.249902] NFS: Registering the id_resolver key type


[    4.291043] Key type id_resolver registered


[    4.291043] Key type id_resolver registered


[    4.324254] Key type id_legacy registered


[    4.324254] Key type id_legacy registered


[    4.357502] nfs4filelayout_init: NFSv4 File Layout Driver Registering...


[    4.357502] nfs4filelayout_init: NFSv4 File Layout Driver Registering...


[    4.411853] nfs4flexfilelayout_init: NFSv4 Flexfile Layout Driver Registering...


[    4.411853] nfs4flexfilelayout_init: NFSv4 Flexfile Layout Driver Registering...


[    4.472089] 9p: Installing v9fs 9p2000 file system support


[    4.472089] 9p: Installing v9fs 9p2000 file system support


[    4.563521] Key type asymmetric registered


[    4.563521] Key type asymmetric registered


[    4.602290] Asymmetric key parser 'x509' registered


[    4.602290] Asymmetric key parser 'x509' registered


[    4.646534] Block layer SCSI generic (bsg) driver version 0.4 loaded (major 245)


[    4.646534] Block layer SCSI generic (bsg) driver version 0.4 loaded (major 245)


[    4.707582] io scheduler mq-deadline registered


[    4.707582] io scheduler mq-deadline registered


[    4.743420] io scheduler kyber registered


[    4.743420] io scheduler kyber registered


[    4.776318] io scheduler bfq registered


[    4.776318] io scheduler bfq registered


[    4.831315] ledtrig-cpu: registered to indicate activity on CPUs


[    4.831315] ledtrig-cpu: registered to indicate activity on CPUs


[    5.006316] Serial: 8250/16550 driver, 4 ports, IRQ sharing enabled


[    5.006316] Serial: 8250/16550 driver, 4 ports, IRQ sharing enabled


[    5.071550] msm_serial: driver initialized


[    5.071550] msm_serial: driver initialized


[    5.107855] SuperH (H)SCI(F) driver initialized


[    5.107855] SuperH (H)SCI(F) driver initialized


[    5.147214] STM32 USART driver initialized


[    5.147214] STM32 USART driver initialized


[    5.237773] loop: module loaded


[    5.237773] loop: module loaded


[    5.268224] megasas: 07.727.03.00-rc1


[    5.268224] megasas: 07.727.03.00-rc1


[    5.313991] tun: Universal TUN/TAP device driver, 1.6


[    5.313991] tun: Universal TUN/TAP device driver, 1.6


[    5.359058] thunder_xcv, ver 1.0


[    5.359058] thunder_xcv, ver 1.0


[    5.386901] thunder_bgx, ver 1.0


[    5.386901] thunder_bgx, ver 1.0


[    5.413999] nicpf, ver 1.0


[    5.413999] nicpf, ver 1.0


[    5.439484] hns3: Hisilicon Ethernet Network Driver for Hip08 Family - version


[    5.439484] hns3: Hisilicon Ethernet Network Driver for Hip08 Family - version


[    5.498207] hns3: Copyright (c) 2017 Huawei Corporation.


[    5.498207] hns3: Copyright (c) 2017 Huawei Corporation.


[    5.542225] hclge is initializing


[    5.542225] hclge is initializing


[    5.569277] e1000: Intel(R) PRO/1000 Network Driver


[    5.569277] e1000: Intel(R) PRO/1000 Network Driver


[    5.607930] e1000: Copyright (c) 1999-2006 Intel Corporation.


[    5.607930] e1000: Copyright (c) 1999-2006 Intel Corporation.


[    5.653829] e1000e: Intel(R) PRO/1000 Network Driver


[    5.653829] e1000e: Intel(R) PRO/1000 Network Driver


[    5.693447] e1000e: Copyright(c) 1999 - 2015 Intel Corporation.


[    5.693447] e1000e: Copyright(c) 1999 - 2015 Intel Corporation.


[    5.741214] igb: Intel(R) Gigabit Ethernet Network Driver


[    5.741214] igb: Intel(R) Gigabit Ethernet Network Driver


[    5.783677] igb: Copyright (c) 2007-2014 Intel Corporation.


[    5.783677] igb: Copyright (c) 2007-2014 Intel Corporation.


[    5.827640] igbvf: Intel(R) Gigabit Virtual Function Network Driver


[    5.827640] igbvf: Intel(R) Gigabit Virtual Function Network Driver


[    5.877052] igbvf: Copyright (c) 2009 - 2012 Intel Corporation.


[    5.877052] igbvf: Copyright (c) 2009 - 2012 Intel Corporation.


[    5.926302] sky2: driver version 1.30


[    5.926302] sky2: driver version 1.30


[    5.963008] VFIO - User Level meta-driver version: 0.3


[    5.963008] VFIO - User Level meta-driver version: 0.3


[    6.015856] usbcore: registered new interface driver usb-storage


[    6.015856] usbcore: registered new interface driver usb-storage


[    6.072042] i2c_dev: i2c /dev entries driver


[    6.072042] i2c_dev: i2c /dev entries driver


[    6.122477] sdhci: Secure Digital Host Controller Interface driver


[    6.122477] sdhci: Secure Digital Host Controller Interface driver


[    6.173348] sdhci: Copyright(c) Pierre Ossman


[    6.173348] sdhci: Copyright(c) Pierre Ossman


[    6.214079] Synopsys Designware Multimedia Card Interface Driver


[    6.214079] Synopsys Designware Multimedia Card Interface Driver


[    6.266017] sdhci-pltfm: SDHCI platform and OF driver helper


[    6.266017] sdhci-pltfm: SDHCI platform and OF driver helper


[    6.320233] usbcore: registered new interface driver usbhid


[    6.320233] usbcore: registered new interface driver usbhid


[    6.365322] usbhid: USB HID core driver


[    6.365322] usbhid: USB HID core driver


[    6.408361] hw perfevents: enabled with armv8_pmuv3 PMU driver, 7 (0,8000003f) counters available


[    6.408361] hw perfevents: enabled with armv8_pmuv3 PMU driver, 7 (0,8000003f) counters available


[    6.494263] NET: Registered PF_PACKET protocol family


[    6.494263] NET: Registered PF_PACKET protocol family


[    6.538093] 9pnet: Installing 9P2000 support


[    6.538093] 9pnet: Installing 9P2000 support


[    6.573306] Key type dns_resolver registered


[    6.573306] Key type dns_resolver registered


[    6.632343] registered taskstats version 1


[    6.632343] registered taskstats version 1


[    6.670215] Loading compiled-in X.509 certificates


[    6.670215] Loading compiled-in X.509 certificates


[    6.729185] Demotion targets for Node 0: null


[    6.729185] Demotion targets for Node 0: null


[    6.774983] clk: Disabling unused clocks


[    6.774983] clk: Disabling unused clocks


[    6.809111] PM: genpd: Disabling unused power domains


[    6.809111] PM: genpd: Disabling unused power domains


[    6.851481] ALSA device list:


[    6.851481] ALSA device list:


[    6.876351]   No soundcards found.


[    6.876351]   No soundcards found.


[    6.982228] Freeing unused kernel memory: 2880K


[    6.982228] Freeing unused kernel memory: 2880K


[    7.019407] Run /init as init process


[    7.019407] Run /init as init process


[    7.049104]   with arguments:


[    7.049104]   with arguments:


[    7.072968]     /init


[    7.072968]     /init


[    7.092119]   with environment:


[    7.092119]   with environment:


[    7.117583]     HOME=/


[    7.117583]     HOME=/


[    7.138918]     TERM=linux


[    7.138918]     TERM=linux


[    7.199074] 


[    7.199074] === LATCH Linux 6.12 Guest Userspace (/init) Alive ===


[    7.199074] 


[    7.199074] 


[    7.199074] === LATCH Linux 6.12 Guest Userspace (/init) Alive ===


[    7.199074] 


[    7.270396] [guest] PID 1 = this binary. The in-guest policy IS /init.


[    7.270396] 


[    7.270396] [guest] PID 1 = this binary. The in-guest policy IS /init.


[    7.270396] 


[    7.335556] [guest] /dev/hvc0 opened! Configuring raw mode for GOVERNOR wire v2...


[    7.335556] 


[    7.335556] [guest] /dev/hvc0 opened! Configuring raw mode for GOVERNOR wire v2...


[    7.335556] 


[    7.411086] [LATENCY] soak: 900 Hz in-envelope CMD_V2 stream for 2100000 ms


[    7.411086] 


[    7.411086] [LATENCY] soak: 900 Hz in-envelope CMD_V2 stream for 2100000 ms


[    7.411086] 


[    7.477659] [LATENCY] the plant is walked to 100 mrad on a 5 mrad staircase, then holds


[    7.477659] 


[    7.477659] [LATENCY] the plant is walked to 100 mrad on a 5 mrad staircase, then holds


[    7.477659] 


[    7.556482] [LATENCY] the console stays quiet until the soak ends


[    7.556482] 


[    7.556482] [LATENCY] the console stays quiet until the soak ends


[    7.556482] 


LATCOC3_0

#

--- THE SOAK'S RATES, AS THE TARGET REPORTED THEM ---
supervisor ticks/s  : 998.5
guest proposals/s   : 891.5
proposals per tick  : 0.893
peak backlog        : 72 frames (ring depth 256)
wall-clock seconds  : 2110.2

--- THE SUPERVISOR'S STATUS, SAMPLED DURING THE SOAK ---
tick         proposals    rung         drops      backlog    overruns   decision_lat theta    vel      alive 
21780        8951         HP           0          57         4          492          100      0        yes   
41856        27096        HP           0          72         6          104          100      0        yes   
61917        45184        HP           0          72         6          143          100      0        yes   
81999        63264        HP           0          72         8          215          100      0        yes   
102072       81340        HP           0          72         11         830          100      0        yes   
122138       99425        HP           0          72         17         793          100      0        yes   
142170       117508       HP           0          72         19         169          100      0        yes   
162254       135591       HP           0          72         22         419          100      0        yes   
182322       153673       HP           0          72         24         427          100      0        yes   
202408       171752       HP           0          72         26         443          100      0        yes   
222489       189836       HP           0          72         26         147          100      0        yes   
242513       207912       HP           0          72         32         125          100      0        yes   
262598       225992       HP           0          72         33         84           100      0        yes   
282682       244076       HP           0          72         35         85           100      0        yes   
302742       262161       HP           0          72         38         675          100      0        yes   
322828       280244       HP           0          72         41         156          100      0        yes   
342914       298324       HP           0          72         42         127          100      0        yes   
362989       316408       HP           0          72         46         148          100      0        yes   
382933       334508       HP           0          72         49         156          100      0        yes   
402882       352592       HP           0          72         59         367          100      0        yes   
422961       370684       HP           0          72         64         115          100      0        yes   
443048       388779       HP           0          72         65         608          100      0        yes   
463139       406872       HP           0          72         70         157          100      0        yes   
483196       424949       HP           0          72         71         609          100      0        yes   
503265       443036       HP           0          72         71         144          100      0        yes   
523332       461112       HP           0          72         74         169          100      0        yes   
543404       479197       HP           0          72         76         461          100      0        yes   
563494       497277       HP           0          72         77         1054         100      0        yes   
583604       515380       HP           0          72         78         403          100      0        yes   
603683       533476       HP           0          72         81         371          100      0        yes   
623664       551552       HP           0          72         82         176          100      0        yes   
643737       569636       HP           0          72         83         219          100      0        yes   
663837       587732       HP           0          72         83         243          100      0        yes   
683909       605840       HP           0          72         86         276          100      0        yes   
704006       623940       HP           0          72         88         116          100      0        yes   
724088       642020       HP           0          72         90         162          100      0        yes   
744172       660104       HP           0          72         91         250          100      0        yes   
764239       678188       HP           0          72         93         543          100      0        yes   
784298       696265       HP           0          72         95         1325         100      0        yes   
804377       714353       HP           0          72         96         538          100      0        yes   
824468       732444       HP           0          72         98         220          100      0        yes   
844542       750531       HP           0          72         100        402          100      0        yes   
864570       768613       HP           0          72         103        341          100      0        yes   
884639       786688       HP           0          72         104        100          100      0        yes   
904718       804772       HP           0          72         106        107          100      0        yes   
924781       822852       HP           0          72         108        170          100      0        yes   
944813       840932       HP           0          72         113        148          100      0        yes   
964876       859024       HP           0          72         115        632          100      0        yes   
984983       877112       HP           0          72         115        164          100      0        yes   
1005038      895200       HP           0          72         118        169          100      0        yes   
1025096      913277       HP           0          72         119        939          100      0        yes   
1045172      931360       HP           0          72         119        80           100      0        yes   
1065257      949444       HP           0          72         120        479          100      0        yes   
1085331      967521       HP           0          72         121        908          100      0        yes   
1105358      985608       HP           0          72         123        114          100      0        yes   
1125455      1003711      HP           0          72         126        523          100      0        yes   
1145547      1021804      HP           0          72         130        195          100      0        yes   
1165632      1039888      HP           0          72         131        437          100      0        yes   
1185722      1057968      HP           0          72         131        168          100      0        yes   
1205801      1076055      HP           0          72         133        447          100      0        yes   
1225862      1094132      HP           0          72         135        358          100      0        yes   
1245910      1112219      HP           0          72         138        818          100      0        yes   
1265931      1130300      HP           0          72         142        418          100      0        yes   
1286001      1148376      HP           0          72         143        189          100      0        yes   
1306064      1166465      HP           0          72         144        521          100      0        yes   
1326125      1184541      HP           0          72         145        440          100      0        yes   
1346138      1202625      HP           0          72         147        510          100      0        yes   
1366212      1220704      HP           0          72         147        370          100      0        yes   
1386290      1238788      HP           0          72         149        450          100      0        yes   
1406355      1256865      HP           0          72         149        975          100      0        yes   
1426441      1274951      HP           0          72         149        401          100      0        yes   
1446525      1293035      HP           0          72         149        662          100      0        yes   
1466591      1311112      HP           0          72         149        221          100      0        yes   
1486677      1329197      HP           0          72         151        677          100      0        yes   
1506757      1347276      HP           0          72         151        221          100      0        yes   
1526842      1365360      HP           0          72         151        217          100      0        yes   
1546922      1383440      HP           0          72         152        401          100      0        yes   
1566992      1401520      HP           0          72         153        167          100      0        yes   
1586980      1419602      HP           0          72         157        450          100      0        yes   
1607062      1437684      HP           0          72         158        127          100      0        yes   
1627126      1455767      HP           0          72         158        384          100      0        yes   
1647208      1473849      HP           0          72         160        666          100      0        yes   
1667288      1491925      HP           0          72         161        1520         100      0        yes   
1687365      1510004      HP           0          72         161        114          100      0        yes   
1707457      1528092      HP           0          72         164        167          100      0        yes   
1727518      1546188      HP           0          72         166        134          100      0        yes   
1747593      1564272      HP           0          72         167        180          100      0        yes   
1767665      1582357      HP           0          72         173        2502         100      0        yes   
1787753      1600478      HP           0          72         173        467          100      0        yes   
1807823      1618556      HP           0          72         174        328          100      0        yes   
1827848      1636636      HP           0          72         175        146          100      0        yes   
1847915      1654721      HP           0          72         176        1219         100      0        yes   
1868001      1672824      HP           0          72         180        384          100      0        yes   
1888093      1690917      HP           0          72         183        702          100      0        yes   
1908190      1709016      HP           0          72         186        430          100      0        yes   
1928255      1727096      HP           0          72         187        198          100      0        yes   
1948319      1745180      HP           0          72         188        147          100      0        yes   
1968383      1763256      HP           0          72         189        204          100      0        yes   
1988454      1781348      HP           0          72         190        156          100      0        yes   
2008538      1799440      HP           0          72         191        105          100      0        yes   
2028636      1817544      HP           0          72         191        177          100      0        yes   
2048707      1835627      HP           0          72         194        575          100      0        yes   
2068727      1853708      HP           0          72         195        167          100      0        yes   
2088794      1871788      HP           0          72         196        107          100      0        yes   
2108856      1889872      HP           0          72         197        160          100      0        yes   
2128937      1890224      LATCH        0          72         201        119          0        0        no    

--- THE LATENCY DISTRIBUTION (latchctl latency, verbatim) ---
/proc/boot/latchctl latency; echo LATCOC110_$?


=== LATCH Supervisor Decision-Latency Distribution ===

Samples (ticks)       : 2129049

Decision-path samples : 1890224 (a proposal was dequeued)

Idle-path samples     : 238825 (the proposal queue was empty)

Motion evaluations    : 1890220 (of the decision-path samples)

Cycle rate            : 62500000 Hz

First / last tick     : 1 / 2129049

Min / Max (decision)  : 223 / 261336 cyc (3568 / 4181376 ns)

Mean (decision)       : 542.869 cyc

Min / Max (all ticks) : 20 / 261336 cyc (320 / 4181376 ns)

Mean (all ticks)      : 510.018 cyc

Decision path         : p50 = [160, 192) cyc ([2560, 3072) ns) | p99 = [768, 1024) cyc ([12288, 16384) ns)

Idle path             : p50 = [64, 80) cyc ([1024, 1280) ns) | p99 = [512, 640) cyc ([8192, 10240) ns)

Histogram shape      : decision path 30 non-empty buckets | idle path 69 non-empty buckets (of 112)

Over budget           : 202 samples (over the manifest's timing.wcet_budget_us)

Over tick period      : 8 samples (over the decision period)

Mode ticks            : HP (High Performance)=2109735 HOLD (High Assurance 1)=19305 HOME (High Assurance 2)=9

LATCOC110_0

#

--- THE FINAL SUPERVISOR STATUS ---
/proc/boot/latchctl status; echo LATCOC111_$?


=== LATCH Simplex Supervisor Status ===

Tick Counter         : 2129162 ticks

Current Mode         : HOLD (High Assurance 1)

Actuator Angle       : 0 mrad

Velocity / Omega     : 0 mrad/tick | 0 mrad/s

Last Proposed Angle  : 100 mrad (seq=1890224)

Decision Latency     : last = 793 cyc (12688 ns) | max = 261336 cyc (4181376 ns)

Proposals Received   : 1890224

Wire Faults Caught   : 0

Envelope Vetoes      : 0

Ring Drops / WCET    : 0 drops | 201 overruns

Proposal Backlog     : peak 72 frames | 0 over limit

EPERM Rejections     : 0

Operator Hold Locked : NO

Active Fault Bits    : 0x0000 (NONE)

Latched Fault Bits   : 0x2000 (HEARTBEAT)

Clean Streak         : 0 frames

GOVERNOR             : enabled | rung=LATCH (5)

V2 Session / Lease   : active | 74 ticks left | lease age 19926 ticks

Warm-up / Agent      : 4 heartbeats | state 1

Recovery Clean       : 0 accepted commands

Deadline Misses      : 8 overruns

HOMEOSTAT            : disabled | scale_q8=256 (256=unity) | v_max ceiling=0 | stress epochs=0

Lease Owner          : valid | producer tag 1 | session dead YES

Foreign / Takeovers  : 0 frames | 0 takeovers

Session Epoch        : bound | 0xF9C0B340

Rate / Shrink        : 40 tokens | active=0 v_max=0 scale_q8=255

Coherence            : valid | counter=1890224

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

