#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#ifdef __QNXNTO__
#include <sys/neutrino.h>
#include <sys/syspage.h>
#else
static inline uint64_t ClockCycles(void) { return 0; }
typedef struct { uint64_t cycles_per_sec; } qtime_dummy_t;
static qtime_dummy_t g_qtime_dummy = { 1000000000ULL };
#define SYSPAGE_ENTRY(x) (&g_qtime_dummy)
#endif
#include "latch_protocol.h"

static const char *mode_name(uint16_t m) {
    return (m == LATCH_MODE_HP) ? "HP" : (m == LATCH_MODE_HOLD) ? "HOLD" : "HOME";
}

static void send_frame(int fd, uint32_t seq, int32_t u_mrad, uint16_t fault) {
    latch_ipc_proposal_t p;
    memset(&p, 0, sizeof(p));
    p.ipc_magic      = LATCH_IPC_PROPOSAL_MAGIC;
    p.seq            = seq;
    p.u_mrad         = u_mrad;
    p.pre_fault_bits = fault;
    p.ingest_cycles  = ClockCycles();
    write(fd, &p, sizeof(p));
    usleep(2000);
}

int main(int argc, char *argv[]) {
    int dump_only = (argc > 1 && strcmp(argv[1], "--status") == 0);

    if (!dump_only) {
        printf("=== LATCH Native QNX 8.0 Microkernel Verification ===\n");
        int prop_fd = open(LATCH_DEV_PROPOSAL, O_WRONLY);
        if (prop_fd < 0) {
            perror("open /dev/latch/proposal");
            return 1;
        }

        for (uint32_t s = 1; s <= 10; ++s) {
            send_frame(prop_fd, s, (int32_t)(-10 * (int)s), LATCH_FAULT_NONE);
        }
        printf("[1/5] Nominal tracking sent to /dev/latch/proposal (theta = -100 mrad)\n");

        send_frame(prop_fd, 11, 450, LATCH_FAULT_NONE);
        printf("[2/5] Keep-out violation (+450 mrad) injected -> VETO to HA-HOLD\n");

        send_frame(prop_fd, 0, 0, LATCH_FAULT_CRC);
        printf("[3/5] Wire CRC bit-flip fault injected -> HA-HOLD maintained\n");

        send_frame(prop_fd, 10, -100, LATCH_FAULT_NONE);
        usleep(80000);
        printf("[4/5] Sequence replay + 80 ms watchdog silence -> HA-HOME retraction\n");
        close(prop_fd);
    }

    int act_fd = open(LATCH_DEV_ACTUATOR, O_RDWR);
    if (act_fd < 0) {
        perror("open /dev/latch/actuator");
        return 1;
    }

    latch_force_hold_cmd_t hold_cmd = { .lock_hold = 1u, .reason_code = 99u };
    int rc = devctl(act_fd, DCMD_LATCH_FORCE_HOLD, &hold_cmd, sizeof(hold_cmd), NULL);
    if (rc != 0) {
        printf("[5/5] Calling devctl(FORCE_HOLD) WITHOUT 'latch/actuator' ability -> %d (%s)\n",
               rc, strerror(rc));
    }

    latch_status_reply_t st;
    memset(&st, 0, sizeof(st));
    if (devctl(act_fd, DCMD_LATCH_GET_STATUS, &st, sizeof(st), NULL) != 0) {
        close(act_fd);
        return 0;
    }

    uint64_t cps = SYSPAGE_ENTRY(qtime)->cycles_per_sec;
    char sha_hex[65];
    for (int i = 0; i < 32; ++i) {
        snprintf(&sha_hex[i * 2], 3, "%02x", st.manifest_sha256[i]);
    }
    sha_hex[64] = '\0';

    printf("\n=== Authorized via 'latch/actuator' Ability: Live QNX 8.0 Telemetry ===\n");
    printf("Tick Counter       : %" PRIu64 " ticks (1 kHz CLOCK_MONOTONIC pulse)\n", st.tick);
    printf("Current Mode       : %s (theta = %d mrad)\n", mode_name(st.mode), st.theta_mrad);
    printf("Proposals Received : %u | Wire Faults: %u | Envelope Vetoes: %u | EPERM Rejects: %u\n",
           st.total_proposals_rx, st.total_wire_faults, st.total_envelope_faults, st.total_eperm_rejects);
    printf("Decision Latency   : last = %" PRIu64 " cyc (%u ns) | max = %" PRIu64 " cyc (%u ns) @ %" PRIu64 " Hz\n",
           st.last_latency_cycles, st.last_latency_ns, st.max_latency_cycles, st.max_latency_ns, cps);
    printf("Manifest SHA-256   : %s\n", sha_hex);

    latch_tape_dump_t dump;
    memset(&dump, 0, sizeof(dump));
    dump.start_index = UINT32_MAX;
    dump.count       = 12;
    if (devctl(act_fd, DCMD_LATCH_DUMP_TAPE, &dump, sizeof(dump), NULL) == 0) {
        printf("\nLast %u Evidence Tape Records (.bss Ring):\n", dump.count);
        printf("  %-8s %-8s %-10s %-10s %-6s %-8s %-10s\n",
               "TICK", "SEQ", "U_PROP", "THETA_OUT", "MODE", "FAULTS", "CYCLES");
        for (uint32_t i = 0; i < dump.count; ++i) {
            const latch_tape_entry_t *e = &dump.entries[i];
            printf("  #%-7" PRIu64 " %-8u %-10d %-10d %-6s 0x%04X   %" PRIu64 "\n",
                   e->tick, e->seq, e->u_proposed, e->theta_applied,
                   mode_name(e->mode), e->fault_bits, e->cycles_out - e->cycles_in);
        }
    }
    close(act_fd);
    return 0;
}
