/*
 * qnx/latchctl.c
 *
 * LATCH — Last Authority for Trusted Control Handoff (QNX SDP 8.0)
 *
 * Administrative & Verification CLI Utility:
 *   - Interacts with /dev/latch/actuator via devctl().
 *   - Verifies whether caller holds custom "latch/actuator" ability.
 *   - Commands emergency operator HA-HOLD lock.
 *   - Queries live status, nanosecond latency telemetry, and manifest hash.
 *   - Dumps .bss evidence tape to CSV format.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "latch_protocol.h"

static const char *mode_name(uint16_t m) {
    switch (m) {
        case LATCH_MODE_HP:   return "HP (High Performance)";
        case LATCH_MODE_HOLD: return "HOLD (High Assurance 1)";
        case LATCH_MODE_HOME: return "HOME (High Assurance 2)";
        default:              return "UNKNOWN";
    }
}

static void print_usage(const char *prog) {
    fprintf(stderr,
            "Usage: %s [-d /dev/latch/actuator] <command> [args...]\n\n"
            "Commands:\n"
            "  status              Query live Simplex supervisor state & telemetry\n"
            "  grant-check         Verify whether caller holds 'latch/actuator' ability\n"
            "  hold <1|0> [reason] Set (1) or release (0) operator emergency HA-HOLD\n"
            "  dump <output.csv>   Dump evidence tape records to CSV\n",
            prog);
}

static int do_status(int fd) {
    latch_status_reply_t rep;
    memset(&rep, 0, sizeof(rep));

    int rc = devctl(fd, DCMD_LATCH_GET_STATUS, &rep, sizeof(rep), NULL);
    if (rc != EOK) {
        fprintf(stderr, "latchctl: devctl(GET_STATUS) failed: %s (%d)\n", strerror(rc), rc);
        return (rc == EPERM) ? 2 : 1;
    }

    printf("=== LATCH Simplex Supervisor Status ===\n");
    printf("Tick Counter         : %" PRIu64 " ticks\n", rep.tick);
    printf("Current Mode         : %s\n", mode_name(rep.mode));
    printf("Actuator Angle       : %d mrad\n", rep.theta_mrad);
    printf("Velocity / Omega     : %d mrad/tick | %d mrad/s\n",
           rep.velocity_mrad_tick, rep.omega_mrad_s);
    printf("Last Proposed Angle  : %d mrad (seq=%u)\n",
           rep.last_u_proposed_mrad, rep.last_seq);
    printf("Decision Latency     : last = %" PRIu64 " cyc (%u ns) | max = %" PRIu64 " cyc (%u ns)\n",
           rep.last_latency_cycles, rep.last_latency_ns,
           rep.max_latency_cycles, rep.max_latency_ns);
    printf("Proposals Received   : %u\n", rep.total_proposals_rx);
    printf("Wire Faults Caught   : %u\n", rep.total_wire_faults);
    printf("Envelope Vetoes      : %u\n", rep.total_envelope_faults);
    printf("EPERM Rejections     : %u\n", rep.total_eperm_rejects);
    printf("Operator Hold Locked : %s\n", rep.operator_hold_locked ? "YES" : "NO");
    printf("Active Fault Bits    : 0x%04X\n", rep.active_faults);
    printf("Latched Fault Bits   : 0x%04X\n", rep.latched_faults);
    printf("Clean Streak         : %u frames\n", rep.clean_streak);

    char sha_hex[65];
    for (int i = 0; i < 32; ++i) {
        snprintf(&sha_hex[i * 2], 3, "%02x", rep.manifest_sha256[i]);
    }
    sha_hex[64] = '\0';
    printf("Manifest SHA-256     : %s\n", sha_hex);

    return 0;
}

static int do_grant_check(int fd) {
    latch_force_hold_cmd_t cmd = { .lock_hold = 0u, .reason_code = 0u };

    int rc = devctl(fd, DCMD_LATCH_FORCE_HOLD, &cmd, sizeof(cmd), NULL);
    if (rc == EOK) {
        printf("[AUTH] SUCCESS: Process holds 'latch/actuator' ability. Actuator access granted.\n");
        return 0;
    }
    if (rc == EPERM) {
        printf("[AUTH] DENIED: Process lacks 'latch/actuator' ability (EPERM). Fail-closed.\n");
        return 2;
    }
    fprintf(stderr, "[AUTH] ERROR: Unexpected devctl failure: %s (%d)\n", strerror(rc), rc);
    return 1;
}

static int do_hold(int fd, int argc, char *argv[]) {
    if (argc < 1) {
        fprintf(stderr, "Usage: latchctl hold <1|0> [reason_code]\n");
        return 1;
    }

    uint32_t lock_val = (uint32_t)strtoul(argv[0], NULL, 10);
    uint32_t reason   = (argc >= 2) ? (uint32_t)strtoul(argv[1], NULL, 10) : 1u;

    latch_force_hold_cmd_t cmd = {
        .lock_hold   = lock_val ? 1u : 0u,
        .reason_code = reason
    };

    int rc = devctl(fd, DCMD_LATCH_FORCE_HOLD, &cmd, sizeof(cmd), NULL);
    if (rc != EOK) {
        fprintf(stderr, "latchctl: devctl(FORCE_HOLD) failed: %s (%d)\n", strerror(rc), rc);
        return (rc == EPERM) ? 2 : 1;
    }

    printf("latchctl: Operator HA-HOLD %s (reason=%u)\n",
           lock_val ? "LOCKED" : "RELEASED", reason);
    return 0;
}

static int do_dump(int fd, const char *out_csv) {
    latch_tape_dump_t dump;
    memset(&dump, 0, sizeof(dump));
    dump.start_index = UINT32_MAX;
    dump.count       = LATCH_DUMP_MAX_ENTRIES;

    int rc = devctl(fd, DCMD_LATCH_DUMP_TAPE, &dump, sizeof(dump), NULL);
    if (rc != EOK) {
        fprintf(stderr, "latchctl: devctl(DUMP_TAPE) failed: %s (%d)\n", strerror(rc), rc);
        return (rc == EPERM) ? 2 : 1;
    }

    FILE *fp = stdout;
    if (out_csv != NULL && strcmp(out_csv, "-") != 0) {
        fp = fopen(out_csv, "w");
        if (!fp) {
            fprintf(stderr, "latchctl: Cannot open output '%s': %s\n", out_csv, strerror(errno));
            return 1;
        }
    }

    fprintf(fp, "# LATCH Evidence Tape Dump | Records: %u | Latest Tick: %" PRIu64 "\n",
            dump.count, dump.latest_tick);
    fprintf(fp, "tick,cycles_in,cycles_out,latency_cycles,seq,u_proposed,theta_applied,mode,fault_bits\n");

    for (uint32_t i = 0; i < dump.count; ++i) {
        const latch_tape_entry_t *e = &dump.entries[i];
        uint64_t lat = (e->cycles_out >= e->cycles_in) ? (e->cycles_out - e->cycles_in) : 0;
        fprintf(fp, "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%u,%d,%d,%u,0x%04X\n",
                e->tick, e->cycles_in, e->cycles_out, lat,
                e->seq, e->u_proposed, e->theta_applied,
                (unsigned int)e->mode, (unsigned int)e->fault_bits);
    }

    if (fp != stdout) {
        fclose(fp);
        printf("latchctl: Exported %u tape records to '%s'\n", dump.count, out_csv);
    }
    return 0;
}

int main(int argc, char *argv[]) {
    const char *dev_path = LATCH_DEV_ACTUATOR;
    int opt;

    while ((opt = getopt(argc, argv, "d:")) != -1) {
        switch (opt) {
            case 'd':
                dev_path = optarg;
                break;
            default:
                print_usage(argv[0]);
                return EXIT_FAILURE;
        }
    }

    if (optind >= argc) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    const char *cmd = argv[optind++];

    int fd = open(dev_path, O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "latchctl: Cannot open '%s': %s\n", dev_path, strerror(errno));
        return (errno == EACCES || errno == EPERM) ? 2 : 1;
    }

    int ret = 0;
    if (strcmp(cmd, "status") == 0) {
        ret = do_status(fd);
    } else if (strcmp(cmd, "grant-check") == 0) {
        ret = do_grant_check(fd);
    } else if (strcmp(cmd, "hold") == 0) {
        ret = do_hold(fd, argc - optind, &argv[optind]);
    } else if (strcmp(cmd, "dump") == 0) {
        const char *csv_file = (optind < argc) ? argv[optind] : "-";
        ret = do_dump(fd, csv_file);
    } else {
        fprintf(stderr, "latchctl: Unknown command '%s'\n", cmd);
        print_usage(argv[0]);
        ret = 1;
    }

    close(fd);
    return ret;
}
