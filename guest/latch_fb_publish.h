/*
 * guest/latch_fb_publish.h
 *
 * THE GUEST'S CROSS-CORE PUBLICATION PROTOCOL.
 * ===========================================
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * The guest has TWO vCPUs (`_cpu-2` and `_cpu-3` in
 * `qnx/latch_qemu_governor.qvmconf`), so the verdict watcher and the main
 * thread can be running on DIFFERENT cores at the same time.  AArch64 is
 * WEAKLY ORDERED: a store can become VISIBLE to another core before an
 * EARLIER store of the same program has become visible, and two loads can
 * be reordered with respect to each other.
 *
 * The code this file replaces used a COMPILER barrier:
 *
 *     static inline void fb_barrier(void) {
 *         __asm__ volatile("" ::: "memory");
 *     }
 *
 * That stops the COMPILER from reordering the accesses, and it does
 * NOTHING for the CPU.  The hardware is still free to make the
 * watcher's summary stores visible AFTER the flag store that announces
 * them -- so the main thread can read a HALF-UPDATED summary.  It is
 * still free to make the two sequence-number stores visible in the
 * opposite order -- so the watcher can read `cmd_seq = N` together with
 * `seq_sent = N-1`, which is exactly the "stale verdict" case the guest's
 * own documentation says the order of the fold exists to prevent.
 *
 * A compiler barrier is not a memory barrier, and a guest with two cores
 * needs a memory barrier.
 *
 * THE PROTOCOL
 * ------------
 * Every word that crosses the core boundary is published with the same
 * three steps, and the steps live HERE so that no call site can invent
 * its own:
 *
 *     1. the PAYLOAD is written;
 *     2. a RELEASE fence is executed;
 *     3. the PUBLICATION POINT -- one relaxed atomic store -- is executed.
 *
 * and the reader does the mirror image:
 *
 *     1. the PUBLICATION POINT is read with one relaxed atomic load;
 *     2. an ACQUIRE fence is executed;
 *     3. the PAYLOAD is read.
 *
 * The release fence is BEFORE the store and the acquire fence is AFTER
 * the load, and that order is not cosmetic: it is the fence-based
 * synchronisation pattern of C11 7.17.4.  A release fence placed AFTER
 * the store would order the store against what FOLLOWS it, not against
 * the payload that PRECEDES it, and the payload would still be free to
 * arrive late.
 *
 * The order lives INSIDE these functions for the same reason the
 * operator-hold order lives inside `qnx/latch_hold.h`: a caller cannot
 * choose the wrong order when there is only one way to spell it.
 *
 * WHY THE RELAXED ATOMIC ACCESSORS
 * --------------------------------
 * The fences carry the ORDERING; the accesses carry the ATOMICITY.  A
 * `volatile` access is not an atomic operation in the C11 model, so a
 * fence-based handshake built on `volatile` alone does not form a
 * synchronises-with edge at all -- the fences would be ordering nothing.
 * `__atomic_store_n` / `__atomic_load_n` with `__ATOMIC_RELAXED` are
 * single-copy atomic and cost exactly one `str` / `ldr` on AArch64.
 *
 * WHAT THIS COSTS ON AARCH64
 * --------------------------
 * MEASURED on this tree (2026-11-28):
 *
 *     release fence  ->  dmb ishst   (aarch64-linux-gnu-gcc 16.2.1)
 *                     ->  dmb ish     (clang --target=aarch64-linux-gnu)
 *     acquire fence  ->  dmb ishld   (both)
 *
 * and the relaxed accesses are one `str` / `ldr` each.  The fences are
 * NOT free -- a `dmb ishst` drains the store buffer -- so they are used
 * only where a payload actually crosses the core boundary.
 *
 * THE GATE
 * --------
 * `verify_guest_publish_barrier()` in `tools/consistency_check.py` proves
 * the protocol structurally, and proves at the INSTRUCTION level that
 * the fences are real hardware barriers on AArch64 rather than compiler
 * barriers.
 */
#ifndef LATCH_FB_PUBLISH_H
#define LATCH_FB_PUBLISH_H

#include <stdint.h>

/*
 * Publish a 32-bit word to the other core.
 *
 * The release fence comes FIRST, so everything the caller wrote before
 * this call is visible to a reader that consumes this word.  The store
 * itself is RELAXED: the fence carries the ordering, and a relaxed
 * store is one `str` on AArch64.
 */
static inline void latch_fb_publish_release_store32(volatile uint32_t *word,
                                                    uint32_t value) {
    __atomic_thread_fence(__ATOMIC_RELEASE);
    __atomic_store_n(word, value, __ATOMIC_RELAXED);
}

/*
 * Consume a 32-bit word published by the other core.
 *
 * The acquire fence comes AFTER the load, so everything the publisher
 * wrote before its release fence is visible once this call returns.
 */
static inline uint32_t latch_fb_publish_acquire_load32(
    const volatile uint32_t *word) {
    uint32_t value = __atomic_load_n(word, __ATOMIC_RELAXED);
    __atomic_thread_fence(__ATOMIC_ACQUIRE);
    return value;
}

/* The 64-bit twins, for a word that carries more than 32 bits. */
static inline void latch_fb_publish_release_store64(volatile uint64_t *word,
                                                    uint64_t value) {
    __atomic_thread_fence(__ATOMIC_RELEASE);
    __atomic_store_n(word, value, __ATOMIC_RELAXED);
}

static inline uint64_t latch_fb_publish_acquire_load64(
    const volatile uint64_t *word) {
    uint64_t value = __atomic_load_n(word, __ATOMIC_RELAXED);
    __atomic_thread_fence(__ATOMIC_ACQUIRE);
    return value;
}

/*
 * Publish the SEQUENCE-NUMBER PAIR.
 *
 * The general sequence number is stored FIRST and the command sequence
 * number SECOND, with a release fence BETWEEN them.  The fence is what
 * makes the order real: without it the two stores may become visible to
 * the other core in either order.
 *
 * The reader (`latch_fb_publish_seq_get()`) reads the command sequence
 * number FIRST and the general one SECOND, with an acquire fence
 * BETWEEN them.  Together the two fences buy one property:
 *
 *     IF THE WATCHER SEES `cmd_seq = N`, IT ALSO SEES `seq_sent >= N`.
 *
 * which is the property the guest's own documentation claims for the
 * order of the fold -- and which a compiler barrier did not deliver.
 * The other order could see `cmd_seq = N` together with `seq_sent = N-1`,
 * and the watcher's staleness test (`verdict.seq > last_seq_sent`) would
 * then throw away a verdict that was perfectly good.
 *
 * The release fence is unconditional: it orders the general sequence
 * number against the frame that is about to go on the wire.  The command
 * sequence number is stored only for a MOTION PROPOSAL, because it is
 * what arms the feedback timeout, and it is stored AFTER the fence
 * because it is the publication point the reader synchronises with.
 */
static inline void latch_fb_publish_seq_set(volatile uint32_t *sent,
                                            volatile uint32_t *cmd,
                                            uint32_t seq, int is_cmd) {
    __atomic_store_n(sent, seq, __ATOMIC_RELAXED);
    __atomic_thread_fence(__ATOMIC_RELEASE);
    if (is_cmd) {
        __atomic_store_n(cmd, seq, __ATOMIC_RELAXED);
    }
}

/*
 * Read the SEQUENCE-NUMBER PAIR, in the reader's order: the command
 * sequence number first, the general one second, with the acquire fence
 * between the two loads.
 */
static inline void latch_fb_publish_seq_get(const volatile uint32_t *cmd,
                                            const volatile uint32_t *sent,
                                            uint32_t *cmd_out,
                                            uint32_t *sent_out) {
    uint32_t c = __atomic_load_n(cmd, __ATOMIC_RELAXED);
    __atomic_thread_fence(__ATOMIC_ACQUIRE);
    uint32_t s = __atomic_load_n(sent, __ATOMIC_RELAXED);
    *cmd_out = c;
    *sent_out = s;
}

#endif /* LATCH_FB_PUBLISH_H */
