/*
 * THE HOST-SIDE FEEDBACK PUBLISHER  (W5)
 * ======================================
 *
 * The full contract is in latch_feedback_pub.h.  This file is the
 * implementation, and the comments below are about the properties that
 * are easy to break by accident:
 *
 *   1. THE CALLER NEVER BLOCKS ON I/O.  The publish path is a memcpy and
 *      a condvar signal; the write to the resource manager is on a
 *      dedicated thread.
 *
 *   2. THE WRITER THREAD RUNS BELOW THE SAFETY CORE.  The supervisor's
 *      tick is SCHED_FIFO 63; the actuator I/O worker is 20; this thread
 *      is 40 -- above the actuator worker (so an advisory verdict is not
 *      stuck behind a physical write) and well below the safety core (so
 *      a wedged feedback sink can never delay a decision).
 *
 *   3. THE SLOT IS ONE VERDICT DEEP AND THE OVERWRITE IS COUNTED.  See
 *      the header.
 *
 *   4. A FAILED PUBLISH IS NOT SILENT.  Every failure path increments a
 *      counter that the caller can read back.
 *
 *   5. THE PRIMITIVES LIVE FOR THE PROCESS LIFETIME.  The mutex and the
 *      condvar are STATIC objects with static storage duration; they are
 *      initialised EXACTLY ONCE and they are NEVER destroyed.  See the
 *      block above `g_pub` for why.
 */

#include "latch_feedback_pub.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* The writer thread's scheduling priority.  See (2) above. */
#define FB_PUB_THREAD_PRIO 40

/* How long the writer thread waits for a new frame before it looks around
 * again.  A timed wait is what lets the thread notice a stop request
 * without a spurious wake-up. */
#define FB_PUB_WAIT_MS 50

/* How many times a write that returned EAGAIN is retried before the frame
 * is dropped.  The sink's publisher node is O_NONBLOCK and the sink writes
 * the verdict file BEFORE it mirrors the frame into its own mailbox, so a
 * sustained EAGAIN should not happen -- but a bounded retry turns a
 * transient refusal into a delivery instead of a loss. */
#define FB_PUB_MAX_RETRIES 50

/* The pause between two retries. */
#define FB_PUB_RETRY_MS 20

typedef struct {
    pthread_mutex_t   lock;
    pthread_cond_t    cond;
    pthread_t         tid;
    int               thread_valid;
    int               running;
    int               fd;
    char              path[256];
    latch_feedback_t  slot;
    int               pending;
    latch_feedback_pub_status_t status;
} fb_pub_t;

static fb_pub_t g_pub;

/*
 * THE PRIMITIVES LIVE FOR THE PROCESS LIFETIME.
 * ===========================================
 *
 * `g_pub.lock` and `g_pub.cond` are STATIC objects with static storage
 * duration, and they are used by EVERY public entry point -- including
 * the ones that run before the publisher was started and the ones that
 * run after it was stopped.  So they have to be in a defined state at
 * EVERY point in the process's life, which means:
 *
 *   - they are initialised EXACTLY ONCE, by `pthread_once`, and
 *   - they are NEVER destroyed.
 *
 * WHY NEVER DESTROYED
 * -------------------
 * `pthread_mutex_destroy()` / `pthread_cond_destroy()` are not "stop
 * using this".  POSIX leaves the behaviour UNDEFINED after a destroy:
 * a destroyed mutex may be LOCKED again, and a destroyed condvar may be
 * WAITED on or SIGNalled again.  Every one of those happens here:
 *
 *   - `latch_feedback_pub_publish()` after a stop takes the lock to
 *     discover that the publisher is not running (and refuses the
 *     frame);
 *   - `latch_feedback_pub_get_status()` after a stop takes the lock to
 *     hand the operator a final snapshot;
 *   - `latch_feedback_pub_start()` after a stop RE-USES the very same
 *     mutex and condvar for the new writer thread.
 *
 * So the old `stop()` -- which destroyed both -- made every one of
 * those a use of a destroyed object.  On glibc the destroy of a normal
 * mutex is very nearly a no-op, so the defect is INVISIBLE on the host;
 * it is still undefined behaviour, and "it happens to work on the
 * library we test with" is not a safety argument.
 *
 * AND WHY INITIALISED EXACTLY ONCE
 * --------------------------------
 * The same reasoning applies to the INITIALISATION.  `start()` used to
 * call `pthread_mutex_init()` every time it ran, so a restart
 * re-initialised an already-initialised mutex -- undefined behaviour
 * again -- and a `publish()` that arrived BEFORE the first `start()`
 * locked a mutex that had never been initialised at all.
 *
 * `pthread_once` is the canonical POSIX answer to both: the
 * initialiser runs exactly once, on the first call, and every later
 * call is a single atomic load.  The primitives are then in a defined
 * state for the whole life of the process, and `stop()` only has to do
 * what it says: stop the writer thread and join it.
 */
static pthread_once_t g_pub_prim_once = PTHREAD_ONCE_INIT;
static int            g_pub_prim_ready;

static void fb_pub_init_primitives(void)
{
    (void)pthread_mutex_init(&g_pub.lock, NULL);
    (void)pthread_cond_init(&g_pub.cond, NULL);
}

/* Make sure the primitives exist.  Cheap after the first call: the flag
 * is a plain int and the branch is perfectly predicted, so the safety
 * core's publish path pays one predictable load and nothing else. */
static void fb_pub_primitives_ready(void)
{
    if (!g_pub_prim_ready) {
        (void)pthread_once(&g_pub_prim_once, fb_pub_init_primitives);
        g_pub_prim_ready = 1;
    }
}

/* A short sleep that does not need the alarm machinery. */
static void fb_pub_sleep_ms(long ms)
{
    struct timespec ts;
    ts.tv_sec  = ms / 1000L;
    ts.tv_nsec = (ms % 1000L) * 1000000L;
    (void)nanosleep(&ts, NULL);
}

static void fb_pub_count_locked(uint64_t *counter)
{
    *counter += 1u;
}

/*
 * Open the publisher node.
 *
 * O_WRONLY: the node is write-only, and the resource manager refuses a
 * read access on it.  O_NONBLOCK: a publisher must never be able to stall
 * the safety core, even by accident.
 */
static int fb_pub_open_node(void)
{
    int fd = open(g_pub.path, O_WRONLY | O_NOCTTY | O_NONBLOCK);
    if (fd < 0) {
        return -1;
    }
    pthread_mutex_lock(&g_pub.lock);
    if (g_pub.status.opens > 0u) {
        fb_pub_count_locked(&g_pub.status.reconnects);
    }
    fb_pub_count_locked(&g_pub.status.opens);
    pthread_mutex_unlock(&g_pub.lock);
    return fd;
}

/*
 * The writer thread.
 *
 * It owns the descriptor.  Everything else -- the slot, the counters -- is
 * shared with the caller and protected by the lock.
 */
static void *fb_pub_writer(void *arg)
{
    (void)arg;

    struct sched_param sp;
    memset(&sp, 0, sizeof(sp));
    sp.sched_priority = FB_PUB_THREAD_PRIO;
    (void)pthread_setschedparam(pthread_self(), SCHED_FIFO, &sp);

    int fd = -1;

    for (;;) {
        latch_feedback_t frame;
        int have_frame = 0;

        pthread_mutex_lock(&g_pub.lock);
        while (g_pub.running && !g_pub.pending) {
            struct timespec deadline;
            (void)clock_gettime(CLOCK_REALTIME, &deadline);
            deadline.tv_sec  += FB_PUB_WAIT_MS / 1000L;
            deadline.tv_nsec += (FB_PUB_WAIT_MS % 1000L) * 1000000L;
            if (deadline.tv_nsec >= 1000000000L) {
                deadline.tv_sec  += 1L;
                deadline.tv_nsec -= 1000000000L;
            }
            (void)pthread_cond_timedwait(&g_pub.cond, &g_pub.lock, &deadline);
        }
        if (!g_pub.running && !g_pub.pending) {
            pthread_mutex_unlock(&g_pub.lock);
            break;
        }
        frame      = g_pub.slot;
        g_pub.pending = 0;
        have_frame = 1;
        pthread_mutex_unlock(&g_pub.lock);

        if (!have_frame) {
            continue;
        }

        /* Make sure there is a descriptor.  The node may not exist yet (the
         * resource manager may still be starting), so this is a RETRY, not
         * an error: the frame is lost, and the loss is counted. */
        if (fd < 0) {
            fd = fb_pub_open_node();
            if (fd < 0) {
                pthread_mutex_lock(&g_pub.lock);
                fb_pub_count_locked(&g_pub.status.errors);
                fb_pub_count_locked(&g_pub.status.dropped);
                pthread_mutex_unlock(&g_pub.lock);
                fb_pub_sleep_ms(FB_PUB_RETRY_MS);
                continue;
            }
        }

        /* The write itself.  A short frame is a protocol violation on the
         * node's side and is treated as an error. */
        int retries = 0;
        for (;;) {
            ssize_t w = write(fd, &frame, sizeof(frame));
            if (w == (ssize_t)sizeof(frame)) {
                pthread_mutex_lock(&g_pub.lock);
                fb_pub_count_locked(&g_pub.status.written);
                pthread_mutex_unlock(&g_pub.lock);
                break;
            }
            if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                pthread_mutex_lock(&g_pub.lock);
                fb_pub_count_locked(&g_pub.status.retries);
                pthread_mutex_unlock(&g_pub.lock);
                if (retries >= FB_PUB_MAX_RETRIES) {
                    pthread_mutex_lock(&g_pub.lock);
                    fb_pub_count_locked(&g_pub.status.dropped);
                    pthread_mutex_unlock(&g_pub.lock);
                    break;
                }
                retries++;
                fb_pub_sleep_ms(FB_PUB_RETRY_MS);
                continue;
            }
            /* Anything else: the descriptor is suspect.  Count the error,
             * drop the frame and reopen the node on the next round. */
            pthread_mutex_lock(&g_pub.lock);
            fb_pub_count_locked(&g_pub.status.errors);
            fb_pub_count_locked(&g_pub.status.dropped);
            pthread_mutex_unlock(&g_pub.lock);
            (void)close(fd);
            fd = -1;
            break;
        }
    }

    if (fd >= 0) {
        (void)close(fd);
    }
    return NULL;
}

int latch_feedback_pub_start(const char *path)
{
    if (g_pub.running) {
        return 0;
    }
    if (path == NULL || path[0] == '\0') {
        path = LATCH_FEEDBACK_PUB_PATH_DEFAULT;
    }
    if (strlen(path) >= sizeof(g_pub.path)) {
        return -1;
    }

    /* The primitives are initialised EXACTLY ONCE, for the process
     * lifetime, and are never destroyed.  See the block above. */
    fb_pub_primitives_ready();
    memset(&g_pub.status, 0, sizeof(g_pub.status));
    g_pub.fd      = -1;
    g_pub.pending = 0;
    g_pub.running = 1;
    memset(g_pub.path, 0, sizeof(g_pub.path));
    (void)memcpy(g_pub.path, path, strlen(path));

    if (pthread_create(&g_pub.tid, NULL, fb_pub_writer, NULL) != 0) {
        g_pub.running = 0;
        /* The primitives are NOT destroyed here.  A failed start leaves
         * them alive and usable, so a later `start()` -- or a
         * `publish()` that is refused -- does not touch a destroyed
         * object. */
        return -1;
    }
    g_pub.thread_valid = 1;
    return 0;
}

int latch_feedback_pub_publish(const latch_feedback_t *frame)
{
    if (frame == NULL) {
        return -EINVAL;
    }
    /* The lock has to exist even if the publisher was never started:
     * the refusal below is the answer to "publish before start". */
    fb_pub_primitives_ready();
    pthread_mutex_lock(&g_pub.lock);
    if (!g_pub.running) {
        pthread_mutex_unlock(&g_pub.lock);
        return -EPERM;
    }
    if (g_pub.pending) {
        /* The slot still holds a frame the writer thread has not taken
         * yet.  It is overwritten: the transport keeps the LATEST verdict,
         * and a backlog of verdicts would deliver stale ones. */
        fb_pub_count_locked(&g_pub.status.dropped);
    }
    g_pub.slot    = *frame;
    g_pub.pending = 1;
    fb_pub_count_locked(&g_pub.status.offered);
    (void)pthread_cond_signal(&g_pub.cond);
    pthread_mutex_unlock(&g_pub.lock);
    return 0;
}

void latch_feedback_pub_stop(void)
{
    fb_pub_primitives_ready();
    if (!g_pub.running && !g_pub.thread_valid) {
        return;
    }
    pthread_mutex_lock(&g_pub.lock);
    g_pub.running = 0;
    (void)pthread_cond_signal(&g_pub.cond);
    pthread_mutex_unlock(&g_pub.lock);

    if (g_pub.thread_valid) {
        (void)pthread_join(g_pub.tid, NULL);
        g_pub.thread_valid = 0;
    }
    /* THE PRIMITIVES ARE NOT DESTROYED HERE.  They live for the process
     * lifetime; see the block above `g_pub`.  A `publish()` after this
     * call, a `get_status()` after this call and a `start()` after this
     * call all use the SAME live mutex and condvar. */
}

void latch_feedback_pub_get_status(latch_feedback_pub_status_t *out)
{
    if (out == NULL) {
        return;
    }
    fb_pub_primitives_ready();
    pthread_mutex_lock(&g_pub.lock);
    *out = g_pub.status;
    out->running = g_pub.running ? 1 : 0;
    pthread_mutex_unlock(&g_pub.lock);
}

int latch_feedback_pub_is_running(void)
{
    return g_pub.running ? 1 : 0;
}
