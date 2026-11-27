/*
 * guest/latch_infer.cpp -- the in-guest inference program.
 *
 * WHAT THIS IS
 * ------------
 * A statically linked AArch64 C++ program that runs INSIDE the Linux
 * guest, loads a GGUF model with llama.cpp, asks the model for a motion
 * command, constrains the model's output to LATCH's action schema with a
 * GBNF grammar, re-validates the model's JSON with an INDEPENDENT
 * parser, and writes the resulting 32-byte wire-v2 frame to a file
 * descriptor (a pipe to the freestanding policy).
 *
 * WHY IT IS BUILT THIS WAY
 * ------------------------
 * The model is the UNTRUSTED side of the system.  Everything here is
 * therefore written to make a bad model output HARMLESS rather than to
 * make a good model output clever:
 *
 *   1. The GBNF grammar constrains the SHAPE of the output.  The model
 *      physically cannot emit anything but an action object.
 *   2. guest/latch_action.c re-validates that output with a SECOND,
 *      INDEPENDENT implementation of the schema.  A bug in the grammar
 *      therefore cannot become the definition of what is acceptable.
 *   3. The validator checks STRUCTURE only.  It does NOT know the
 *      safety envelope: the keep-out box, the rate limit and the unit
 *      whitelist live in the signed manifest and are enforced by the
 *      trusted QNX supervisor, which is the only component allowed to
 *      decide what is safe.
 *   4. A frame that fails the gate is DROPPED.  Nothing is emitted, and
 *      the next attempt starts from a clean slate.
 *
 * The freestanding policy (guest/latch_guest_init.c) stays PID 1 and
 * remains the ONLY writer on the guest's virtio-console.  This program
 * never touches that channel: it writes to a pipe, and the policy
 * relays.  If this program dies, the policy observes the closed pipe and
 * stops relaying -- which is the same fail-closed behaviour as the guest
 * going silent.
 *
 * THE PROMPT
 * ----------
 * The prompt is deliberately small and explicit, with one worked
 * example.  A 135M-parameter model is not going to plan a robot arm; it
 * is going to produce a well-formed, plausible command.  What makes the
 * system safe is not the model's cleverness -- it is the supervisor's
 * refusal to act on anything the envelope forbids.
 */

#include "llama.h"
#include "latch_action.h"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include <unistd.h>

/* ---------------------------------------------------------------------- */
/* The GBNF grammar                                                        */
/* ---------------------------------------------------------------------- */

/*
 * The grammar is the SHAPE of the action schema:
 *
 *     {"u_mrad":<int>,"unit_id":<uint>,"confidence":<0..255>}
 *
 * The number rule forbids leading zeros, so the grammar and the
 * validator agree by construction: anything the grammar can produce, the
 * validator accepts syntactically.
 */
static const char *LATCH_ACTION_GBNF =
    "root   ::= \"{\\\"u_mrad\\\":\" number \",\\\"unit_id\\\":\" number "
    "\",\\\"confidence\\\":\" number \"}\"\n"
    "number ::= \"-\"? (\"0\" | [1-9] [0-9]*)\n";

/* ---------------------------------------------------------------------- */
/* Log filtering                                                           */
/* ---------------------------------------------------------------------- */

/*
 * llama.cpp's default logger prints EVERY level, including DEBUG, and the
 * graph dump alone is thousands of lines.  In this guest that is not a
 * cosmetic problem -- it is a TIMING problem:
 *
 *   QNX's own hypervisor documentation says the PL011 "is slow and has slow
 *   output", and the measured cost on this tree is ~24 ms of GUEST STALL
 *   per line written to the guest console.  Thousands of DEBUG lines is
 *   therefore minutes of guest stall before the model produces its first
 *   token, and it fills the guest's console log with megabytes of noise.
 *
 * Measured on the QEMU AArch64 target (2026-11-26): with the default
 * logger the guest console reached 1.8 GB and the model had still not
 * emitted a decision 90 s after the relay started.
 *
 * So the program installs its own logger.  WARN and ERROR are kept -- they
 * are the ones that matter and there are few of them.  INFO is kept only
 * for ONE line: the model's own load summary, because that is the line the
 * on-target evidence quotes.  DEBUG and CONT are dropped.
 *
 * The bulk that is dropped is llama.cpp's metadata dump: 41 lines for this
 * model (one "loaded meta data", one "Dumping metadata keys/values" header,
 * 37 "- kv N: ..." lines and 2 "- type ..." lines).  Each of those lines is
 * a separate printk to the guest's PL011 console, and the console is the
 * slow device: at the measured ~24 ms per line they are a second of guest
 * time, spent while the model's output competes with the POLICY's markers
 * for the same console lock.
 *
 * The LATCH-specific lines ([latch_infer] ...) are printed by this program
 * directly with fprintf(stderr, ...), so they are unaffected by this
 * filter and always reach the console.  There are three of them.
 */
static void latch_infer_log_filter(enum ggml_log_level level,
                                   const char *text,
                                   void *user_data) {
    (void)user_data;
    switch (level) {
        case GGML_LOG_LEVEL_WARN:
        case GGML_LOG_LEVEL_ERROR:
            std::fputs(text, stderr);
            break;
        case GGML_LOG_LEVEL_INFO:
            /* Keep the one line that says the model was loaded; drop the
             * 40 lines of metadata behind it. */
            if (std::strstr(text, "loaded meta data with") != nullptr) {
                std::fputs(text, stderr);
            }
            break;
        case GGML_LOG_LEVEL_CONT:
            /* A continuation of a line we may have dropped.  Dropping it
             * can leave a partial line; the next kept line starts with
             * the level prefix, so a stray fragment is harmless. */
            break;
        case GGML_LOG_LEVEL_DEBUG:
        case GGML_LOG_LEVEL_NONE:
        default:
            break;
    }
}

/* ---------------------------------------------------------------------- */
/* Options                                                                 */
/* ---------------------------------------------------------------------- */

struct Options {
    std::string model_path;
    std::string prompt_path;
    int         out_fd       = 1;
    int         n_threads    = 4;
    int         max_new      = 64;
    int         iterations   = 0;      /* 0 = until stopped */
    int         start_theta  = 0;      /* mrad */
    int         example_u    = 0;      /* the worked example's u_mrad */
    bool        example_u_set = false;
    bool        dry_run      = false;  /* do not write frames */
    bool        show_prompt  = false;
    bool        show_grammar = false;
};

static void usage(const char *prog) {
    std::fprintf(stderr,
        "Usage: %s --model <file.gguf> [options]\n"
        "\n"
        "  --model <path>        the GGUF model to load (required)\n"
        "  --out-fd <n>          the file descriptor to write frames to (default 1)\n"
        "  --n-threads <n>       llama.cpp worker threads (default 4)\n"
        "  --max-new <n>         the maximum number of tokens per decision (default 64)\n"
        "  --iterations <n>      how many decisions to make (0 = forever)\n"
        "  --theta <mrad>        the initial joint angle (default 0)\n"
        "  --prompt <file>       read the user prompt body from a file\n"
        "  --example-u <mrad>    the u_mrad shown in the worked example\n"
        "  --dry-run             generate, report, but write no frames\n"
        "  --show-prompt         print the prompt and exit\n"
        "  --show-grammar        print the GBNF grammar and exit\n"
        "  --help                this text\n",
        prog);
}

static bool parse_args(int argc, char **argv, Options &opt) {
    for (int i = 1; i < argc; ++i) {
        const char *a = argv[i];
        auto next = [&](const char *what) -> const char * {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "latch_infer: %s needs a value\n", what);
                return nullptr;
            }
            return argv[++i];
        };
        if (std::strcmp(a, "--model") == 0) {
            const char *v = next("--model"); if (!v) return false;
            opt.model_path = v;
        } else if (std::strcmp(a, "--out-fd") == 0) {
            const char *v = next("--out-fd"); if (!v) return false;
            opt.out_fd = std::atoi(v);
        } else if (std::strcmp(a, "--n-threads") == 0) {
            const char *v = next("--n-threads"); if (!v) return false;
            opt.n_threads = std::atoi(v);
        } else if (std::strcmp(a, "--max-new") == 0) {
            const char *v = next("--max-new"); if (!v) return false;
            opt.max_new = std::atoi(v);
        } else if (std::strcmp(a, "--iterations") == 0) {
            const char *v = next("--iterations"); if (!v) return false;
            opt.iterations = std::atoi(v);
        } else if (std::strcmp(a, "--theta") == 0) {
            const char *v = next("--theta"); if (!v) return false;
            opt.start_theta = std::atoi(v);
        } else if (std::strcmp(a, "--prompt") == 0) {
            const char *v = next("--prompt"); if (!v) return false;
            opt.prompt_path = v;
        } else if (std::strcmp(a, "--example-u") == 0) {
            const char *v = next("--example-u"); if (!v) return false;
            opt.example_u = std::atoi(v);
            opt.example_u_set = true;
        } else if (std::strcmp(a, "--dry-run") == 0) {
            opt.dry_run = true;
        } else if (std::strcmp(a, "--show-prompt") == 0) {
            opt.show_prompt = true;
        } else if (std::strcmp(a, "--show-grammar") == 0) {
            opt.show_grammar = true;
        } else if (std::strcmp(a, "--help") == 0 || std::strcmp(a, "-h") == 0) {
            usage(argv[0]);
            std::exit(0);
        } else {
            std::fprintf(stderr, "latch_infer: unknown argument '%s'\n", a);
            return false;
        }
    }
    return true;
}

/* ---------------------------------------------------------------------- */
/* The prompt                                                              */
/* ---------------------------------------------------------------------- */

/*
 * The prompt body describes the plant state and shows ONE worked
 * example of the answer format.  The example is the important part: a
 * 135M model copies a pattern far more reliably than it invents one,
 * and the grammar guarantees that whatever it copies is well formed.
 */
static std::string build_prompt(int theta_mrad,
                                const std::string &user_body,
                                int example_u) {
    std::string p;
    p += "<|im_start|>system\n";
    p += "You plan motions for a one-joint robotic arm. Reply with one JSON "
         "object and nothing else.<|im_end|>\n";
    p += "<|im_start|>user\n";
    p += user_body;
    p += "Current joint angle: ";
    p += std::to_string(theta_mrad);
    p += " mrad. Unit id 1 is the arm.\n";
    p += "Answer with exactly this shape: "
         "{\"u_mrad\":<integer>,\"unit_id\":1,\"confidence\":<0-255>}\n";
    p += "Example answer: {\"u_mrad\":";
    p += std::to_string(example_u);
    p += ",\"unit_id\":1,\"confidence\":210}\n";
    p += "<|im_end|>\n";
    p += "<|im_start|>assistant\n";
    return p;
}

/* ---------------------------------------------------------------------- */
/* The experiment's parameters, taken from the read-only asset disk        */
/* ---------------------------------------------------------------------- */

/*
 * The prompt body and the worked example are EXPERIMENT PARAMETERS, not
 * safety parameters: the safety envelope lives in the signed manifest and
 * is enforced by the trusted QNX supervisor, which never sees any of this.
 *
 * They are read from the asset disk -- the read-only virtio-blk image the
 * hypervisor hands to the guest -- so that one build of the guest serves
 * several experiments and the freestanding policy stays untouched.  The
 * policy's argv is fixed at compile time, so a parameter that has to vary
 * per experiment cannot come from there.
 *
 *   /model/latch_prompt.txt   the user prompt body (optional)
 *   /model/latch_example_u    the worked example's u_mrad (optional)
 *
 * If a file is ABSENT, the built-in default is used and the program SAYS
 * so on the console.  That is the opposite of a silent safety fallback:
 * the default is a documented value, and the evidence quotes which one was
 * in force.
 */
#define LATCH_DEFAULT_EXAMPLE_U (-20)
static const char *LATCH_PROMPT_FILE    = "/model/latch_prompt.txt";
static const char *LATCH_EXAMPLE_U_FILE = "/model/latch_example_u";

/* Read a small text file into a string.  Returns false if it cannot be
 * opened; a missing file is NOT an error here (see the comment above). */
static bool read_small_file(const char *path, std::string &out) {
    FILE *f = std::fopen(path, "rb");
    if (f == nullptr) {
        return false;
    }
    char buf[4096];
    size_t n = std::fread(buf, 1u, sizeof(buf) - 1u, f);
    buf[n] = '\0';
    std::fclose(f);
    out.assign(buf, n);
    return true;
}

/* ---------------------------------------------------------------------- */
/* Sampling                                                                */
/* ---------------------------------------------------------------------- */

static void batch_set_tokens(llama_batch_ext *batch, const llama_token *tokens,
                             int32_t n_tokens, llama_pos pos_0) {
    llama_batch_ext_clear(batch);
    for (int32_t i = 0; i < n_tokens; ++i) {
        const int32_t idx = llama_batch_ext_add_token(batch, 0, tokens[i]);
        const llama_pos pos = pos_0 + i;
        llama_batch_ext_set_pos(batch, idx, &pos);
    }
    llama_batch_ext_set_output_logits(batch, n_tokens - 1, true);
}

struct Decision {
    std::string            text;      /* exactly what the model produced */
    latch_action_t         action{};
    latch_action_status_t  status = LATCH_ACTION_INCOMPLETE;
    int                    n_tokens = 0;
    bool                   complete = false;  /* the object was closed */
};

/*
 * Run one decision.
 *
 * The stopping rule is the VALIDATOR, not a token count: generation
 * stops as soon as the produced text is a syntactically complete object.
 * That is what makes "the grammar allows it" and "the parser accepts it"
 * the same statement -- and it means a truncated generation is detected
 * rather than silently padded.
 */
static Decision decide(llama_context *ctx, const llama_vocab *vocab,
                       llama_sampler *smpl, llama_batch_ext *batch,
                       const std::string &prompt, int max_new) {
    Decision out;

    llama_sampler_reset(smpl);
    llama_memory_clear(llama_get_memory(ctx), true);

    const int n_prompt = -llama_tokenize(vocab, prompt.c_str(), prompt.size(),
                                         nullptr, 0, true, true);
    if (n_prompt <= 0) {
        out.status = LATCH_ACTION_ERR_SYNTAX;
        out.complete = true;
        return out;
    }
    std::vector<llama_token> prompt_tokens((size_t)n_prompt);
    if (llama_tokenize(vocab, prompt.c_str(), prompt.size(),
                       prompt_tokens.data(), prompt_tokens.size(),
                       true, true) < 0) {
        out.status = LATCH_ACTION_ERR_SYNTAX;
        out.complete = true;
        return out;
    }

    batch_set_tokens(batch, prompt_tokens.data(), n_prompt, 0);
    if (llama_process(ctx, LLAMA_PROCESS_TYPE_DECODE, batch) != 0) {
        out.status = LATCH_ACTION_ERR_SYNTAX;
        out.complete = true;
        return out;
    }

    llama_pos pos = n_prompt;
    std::string text;

    for (int i = 0; i < max_new; ++i) {
        /*
         * llama_sampler_sample() does THREE things: it builds the
         * candidate set from the context logits, it applies the chain
         * (grammar filter first, greedy pick second), and it ACCEPTS the
         * chosen token -- i.e. it calls llama_sampler_accept() for us.
         *
         * So there must be NO second llama_sampler_accept() here.  An
         * extra accept advances the grammar stack TWICE for the same
         * token: the first advance consumes '{' (the stack now expects
         * '"'), the second tries to consume '{' again, fails to match,
         * empties the stack, and llama.cpp throws
         *
         *     Unexpected empty grammar stack after accepting piece: { (107)
         *
         * That is not a hypothesis: it was reproduced on the host with
         * this exact model and grammar, and it disappears when the
         * second accept is removed.
         */
        const llama_token id = llama_sampler_sample(smpl, ctx, -1);
        if (llama_vocab_is_eog(vocab, id)) {
            break;
        }

        char buf[256];
        const int n = llama_token_to_piece(vocab, id, buf, sizeof(buf), 0, true);
        if (n < 0) {
            break;
        }
        text.append(buf, (size_t)n);
        out.n_tokens++;

        latch_action_t parsed{};
        const latch_action_status_t st =
            latch_action_parse(text.c_str(), text.size(), &parsed);
        if (st == LATCH_ACTION_OK) {
            out.action = parsed;
            out.status = LATCH_ACTION_OK;
            out.complete = true;
            out.text = text;
            return out;
        }
        if (st != LATCH_ACTION_INCOMPLETE) {
            /* The object is closed but something about it is wrong.  Stop
             * here: the text is final, and the caller will drop it. */
            out.status = st;
            out.complete = true;
            out.text = text;
            return out;
        }

        llama_token next = id;
        batch_set_tokens(batch, &next, 1, pos);
        if (llama_process(ctx, LLAMA_PROCESS_TYPE_DECODE, batch) != 0) {
            out.status = LATCH_ACTION_ERR_SYNTAX;
            out.complete = true;
            out.text = text;
            return out;
        }
        pos++;
    }

    out.text = text;
    out.complete = false;
    if (out.status == LATCH_ACTION_INCOMPLETE) {
        out.status = LATCH_ACTION_ERR_SYNTAX;
    }
    return out;
}

/* ---------------------------------------------------------------------- */

static bool write_all(int fd, const void *buf, size_t len) {
    const uint8_t *p = (const uint8_t *)buf;
    size_t done = 0u;
    while (done < len) {
        const ssize_t n = ::write(fd, p + done, len - done);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        if (n == 0) {
            return false;
        }
        done += (size_t)n;
    }
    return true;
}

int main(int argc, char **argv) {
    Options opt;
    if (!parse_args(argc, argv, opt)) {
        usage(argv[0]);
        return 2;
    }

    if (opt.show_grammar) {
        std::fputs(LATCH_ACTION_GBNF, stdout);
        return 0;
    }

    if (opt.model_path.empty()) {
        std::fprintf(stderr, "latch_infer: --model is required\n");
        usage(argv[0]);
        return 2;
    }

    std::string user_body =
        "Pick a small safe step towards the centre of the safe range.\n";
    if (!opt.prompt_path.empty()) {
        if (!read_small_file(opt.prompt_path.c_str(), user_body)) {
            std::fprintf(stderr, "latch_infer: cannot open prompt file '%s'\n",
                         opt.prompt_path.c_str());
            return 2;
        }
    } else {
        /* No explicit --prompt: take the one from the asset disk if it is
         * there, and say so. */
        std::string from_disk;
        if (read_small_file(LATCH_PROMPT_FILE, from_disk) && !from_disk.empty()) {
            user_body = from_disk;
            std::fprintf(stderr, "[latch_infer] prompt body: %s\n",
                         LATCH_PROMPT_FILE);
        } else {
            std::fprintf(stderr, "[latch_infer] prompt body: built-in default\n");
        }
    }

    /* The worked example's u_mrad.  Same rule: explicit option, then the
     * asset disk, then the documented default. */
    int example_u = LATCH_DEFAULT_EXAMPLE_U;
    if (opt.example_u_set) {
        example_u = opt.example_u;
    } else {
        std::string from_disk;
        if (read_small_file(LATCH_EXAMPLE_U_FILE, from_disk) && !from_disk.empty()) {
            example_u = std::atoi(from_disk.c_str());
            std::fprintf(stderr, "[latch_infer] example u_mrad: %s (%d)\n",
                         LATCH_EXAMPLE_U_FILE, example_u);
        } else {
            std::fprintf(stderr, "[latch_infer] example u_mrad: built-in default (%d)\n",
                         example_u);
        }
    }

    const std::string prompt = build_prompt(opt.start_theta, user_body, example_u);
    if (opt.show_prompt) {
        std::fputs(prompt.c_str(), stdout);
        return 0;
    }

    llama_backend_init();

    /* Install the log filter BEFORE the model is loaded, so that the
     * loader's own INFO lines are the only ones that reach the console. */
    llama_log_set(latch_infer_log_filter, nullptr);

    llama_model_params model_params = llama_model_default_params();
    model_params.n_gpu_layers = 0;      /* CPU only: the guest has no GPU */

    llama_model *model = llama_model_load_from_file(opt.model_path.c_str(), model_params);
    if (model == nullptr) {
        std::fprintf(stderr, "latch_infer: cannot load the model '%s'\n",
                     opt.model_path.c_str());
        llama_backend_free();
        return 1;
    }

    const llama_vocab *vocab = llama_model_get_vocab(model);

    llama_context_params ctx_params = llama_context_default_params();
    ctx_params.n_ctx           = 1024;
    ctx_params.n_batch         = 256;
    ctx_params.n_ubatch        = 256;
    ctx_params.n_threads       = opt.n_threads;
    ctx_params.n_threads_batch = opt.n_threads;

    llama_context *ctx = llama_init_from_model(model, ctx_params);
    if (ctx == nullptr) {
        std::fprintf(stderr, "latch_infer: cannot create the context\n");
        llama_model_free(model);
        llama_backend_free();
        return 1;
    }

    /* The sampler chain: the GRAMMAR FIRST, so that it removes the
     * tokens that do not fit the schema from the candidate set, and the
     * greedy sampler second, so that it picks from what is left.  The
     * order matters: a greedy sampler placed before the grammar would
     * have already chosen an illegal token.
     *
     * llama_sampler_sample() applies the whole chain and then accepts
     * the chosen token, so this program never calls
     * llama_sampler_accept() itself.  See the comment in decide(). */
    llama_sampler_chain_params sparams = llama_sampler_chain_default_params();
    sparams.no_perf = false;
    llama_sampler *smpl = llama_sampler_chain_init(sparams);
    llama_sampler_chain_add(smpl,
        llama_sampler_init_grammar(vocab, LATCH_ACTION_GBNF, "root"));
    llama_sampler_chain_add(smpl, llama_sampler_init_greedy());

    llama_batch_ext *batch = llama_batch_ext_init(ctx);

    std::fprintf(stderr,
                 "[latch_infer] model=%s params=%llu threads=%d\n",
                 opt.model_path.c_str(),
                 (unsigned long long)llama_model_n_params(model),
                 opt.n_threads);
    std::fflush(stderr);

    /*
     * THE "READY" BYTE -- the producer tells the policy it has a
     * proposal ready.
     *
     * The guest policy is the only writer on the wire, and the trusted
     * supervisor starts its deadman lease when the FIRST frame arrives.
     * So the moment the policy opens its session is the moment the
     * producer has to be ready to produce.
     *
     * MEASURED DEFECTS on the QEMU AArch64 target (2026-11-26), and
     * what each one taught:
     *
     * 1. The session opened BEFORE the model was loaded.  The load
     *    reads 168 MB from the hypervisor's block device, and while
     *    that I/O is in flight the host is busy enough that the
     *    virtio-console forwarding stalls for hundreds of milliseconds
     *    -- far longer than the signed 100-tick lease.  The frame
     *    stream had a 594-tick hole, the supervisor's deadman fired
     *    five times, and it demoted itself all the way to LATCH before
     *    the model had said anything.  The supervisor was right to; the
     *    producer had opened its session before it could produce.
     *
     * 2. The session opened after the model was LOADED, and the model
     *    then thought under the lease.  That part worked -- the lease
     *    was held for the whole 88-second think -- but the model's
     *    ANNOUNCEMENT was still inside the supervised window, and a
     *    console line on this platform is not free:
     *
     *      a `/dev/kmsg` write becomes a printk, and the guest's PL011
     *      console is slow.  Measured on the target: 57-88 ms of GUEST
     *      TIME per line, at roughly 1.3-1.8 ms per CHARACTER.
     *
     *    The model's decision line is 119 characters, so announcing it
     *    inside the supervised window cost about 153 ticks -- more
     *    than the 100-tick lease -- and the deadman fired again.  The
     *    guest was alive; the guest's own diagnostics had eaten the
     *    lease.
     *
     * So the FIRST proposal is computed and announced BEFORE the
     * session opens.  The console cost is then paid while no lease is
     * running, the session opens with a proposal already in hand, and
     * the supervised window contains NO console write at all.
     *
     * The byte is 0xA5.  It is the first thing on the pipe, ahead of
     * any frame, so the policy can read exactly one byte and know it
     * has the readiness signal.
     */
    bool ready_sent = false;

    auto send_ready = [&](void) {
        const unsigned char ready = 0xA5u;
        ssize_t written = 0;
        while (written < 1) {
            ssize_t n = ::write(opt.out_fd, &ready, 1);
            if (n > 0) {
                written += n;
                continue;
            }
            if (n < 0 && errno == EINTR) {
                continue;
            }
            std::fprintf(stderr, "latch_infer: cannot signal readiness: %s\n",
                         std::strerror(errno));
            break;
        }
        if (written == 1) {
            ready_sent = true;
            std::fprintf(stderr, "[latch_infer] ready: the first proposal is ready\n");
            std::fflush(stderr);
        }
    };

    int theta = opt.start_theta;
    uint32_t seq = 1u;
    uint32_t coherence = 0u;
    int emitted = 0;
    int dropped = 0;

    for (int iter = 0; opt.iterations == 0 || iter < opt.iterations; ++iter) {
        const std::string p = build_prompt(theta, user_body, example_u);
        Decision d = decide(ctx, vocab, smpl, batch, p, opt.max_new);

        if (d.status != LATCH_ACTION_OK) {
            dropped++;
            std::fprintf(stderr,
                         "[latch_infer] decision DROPPED: %s (text='%s', tokens=%d)\n",
                         latch_action_status_str(d.status), d.text.c_str(), d.n_tokens);
            std::fflush(stderr);
            if (!ready_sent) {
                /* The FIRST proposal could not be made, so the producer
                 * will never be ready.  Exit, so the policy sees EOF on
                 * the pipe and fails closed instead of opening a session
                 * for a producer that cannot produce. */
                std::fprintf(stderr, "[latch_infer] FATAL: the first proposal was "
                             "dropped; the producer cannot produce\n");
                std::fflush(stderr);
                break;
            }
            continue;
        }

        uint8_t frame[LATCH_WIRE_V2_SIZE];
        latch_wire_v2_pack(frame, LATCH_GOV_KIND_CMD_V2, seq, coherence,
                           d.action.u_mrad, d.action.confidence, 1u,
                           d.action.unit_id);
        if (latch_wire_v2_check(frame, sizeof(frame)) != 0) {
            dropped++;
            std::fprintf(stderr, "[latch_infer] decision DROPPED: the packed frame "
                                 "failed its own check\n");
            continue;
        }

        if (!ready_sent) {
            /*
             * THE FIRST PROPOSAL IS ANNOUNCED BEFORE THE SESSION OPENS.
             *
             * This is the whole console discipline of the profile, and
             * it is measured, not stylistic.  A console line on this
             * platform costs 57-88 ms of guest time -- roughly 1.3-1.8
             * ms per character -- because a `/dev/kmsg` write becomes a
             * printk and the guest's PL011 console is slow.  The signed
             * lease is 100 ticks, and 100 ticks is roughly 100 ms, so a
             * single 119-character line announced inside the supervised
             * window cost about 153 ticks: the deadman fired and the
             * supervisor demoted itself out of HP, not because the model
             * had gone silent but because the model's own announcement
             * had eaten the lease.
             *
             * So the first proposal is announced while no lease is
             * running, and the session opens immediately afterwards with
             * the proposal already in hand.  Every LATER proposal is
             * relayed SILENTLY: the supervised window contains no
             * console write at all.
             */
            std::fprintf(stderr,
                         "[latch_infer] decision %d: u_mrad=%d unit_id=%u confidence=%u "
                         "seq=%u text='%s'\n",
                         iter, d.action.u_mrad, d.action.unit_id, d.action.confidence,
                         seq, d.text.c_str());
            std::fflush(stderr);
            send_ready();
            if (!ready_sent) {
                std::fprintf(stderr, "[latch_infer] FATAL: cannot signal readiness\n");
                std::fflush(stderr);
                break;
            }
        }

        if (!opt.dry_run) {
            if (!write_all(opt.out_fd, frame, sizeof(frame))) {
                std::fprintf(stderr, "[latch_infer] the frame pipe is closed; stopping\n");
                break;
            }
        }

        seq++;
        coherence++;
        theta += d.action.u_mrad;
        emitted++;
    }

    std::fprintf(stderr, "[latch_infer] done: %d frame(s) emitted, %d dropped\n",
                 emitted, dropped);

    llama_batch_ext_free(batch);
    llama_sampler_free(smpl);
    llama_free(ctx);
    llama_model_free(model);
    llama_backend_free();
    return 0;
}
