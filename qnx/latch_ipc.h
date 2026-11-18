#ifndef LATCH_IPC_H_
#define LATCH_IPC_H_

#include <stddef.h>
#include "latch_protocol.h"

/* Decode only exact-size LPRP v1 or LPR2 v2 messages. */
int latch_ipc_decode(const void *bytes, size_t length, latch_proposal_t *out);

#endif
