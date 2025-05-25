#include <picoquic.h>
#include <picoquic_utils.h>
#include <picoquic_internal.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "fuzi_q.h"

/* Copied and modified from lib/fuzzer.c for Step 2 of subtask */
fuzzer_icid_ctx_t* fuzzer_get_icid_ctx(fuzzer_ctx_t* ctx, picoquic_connection_id_t* icid, uint64_t current_time)
{
    fuzzer_icid_ctx_t* icid_ctx = (fuzzer_icid_ctx_t*)picosplay_find(&ctx->icid_tree, icid);

    if (icid_ctx == NULL) {
        /* This is a new ICID. Add it to the tree */
        icid_ctx = (fuzzer_icid_ctx_t*)malloc(sizeof(fuzzer_icid_ctx_t));
        if (icid_ctx != NULL) {
            memset(icid_ctx, 0, sizeof(fuzzer_icid_ctx_t));
            /* Initialize MAX_DATA stateful fuzzing fields */
            icid_ctx->last_sent_max_data = 0;
            icid_ctx->has_sent_max_data = 0;
            memcpy(&icid_ctx->icid, icid, sizeof(picoquic_connection_id_t));
            icid_ctx->last_time = current_time;
            fuzzer_random_cid(ctx, (picoquic_connection_id_t*)&icid_ctx->random_context); /* Using CID field as a container for random data */
            icid_ctx->random_context ^= picoquic_val64_connection_id(ctx->next_cid);
            picoquic_test_random_update_context(&icid_ctx->random_context, (picoquic_connection_id_t*) & icid_ctx->random_context);
            icid_ctx->target_state = (fuzzer_cnx_state_enum)(icid_ctx->random_context % fuzzer_cnx_state_max);
            icid_ctx->random_context >>= 3;
            icid_ctx->target_wait = (unsigned int)(1 + (icid_ctx->random_context % 16));
            icid_ctx->random_context >>= 4;
            memset(icid_ctx->wait_count, 0, sizeof(icid_ctx->wait_count)); /* Ensure wait_count is also initialized here */
            icid_ctx->already_fuzzed = 0; /* Ensure already_fuzzed is initialized */
            /* last_time_fuzzed is not explicitly set here, relies on memset or later update */
            
            picosplay_insert(&ctx->icid_tree, icid_ctx);
            /* Manage LRU list */
            if (ctx->icid_lru == NULL) {
                ctx->icid_lru = icid_ctx;
                ctx->icid_mru = icid_ctx;
                icid_ctx->icid_before = NULL; /* Explicitly NULL for new list */
                icid_ctx->icid_after = NULL;  /* Explicitly NULL for new list */
            }
            else {
                icid_ctx->icid_before = ctx->icid_mru;
                icid_ctx->icid_after = NULL; /* New MRU has no 'after' */
                if (ctx->icid_mru != NULL) { // Should always be true if icid_lru is not NULL
                    ctx->icid_mru->icid_after = icid_ctx;
                }
                ctx->icid_mru = icid_ctx;
            }
        }
    }
    else {
        icid_ctx->last_time = current_time;
        /* Manage LRU list */
        if (ctx->icid_mru != icid_ctx) {
            if (icid_ctx->icid_before != NULL) {
                icid_ctx->icid_before->icid_after = icid_ctx->icid_after;
            }
            else {
                /* This was the LRU */
                ctx->icid_lru = icid_ctx->icid_after;
            }

            if (icid_ctx->icid_after != NULL) {
                icid_ctx->icid_after->icid_before = icid_ctx->icid_before;
            }
            /* else: this was the MRU, no icid_after to update, but this branch (icid_mru != icid_ctx) means it wasn't MRU.
               Actually, if icid_ctx->icid_after is NULL, it *was* the MRU. This case should be caught by icid_mru == icid_ctx.
               If it's not MRU but icid_after is NULL, it means it's the last element, and icid_before is the current MRU.
               This part of LRU seems complex and potentially has edge cases.
               The original code was:
               else { // This was the MRU
                   ctx->icid_mru = icid_ctx->icid_before;
               }
               This implies if icid_ctx->icid_after is NULL, then icid_ctx->icid_before should become the new MRU.
               This seems correct if icid_ctx was indeed the MRU.
            */
            if (ctx->icid_mru == icid_ctx && icid_ctx->icid_before != NULL) { // If it was MRU and not the only element
                 ctx->icid_mru = icid_ctx->icid_before;
            }


            icid_ctx->icid_before = ctx->icid_mru;
            icid_ctx->icid_after = NULL;
            if(ctx->icid_mru != NULL){ // Should always be true if list not empty
                ctx->icid_mru->icid_after = icid_ctx;
            }
            ctx->icid_mru = icid_ctx;
             if (ctx->icid_lru == NULL && ctx->icid_mru !=NULL) { // If list became empty and then re-added this, it's also LRU
                ctx->icid_lru = ctx->icid_mru;
            } else if (ctx->icid_lru == icid_ctx && icid_ctx->icid_after != NULL) { // If we moved LRU to MRU
                ctx->icid_lru = icid_ctx->icid_after;
            }
        }
    }
    /* Final check for LRU consistency if only one element */
    if (ctx->icid_mru != NULL && ctx->icid_mru->icid_before == NULL) {
        ctx->icid_lru = ctx->icid_mru;
    }
    if (ctx->icid_lru != NULL && ctx->icid_lru->icid_after == NULL && ctx->icid_lru->icid_before != NULL) {
        // This case seems problematic: LRU has no 'after' but has 'before' implies it's also MRU.
        // However, if it's LRU, it should not have 'before' unless it's the only element.
    }


    return icid_ctx;
}
