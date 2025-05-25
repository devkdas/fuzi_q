#include <picoquic.h>
#include <picoquic_utils.h>
#include <picoquic_internal.h> /* For picoquic_varint_encode etc. */
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "fuzi_q.h"

/* Forward declarations for helper and other fuzzers */
static int encode_and_overwrite_varint(uint8_t* field_start, uint8_t* field_end, uint8_t* frame_max, uint64_t new_value);
void default_frame_fuzzer(uint64_t fuzz_pilot, uint8_t* bytes, uint8_t* bytes_max);
uint8_t* fuzz_in_place_or_skip_varint(uint64_t fuzz_pilot, uint8_t* bytes, uint8_t* bytes_max, int do_fuzz);


/* Create crypto_frame_fuzzer_logic function */
void crypto_frame_fuzzer_logic(uint64_t fuzz_pilot, uint8_t* frame_start, uint8_t* frame_max, fuzzer_ctx_t* ctx, fuzzer_icid_ctx_t* icid_ctx)
{
    uint8_t* p = frame_start;
    uint64_t frame_type;
    int specific_fuzz_applied = 0;

    /* Frame Type (already known to be CRYPTO_HS, but skip it) */
    p = (uint8_t*)picoquic_frames_varint_skip(p, frame_max);
    if (p == NULL || p >= frame_max) {
        default_frame_fuzzer(fuzz_pilot, frame_start, frame_max);
        return;
    }

    uint8_t* offset_start = p;
    uint64_t original_offset;
    uint8_t* offset_end = (uint8_t*)picoquic_frames_varint_decode(offset_start, frame_max, &original_offset);
    if (offset_end == NULL || offset_start == offset_end) { /* Fail or empty varint */
        default_frame_fuzzer(fuzz_pilot, frame_start, frame_max);
        return;
    }

    uint8_t* length_start = offset_end;
    uint64_t original_length;
    uint8_t* length_end = (uint8_t*)picoquic_frames_varint_decode(length_start, frame_max, &original_length);
    if (length_end == NULL || length_start == length_end) { /* Fail or empty varint */
        default_frame_fuzzer(fuzz_pilot, frame_start, frame_max);
        return;
    }

    uint8_t* data_start = length_end;
    size_t data_present_len = 0;
    if (data_start < frame_max) {
        data_present_len = frame_max - data_start;
    }

    /* Probabilistic Fuzzing (1-in-2 to enter specific fuzz block, then further choices) */
    if ((fuzz_pilot & 0x01) == 0) {
        fuzz_pilot >>= 1;
        int choice = fuzz_pilot % 4; /* 0: Offset, 1: Large Length, 2: Zero Length, 3: Corrupt Data */
        fuzz_pilot >>= 2;

        switch (choice) {
        case 0: /* Target Offset */
            if (offset_start && offset_end) {
                uint64_t new_offset_val = (fuzz_pilot & 1) ? 0x3FFFFFFFFFFFFFFF : 0;
                if (encode_and_overwrite_varint(offset_start, offset_end, frame_max, new_offset_val)) {
                    specific_fuzz_applied = 1;
                }
            }
            break;
        case 1: /* Target Length (Extremely Large) */
            if (length_start && length_end) {
                uint64_t new_length_val = (fuzz_pilot & 1) ? 0x3FFFFFFFFFFFFFFF : 65536;
                if (encode_and_overwrite_varint(length_start, length_end, frame_max, new_length_val)) {
                    specific_fuzz_applied = 1;
                }
            }
            break;
        case 2: /* Target Length (Zero) */
            if (length_start && length_end) {
                if (encode_and_overwrite_varint(length_start, length_end, frame_max, 0)) {
                    specific_fuzz_applied = 1;
                }
            }
            break;
        case 3: /* Corrupt Crypto Data */
            if (data_present_len > 0) {
                size_t num_flips = 1 + (fuzz_pilot % 3); /* Flip 1-3 bytes */
                fuzz_pilot >>= 2;
                for (size_t i = 0; i < num_flips; i++) {
                    if (data_present_len == 0) break;
                    size_t flip_idx = fuzz_pilot % data_present_len;
                    if (icid_ctx == NULL && fuzz_pilot == 0) { /* Cannot replenish without context */
                        fuzz_pilot = frame_start[0]; /* Use some byte from frame if out of pilot and no ctx */
                    } else if (fuzz_pilot == 0) {
                         fuzz_pilot = picoquic_test_random(&icid_ctx->random_context);
                    }
                    data_start[flip_idx] ^= (uint8_t)(fuzz_pilot & 0xFF);
                    fuzz_pilot >>= 8;
                }
                specific_fuzz_applied = 1;
            }
            break;
        }
    }

    if (!specific_fuzz_applied) {
        default_frame_fuzzer(fuzz_pilot, frame_start, frame_max);
    }
}

/* Dummy implementations for compilation if not linked with rest of fuzzer.c */
#ifndef LIBRARY_COMPILE 
static int encode_and_overwrite_varint(uint8_t* field_start, uint8_t* field_end, uint8_t* frame_max, uint64_t new_value) {
    (void)field_start; (void)field_end; (void)frame_max; (void)new_value; return 0; }
void default_frame_fuzzer(uint64_t fuzz_pilot, uint8_t* bytes, uint8_t* bytes_max) {
    (void)fuzz_pilot; (void)bytes; (void)bytes_max; }
uint8_t* picoquic_frames_varint_skip(const uint8_t* bytes, const uint8_t* bytes_max) { /* Const corrected */
    if (bytes && bytes < bytes_max) return (uint8_t*)bytes + 1; return (uint8_t*)bytes_max; }
uint8_t* picoquic_frames_varint_decode(const uint8_t* bytes, const uint8_t* bytes_max, uint64_t* val) { /* Const corrected */
    *val = 0; if (bytes && bytes < bytes_max) { *val = bytes[0]; return (uint8_t*)bytes + 1;} return (uint8_t*)bytes_max; }
/* Real picoquic_varint_encode is in picoquic_internal.h */
uint8_t* picoquic_varint_encode(uint8_t* bytes, const uint8_t* bytes_max, uint64_t n64) {
    if(bytes < bytes_max) { bytes[0] = (uint8_t)n64; return bytes+1;} return bytes;
}
#endif
