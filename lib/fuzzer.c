/*
* Author: Christian Huitema
* Copyright (c) 2021, Private Octopus, Inc.
* All rights reserved.
*
* Permission to use, copy, modify, and distribute this software for any
* purpose with or without fee is hereby granted, provided that the above
* copyright notice and this permission notice appear in all copies.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL Private Octopus, Inc. BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#define PICOQUIC_STATELESS_RESET_TOKEN_SIZE 16

#include <picoquic.h>
#include <picoquic_utils.h>
#include <picoquic_internal.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "fuzi_q.h"

#define FUZZER_MAX_NB_FRAMES 32

/* Forward declarations for picoquic functions/macros if not found by compiler */
/* These are added as a workaround for potential build environment/include issues. */

/* extern void picoquic_val32be_to_bytes(uint32_t val32, uint8_t* bytes); */
/* extern uint32_t picoquic_val32be(const uint8_t* bytes); */
/* extern int picoquic_max_bits(uint64_t val); */

/*
 * The following functions are generally defined as static inline in picoquic_utils.h or picoquic_internal.h.
 * Providing extern declarations here might conflict if the headers are eventually processed correctly.
 * Instead, we rely on the existing includes (`picoquic_utils.h`, `picoquic_internal.h`) to provide them.
 * If errors persist for these, it points to a deeper include or version issue.
 * Forcing an extern declaration for a static inline function is not standard.
 *
 * picoquic_val32be_to_bytes IS NOT STATIC INLINE, it's in internal.h
 * picoquic_val32be IS NOT STATIC INLINE, it's in internal.h
 * picoquic_max_bits IS STATIC INLINE in picoquic_utils.h
 */

/* Corrected approach: Provide prototypes for non-static-inline functions if they are missing. */
/* For static inline functions like picoquic_max_bits, the include should be sufficient. */
/* If picoquic_max_bits is still an error, the problem is likely that picoquic_utils.h is not being processed as expected. */

#ifndef picoquic_varint_encode_length
static inline int local_picoquic_varint_encode_length(uint64_t n64) {
    if (n64 < 0x40) return 1;
    else if (n64 < 0x4000) return 2;
    else if (n64 < 0x40000000) return 4;
    else return 8; /* Matches standard picoquic varint encoding lengths */
}
#define picoquic_varint_encode_length local_picoquic_varint_encode_length
#endif

/* For picoquic_max_bits, it's often a static inline. If it's not found, */
/* it's a strong indication picoquic_utils.h isn't properly included or is a different version. */
/* Let's try to provide a common definition if it's missing. */
#ifndef picoquic_max_bits
static inline int local_picoquic_max_bits(uint64_t val) {
    int ret = 0;
    if (val == 0) {
        ret = -1;
    } else {
        while (val != 0) {
            ret++;
            val >>= 1;
        }
    }
    return ret;
}
#define picoquic_max_bits local_picoquic_max_bits
#endif

/* Use local definitions for val32be functions to avoid potential linkage issues with extern */
/* if the functions are indeed available in headers but somehow not seen by the compiler pass. */
/* This is safer than extern declarations for functions that might be static inline elsewhere. */

static int encode_and_overwrite_varint(uint8_t* field_start, uint8_t* field_end, uint8_t* frame_max, uint64_t new_value);
uint8_t* fuzz_in_place_or_skip_varint(uint64_t fuzz_pilot, uint8_t* bytes, uint8_t* bytes_max, int do_fuzz);
void default_frame_fuzzer(uint64_t fuzz_pilot, uint8_t* bytes, uint8_t* bytes_max);

/*
 * Basic fuzz test just tries to flip some bits in random packets
 */

uint32_t basic_packet_fuzzer(fuzzer_ctx_t* ctx, uint64_t fuzz_pilot,
    uint8_t* bytes, size_t bytes_max, size_t length, size_t header_length)
{
    uint32_t fuzz_index = 0;
    uint64_t initial_fuzz_pilot = fuzz_pilot; /* Save for independent fuzz actions */

    /* 1. Enhance basic_packet_fuzzer for Short Header Reserved Bits */
    if (length > 0 && (bytes[0] & 0x80) == 0) { /* is_short_header */
        if ((initial_fuzz_pilot & 0x07) == 0) { /* 1-in-8 chance */
            if ((initial_fuzz_pilot >> 3) & 1) {
                bytes[0] ^= 0x20; /* Flip bit 5 (second reserved bit) */
            } else {
                bytes[0] ^= 0x10; /* Flip bit 4 (first reserved bit) */
            }
        }
    }
    /* Continue with original fuzz_pilot for the main fuzzing logic */

    /* Once in 64, fuzz by changing the length */
    if ((fuzz_pilot & 0x3F) == 0xD) {
        uint32_t fuzz_length_max = (uint32_t)(length + 16u);
        uint32_t fuzzed_length;

        if (fuzz_length_max > bytes_max) {
            fuzz_length_max = (uint32_t)bytes_max;
        }
        fuzz_pilot >>= 4; /* Different consumption from initial_fuzz_pilot's first 3 bits */
        fuzzed_length = 16 + (uint32_t)((fuzz_pilot & 0xFFFF) % fuzz_length_max);
        fuzz_pilot >>= 16;
        if (fuzzed_length > length) {
            for (uint32_t i = (uint32_t)length; i < fuzzed_length; i++) {
                bytes[i] = (uint8_t)fuzz_pilot;
            }
        }
        length = fuzzed_length;

        if (length < header_length) {
            length = header_length;
        }
        ctx->nb_fuzzed_length++;
    }
    else {
        size_t fuzz_target = length - header_length;
        if (fuzz_target > 0) {
            /* Find the position that shall be fuzzed */
            fuzz_index = (uint32_t)(header_length + (fuzz_pilot & 0xFFFF) % fuzz_target);
            fuzz_pilot >>= 16;
            while (fuzz_pilot != 0 && fuzz_index < length) {
                /* flip one byte */
                bytes[fuzz_index++] = (uint8_t)(fuzz_pilot & 0xFF);
                fuzz_pilot >>= 8;
                ctx->nb_fuzzed++;
            }
        }
    }

    return (uint32_t)length;
}

/* Frame specific fuzzers. */

void fuzz_random_byte(uint64_t fuzz_pilot, uint8_t* bytes, uint8_t* bytes_max)
{
    if (bytes != NULL && bytes < bytes_max) { /* Ensure there's at least one byte to fuzz */
        size_t l = bytes_max - bytes;
        size_t x = (l > 0) ? (fuzz_pilot % l) : 0; /* Ensure x is valid if l is 0 */
        uint8_t byte_mask = (uint8_t)(fuzz_pilot >> 8);
        if (l > 0) {
             bytes[x] ^= byte_mask;
        }
    }
}

void ack_frequency_frame_fuzzer(uint64_t fuzz_pilot, uint8_t* bytes, uint8_t* bytes_max)
{
    uint8_t* payload_start = bytes;
    uint8_t* current_field = bytes;

    current_field = (uint8_t*)picoquic_frames_varint_skip(current_field, bytes_max);
    payload_start = current_field;

    if (current_field == NULL || current_field >= bytes_max) {
        if (bytes < bytes_max) {
            fuzz_random_byte(fuzz_pilot, bytes, bytes_max);
        }
        return;
    }

    int choice = fuzz_pilot % 4;
    fuzz_pilot >>= 2;

    uint8_t* seq_num_start = payload_start;
    uint8_t* pkt_tol_start = NULL;
    uint8_t* upd_delay_start = NULL;

    if (seq_num_start < bytes_max) {
        pkt_tol_start = (uint8_t*)picoquic_frames_varint_skip(seq_num_start, bytes_max);
    }
    if (pkt_tol_start != NULL && pkt_tol_start < bytes_max) {
        upd_delay_start = (uint8_t*)picoquic_frames_varint_skip(pkt_tol_start, bytes_max);
    }

    switch (choice) {
    case 0:
        if (seq_num_start != NULL && seq_num_start < bytes_max) {
            fuzz_in_place_or_skip_varint(fuzz_pilot, seq_num_start, bytes_max, 1);
        }
        break;
    case 1:
        if (pkt_tol_start != NULL && pkt_tol_start < bytes_max) {
            fuzz_in_place_or_skip_varint(fuzz_pilot, pkt_tol_start, bytes_max, 1);
        }
        break;
    case 2:
        if (upd_delay_start != NULL && upd_delay_start < bytes_max) {
            fuzz_in_place_or_skip_varint(fuzz_pilot, upd_delay_start, bytes_max, 1);
        }
        break;
    case 3:
        if (payload_start < bytes_max) {
            uint8_t* payload_end = bytes_max;
            if (upd_delay_start != NULL && upd_delay_start < bytes_max) {
                 uint8_t* temp_end = (uint8_t*)picoquic_frames_varint_skip(upd_delay_start, bytes_max);
                 if (temp_end != NULL && temp_end <= bytes_max) payload_end = temp_end;
            } else if (pkt_tol_start != NULL && pkt_tol_start < bytes_max) {
                 uint8_t* temp_end = (uint8_t*)picoquic_frames_varint_skip(pkt_tol_start, bytes_max);
                 if (temp_end != NULL && temp_end <= bytes_max) payload_end = temp_end;
            } else if (seq_num_start != NULL && seq_num_start < bytes_max) {
                 uint8_t* temp_end = (uint8_t*)picoquic_frames_varint_skip(seq_num_start, bytes_max);
                 if (temp_end != NULL && temp_end <= bytes_max) payload_end = temp_end;
            }
            if (payload_start < payload_end) {
                 fuzz_random_byte(fuzz_pilot, payload_start, payload_end);
            } else if (payload_start < bytes_max) {
                 fuzz_random_byte(fuzz_pilot, payload_start, bytes_max);
            }
        }
        break;
    default:
        break;
    }
}

uint8_t* fuzz_in_place_or_skip_varint(uint64_t fuzz_pilot, uint8_t* bytes, uint8_t* bytes_max, int do_fuzz)
{
    if (bytes != NULL) {
        uint8_t* head_bytes = bytes;
        bytes = (uint8_t *)picoquic_frames_varint_skip(bytes, bytes_max);
        if (bytes != NULL && do_fuzz && (bytes > head_bytes)){ /* Check l > 0 */
            size_t l = bytes - head_bytes;
            size_t x = fuzz_pilot % l;
            uint8_t byte_mask = (uint8_t)(fuzz_pilot >> 3);
            if (x == 0 && l > 1) { /* Only apply 0x3F mask if not a single byte varint to preserve length encoding */
                 byte_mask &= 0x3f;
            } else if (x == 0 && l == 1) { /* For single byte varint, ensure it's a valid varint encoding */
                 byte_mask = (head_bytes[x] ^ byte_mask) & 0x3F; /* Apply fuzz then mask to be valid */
                 head_bytes[x] = byte_mask; /* Direct assignment after calculating fuzzed value */
                 return bytes; /* Return early as we directly modified */
            }
            head_bytes[x] ^= byte_mask; /* Use head_bytes for modification */
        }
    }
    return bytes;
}

void varint_frame_fuzzer(uint64_t fuzz_pilot, uint8_t* bytes, uint8_t* bytes_max, size_t nb_varints)
{
    size_t fuzz_target;
    uint8_t * first_byte = bytes;
    size_t nb_skipped = 0;

    if (nb_varints <= 1 && nb_varints > 0) { /* If only one varint, target it */
        fuzz_target = 0;
    } else if (nb_varints > 1) {
        fuzz_target = 1 + fuzz_pilot % (nb_varints - 1);
    } else { /* nb_varints is 0 */
        return;
    }
    fuzz_pilot >>= 8;
    bytes = first_byte;

    while (bytes != NULL && bytes < bytes_max && nb_skipped < fuzz_target) {
        nb_skipped++;
        bytes = (uint8_t *)picoquic_frames_varint_skip(bytes, bytes_max);
    }
    fuzz_in_place_or_skip_varint(fuzz_pilot, bytes, bytes_max, 1);
}

void ack_frame_fuzzer(uint64_t fuzz_pilot, uint8_t* frame_start_bytes, uint8_t* frame_max_bytes)
{
    if (frame_start_bytes < frame_max_bytes) {
        if (((fuzz_pilot >> 16) & 0x07) == 1) {
            uint8_t bit_to_flip = 1 << (((fuzz_pilot >> 19) % 5) + 2);
            frame_start_bytes[0] ^= bit_to_flip;
        }
    }

    uint8_t* current_bytes = frame_start_bytes;
    size_t num_varints_in_frame = 0;
    while (current_bytes != NULL && current_bytes < frame_max_bytes) {
        num_varints_in_frame++;
        current_bytes = (uint8_t*)picoquic_frames_varint_skip(current_bytes, frame_max_bytes);
    }
    varint_frame_fuzzer(fuzz_pilot, frame_start_bytes, frame_max_bytes, num_varints_in_frame);

    if ((fuzz_pilot & 0xF) == 0x1) {
        fuzz_pilot >>= 4;

        uint8_t* largest_ack_ptr = NULL;
        uint8_t* ack_range_count_ptr = NULL;
        uint8_t* temp_ptr = frame_start_bytes;

        temp_ptr = (uint8_t*)picoquic_frames_varint_skip(temp_ptr, frame_max_bytes);
        if (temp_ptr == NULL || temp_ptr >= frame_max_bytes) return;
        largest_ack_ptr = temp_ptr;

        temp_ptr = (uint8_t*)picoquic_frames_varint_skip(temp_ptr, frame_max_bytes);
        if (temp_ptr == NULL || temp_ptr >= frame_max_bytes) return;
        /* ack_delay_ptr = temp_ptr; */

        temp_ptr = (uint8_t*)picoquic_frames_varint_skip(temp_ptr, frame_max_bytes);
        if (temp_ptr == NULL || temp_ptr >= frame_max_bytes) return;
        ack_range_count_ptr = temp_ptr;

        if ((fuzz_pilot & 0x1) == 0) {
            if (largest_ack_ptr != NULL && largest_ack_ptr < frame_max_bytes) {
                uint8_t value_to_write = (fuzz_pilot >> 1) & 0x1;
                largest_ack_ptr[0] = value_to_write;
            }
        }
        fuzz_pilot >>= 2;

        if (ack_range_count_ptr != NULL && ack_range_count_ptr < frame_max_bytes) {
            ack_range_count_ptr[0] = 0x00;
        }
    }
}

void stream_frame_fuzzer(uint64_t fuzz_pilot, uint8_t* bytes, uint8_t* bytes_max)
{
    uint8_t* first_byte = bytes;
    int len_bit = bytes[0] & 2;
    int off_bit = bytes[0] & 4;
    int fuzz_length_flag = 0;
    int fuzz_offset_flag = 0;
    int fuzz_stream_id_flag = 0;
    int fuzz_random_flag = 0;

    uint64_t fuzz_variant = (fuzz_pilot ^ 0x57ea3f8a3ef822e8ull) % 5;
    fuzz_pilot >>=3; /* Consume for variant */

    switch (fuzz_variant) {
    case 0: bytes[0] ^= 1; break; /* FIN bit */
    case 1: if (len_bit) fuzz_length_flag = 1; else bytes[0] ^= 2; break;
    case 2: if (off_bit) fuzz_offset_flag = 1; else bytes[0] ^= 4; break;
    case 3: fuzz_stream_id_flag = 1; break;
    default: fuzz_random_flag = 1; break; /* Random byte in frame */
    }

    if (bytes < bytes_max) bytes++; else bytes = NULL;

    bytes = fuzz_in_place_or_skip_varint(fuzz_pilot, bytes, bytes_max, fuzz_stream_id_flag);
    fuzz_pilot >>= 8;

    if (off_bit) {
        if (fuzz_offset_flag) {
            uint8_t* field_start = bytes;
            uint8_t* field_end = (uint8_t*)picoquic_frames_varint_skip(field_start, bytes_max);
            if (field_end != NULL && field_start != field_end) {
                if ((fuzz_pilot & 0x03) == 0) {
                    size_t varint_len = field_end - field_start;
                    if (varint_len > 0 && varint_len <= 8) {
                        field_start[0] |= 0x3F;
                        for (size_t i = 1; i < varint_len; i++) field_start[i] = 0xFF;
                    } else {
                        fuzz_in_place_or_skip_varint(fuzz_pilot >> 2, field_start, bytes_max, 1);
                    }
                } else {
                    fuzz_in_place_or_skip_varint(fuzz_pilot >> 2, field_start, bytes_max, 1);
                }
                bytes = field_end;
            } else {
                bytes = fuzz_in_place_or_skip_varint(fuzz_pilot >> 2, field_start, bytes_max, 1);
            }
        } else {
            bytes = (uint8_t*)picoquic_frames_varint_skip(bytes, bytes_max);
        }
        fuzz_pilot >>= 8;
    }

    if (len_bit) {
        if (fuzz_length_flag) {
            uint8_t* length_field_start = bytes;
            uint64_t original_length_val;
            uint8_t* length_field_end = (uint8_t*)picoquic_frames_varint_decode(length_field_start, bytes_max, &original_length_val);

            if (length_field_end != NULL && length_field_start != length_field_end) {
                int length_fuzz_choice = fuzz_pilot % 8;
                fuzz_pilot >>= 3;

                if (length_fuzz_choice < 2) {
                    uint64_t large_value = (length_fuzz_choice == 0) ? 65536 : 0x3FFFFFFFFFFFFFFF;
                    if (!encode_and_overwrite_varint(length_field_start, length_field_end, bytes_max, large_value)) {
                        fuzz_in_place_or_skip_varint(fuzz_pilot, length_field_start, bytes_max, 1);
                    }
                } else if (length_fuzz_choice < 4) {
                     size_t varint_len = length_field_end - length_field_start;
                     if (varint_len > 0 && varint_len <= 8) {
                         length_field_start[0] |= 0x3F;
                         for (size_t i = 1; i < varint_len; i++) length_field_start[i] = 0xFF;
                     } else {
                         fuzz_in_place_or_skip_varint(fuzz_pilot, length_field_start, bytes_max, 1);
                     }
                } else {
                    fuzz_in_place_or_skip_varint(fuzz_pilot, length_field_start, bytes_max, 1);
                }
                bytes = length_field_end;
            } else {
                bytes = fuzz_in_place_or_skip_varint(fuzz_pilot, length_field_start, bytes_max, 1);
            }
        } else {
            bytes = (uint8_t*)picoquic_frames_varint_skip(bytes, bytes_max);
        }
    }

    if (bytes != NULL && fuzz_random_flag && first_byte +1 < bytes_max) { /* ensure space for at least one byte */
        fuzz_random_byte(fuzz_pilot, first_byte + 1, bytes_max);
    }
}

void datagram_frame_fuzzer(fuzzer_ctx_t* ctx, fuzzer_icid_ctx_t* icid_ctx, uint64_t fuzz_pilot, uint8_t* frame_start, uint8_t* frame_max)
{
    if (frame_start >= frame_max) return;

    uint8_t type_byte = frame_start[0];
    uint8_t* payload_start = frame_start + 1;

    if (payload_start > frame_max) {
         frame_start[0] ^= (uint8_t)(fuzz_pilot & 0xFF);
        return;
    }

    if (type_byte & 1) {
        uint8_t* length_start = payload_start;
        uint64_t original_length;
        uint8_t* length_end = (uint8_t*)picoquic_frames_varint_decode(length_start, frame_max, &original_length);

        if (length_end != NULL && length_start != length_end) {
            uint8_t* data_actual_start = length_end;

            int choice = fuzz_pilot % 8;
            fuzz_pilot >>= 3;

            if (choice < 2) {
                uint64_t large_value = (choice == 0) ? 65536 : 0x3FFFFFFFFFFFFFFF;
                encode_and_overwrite_varint(length_start, length_end, frame_max, large_value);
            } else if (choice == 2) {
                encode_and_overwrite_varint(length_start, length_end, frame_max, 0);
            } else if (choice < 5) {
                fuzz_in_place_or_skip_varint(fuzz_pilot, length_start, frame_max, 1);
            }

            if (data_actual_start < frame_max) {
                size_t fuzzable_data_len = 0;
                if (original_length > 0 && data_actual_start + original_length <= frame_max) {
                    fuzzable_data_len = original_length;
                } else if (original_length > 0 && data_actual_start < frame_max) {
                    fuzzable_data_len = frame_max - data_actual_start;
                }

                if (fuzzable_data_len > 0) {
                    size_t num_flips = 1 + (fuzz_pilot % 2);
                    fuzz_pilot >>= 1;
                    for (size_t i = 0; i < num_flips; i++) {
                        if (fuzzable_data_len == 0) break;
                        size_t flip_idx = fuzz_pilot % fuzzable_data_len;
                        if (icid_ctx == NULL && fuzz_pilot == 0) {
                            fuzz_pilot = frame_start[0];
                        } else if (fuzz_pilot == 0 && icid_ctx != NULL) {
                             fuzz_pilot = picoquic_test_random(&icid_ctx->random_context);
                        }
                        data_actual_start[flip_idx] ^= (uint8_t)(fuzz_pilot & 0xFF);
                        fuzz_pilot >>= 8;
                    }
                }
            }
        } else {
            frame_start[0] ^= (uint8_t)(fuzz_pilot & 0xFF);
        }
    } else {
        if (payload_start < frame_max) {
            size_t data_present_len = frame_max - payload_start;
            size_t num_flips = 1 + (fuzz_pilot % 3);
            fuzz_pilot >>= 2;
            for (size_t i = 0; i < num_flips; i++) {
                if (data_present_len == 0) break;
                size_t flip_idx = fuzz_pilot % data_present_len;
                 if (icid_ctx == NULL && fuzz_pilot == 0) {
                    fuzz_pilot = frame_start[0];
                } else if (fuzz_pilot == 0 && icid_ctx != NULL) {
                     fuzz_pilot = picoquic_test_random(&icid_ctx->random_context);
                }
                payload_start[flip_idx] ^= (uint8_t)(fuzz_pilot & 0xFF);
                fuzz_pilot >>= 8;
            }
        } else {
             frame_start[0] ^= (uint8_t)(fuzz_pilot & 0xFF);
        }
    }
}

void challenge_frame_fuzzer(uint64_t fuzz_pilot, uint8_t* bytes, uint8_t* bytes_max)
{
    size_t x = fuzz_pilot % 41;

    if (x == 0) {
        bytes[0] ^= 1;
    }
    else {
        x = 1 + ((x - 1) & 7);
        if (bytes + x < bytes_max) {
            bytes[x] ^= (uint8_t)(fuzz_pilot >> 5);
        }
    }
}

/* padding_frame_fuzzer: MODIFIED for Handshake Done tracking */
void padding_frame_fuzzer(picoquic_cnx_t* cnx, fuzzer_icid_ctx_t* icid_ctx, uint64_t fuzz_pilot, uint8_t* bytes, uint8_t* bytes_max)
{
    size_t l = bytes_max - bytes;
    if (l == 0) return;

    /* HANDSHAKE_DONE tracking */
    if (icid_ctx != NULL && cnx != NULL && !picoquic_is_client(cnx) && bytes[0] == picoquic_frame_type_handshake_done) {
        icid_ctx->handshake_done_sent_by_server = 1;
    }

    int action_choice = fuzz_pilot % 3;
    fuzz_pilot >>= 2;

    if (action_choice == 0 && bytes[0] == picoquic_frame_type_padding && l > 1) {
        for (uint8_t* p = bytes + 1; p < bytes_max; p++) {
            if (fuzz_pilot == 0 && icid_ctx != NULL) {
                 fuzz_pilot = picoquic_test_random(&icid_ctx->random_context);
            } else if (fuzz_pilot == 0 && icid_ctx == NULL) {
                 fuzz_pilot = bytes[0] ^ 0xFF; /* Basic replenishment if no context */
            }
            if ((fuzz_pilot & 0x03) == 0) {
                *p = (uint8_t)((fuzz_pilot >> 2) % 255) + 1;
            }
            fuzz_pilot >>= 4;
        }
    } else if (action_choice == 1) {
        int fuzz_type_decision = 1;
        if (l > 1) {
            fuzz_type_decision = (fuzz_pilot & 7) == 0;
            fuzz_pilot >>= 3;
        }

        if (fuzz_type_decision) {
            int flip = fuzz_pilot & 1;
            fuzz_pilot >>=1;

            switch (bytes[0]) {
            case picoquic_frame_type_padding:
                bytes[0] = (flip) ? picoquic_frame_type_ping : picoquic_frame_type_handshake_done;
                break;
            case picoquic_frame_type_ping:
                bytes[0] = (flip) ? picoquic_frame_type_padding : picoquic_frame_type_handshake_done;
                break;
            case picoquic_frame_type_handshake_done:
                bytes[0] = (flip) ? picoquic_frame_type_ping : picoquic_frame_type_padding;
                break;
            default:
                bytes[0] ^= (uint8_t)(fuzz_pilot & 0xFF);
                break;
            }
        }
    } else {
        if (bytes[0] == picoquic_frame_type_padding || l > 1) {
            struct st_insert_t {
                uint8_t i_type;
                uint8_t i_count;
            } insert_table[] = {
                { picoquic_frame_type_max_data, 2 },
                { picoquic_frame_type_data_blocked, 2 },
                { picoquic_frame_type_streams_blocked_bidir, 2 },
                { picoquic_frame_type_streams_blocked_unidir, 2 },
                { picoquic_frame_type_retire_connection_id, 2 },
                { picoquic_frame_type_stream_data_blocked, 3 },
                { picoquic_frame_type_stop_sending, 3 },
                { picoquic_frame_type_max_stream_data, 3 },
                { picoquic_frame_type_max_streams_bidir, 3 },
                { picoquic_frame_type_max_streams_unidir, 3 },
                { picoquic_frame_type_reset_stream, 4 }
            };
            size_t insert_table_size = sizeof(insert_table) / sizeof(struct st_insert_t);
            size_t x_i;
            size_t x_m = insert_table_size;
            do {
                if (x_m == 0) { x_i = 0; break;} /* Avoid modulo by zero if table is empty or l is too small for all entries */
                x_i = fuzz_pilot % x_m;
                x_m = x_i;
            } while (x_i > 0 && insert_table[x_i].i_count > l);

            if(insert_table[x_i].i_count <= l) { /* Ensure selected frame fits */
                bytes[0] = insert_table[x_i].i_type;
                fuzz_pilot >>= 4;
                varint_frame_fuzzer(fuzz_pilot, bytes, bytes_max, insert_table[x_i].i_count);
            }
        }
    }
}

void new_token_frame_fuzzer(uint64_t fuzz_pilot, uint8_t* frame_start, uint8_t* bytes_max)
{
    uint8_t* token_len_varint_start;
    uint8_t* token_data_start;
    uint64_t actual_token_length_val;

    token_len_varint_start = (uint8_t*)picoquic_frames_varint_skip(frame_start, bytes_max);

    if (token_len_varint_start == NULL || token_len_varint_start >= bytes_max) {
        if (frame_start < bytes_max) {
            fuzz_random_byte(fuzz_pilot, frame_start, bytes_max);
        }
        return;
    }

    token_data_start = (uint8_t*)picoquic_frames_varint_decode(token_len_varint_start, bytes_max, &actual_token_length_val);

    if (token_data_start == NULL) {
        fuzz_in_place_or_skip_varint(fuzz_pilot, token_len_varint_start, bytes_max, 1);
        return;
    }

    int choice = fuzz_pilot % 4;
    fuzz_pilot >>= 2;

    switch (choice) {
    case 0:
        {
            int len_choice = fuzz_pilot % 4;
            fuzz_pilot >>= 2;

            switch (len_choice) {
            case 0: case 1: case 2: /* Fall through to general fuzz for simplicity */
                 fuzz_in_place_or_skip_varint(fuzz_pilot, token_len_varint_start, bytes_max, 1);
                 return; /* Return after this attempt */
            default:
                {
                    uint8_t* temp_len_end = (uint8_t*)picoquic_frames_varint_skip(token_len_varint_start, bytes_max);
                    if (temp_len_end > token_len_varint_start) { /* Check if varint has any length */
                        size_t len_varint_byte_len = temp_len_end - token_len_varint_start;
                        token_len_varint_start[0] |= 0x3F;
                        for (size_t i = 1; i < len_varint_byte_len; i++) {
                            token_len_varint_start[i] = 0xFF;
                        }
                    }
                    return;
                }
            }
        }
        break; /* Should be unreachable due to returns in case 0 */

    case 3:
        fuzz_in_place_or_skip_varint(fuzz_pilot, token_len_varint_start, bytes_max, 1);
        break;

    case 1:
        if (token_data_start < bytes_max && actual_token_length_val > 0) {
            uint8_t* effective_token_data_end = token_data_start + actual_token_length_val;
            if (effective_token_data_end > bytes_max) {
                effective_token_data_end = bytes_max;
            }
            if (token_data_start < effective_token_data_end) {
                uint8_t pattern = 0x00;
                int pattern_choice = fuzz_pilot % 3;
                fuzz_pilot >>= 2;
                if (pattern_choice == 0) pattern = 0x00;
                else if (pattern_choice == 1) pattern = 0xFF;
                else pattern = 0xA5;
                memset(token_data_start, pattern, effective_token_data_end - token_data_start);
            }
        }
        break;

    case 2:
        if (token_data_start < bytes_max && actual_token_length_val > 0) {
            uint8_t* effective_token_data_end = token_data_start + actual_token_length_val;
            if (effective_token_data_end > bytes_max) {
                effective_token_data_end = bytes_max;
            }
            if (token_data_start < effective_token_data_end) {
                fuzz_random_byte(fuzz_pilot, token_data_start, effective_token_data_end);
            }
        }
        break;
    }
}

void new_connection_id_frame_fuzzer_logic(uint64_t fuzz_pilot, uint8_t* frame_start, uint8_t* frame_max, fuzzer_icid_ctx_t* icid_ctx)
{
    uint8_t* p = frame_start;
    int specific_fuzz_applied = 0;

    p = (uint8_t*)picoquic_frames_varint_skip(p, frame_max);
    if (p == NULL || p >= frame_max) {
        default_frame_fuzzer(fuzz_pilot, frame_start, frame_max);
        return;
    }

    uint8_t* seq_no_start = p;
    uint64_t original_seq_no;
    uint8_t* seq_no_end = (uint8_t*)picoquic_frames_varint_decode(seq_no_start, frame_max, &original_seq_no);
    if (seq_no_end == NULL || seq_no_start == seq_no_end) {
        default_frame_fuzzer(fuzz_pilot, frame_start, frame_max);
        return;
    }

    if (icid_ctx != NULL) {
        icid_ctx->last_new_cid_seq_no_sent = original_seq_no;
        icid_ctx->new_cid_seq_no_available = 1;
    }

    uint8_t* retire_prior_to_start = seq_no_end;
    uint64_t original_retire_prior_to;
    uint8_t* retire_prior_to_end = (uint8_t*)picoquic_frames_varint_decode(retire_prior_to_start, frame_max, &original_retire_prior_to);
    if (retire_prior_to_end == NULL || retire_prior_to_start == retire_prior_to_end) {
        default_frame_fuzzer(fuzz_pilot, frame_start, frame_max);
        return;
    }

    uint8_t* length_field_ptr = retire_prior_to_end;
    if (length_field_ptr >= frame_max) {
        default_frame_fuzzer(fuzz_pilot, frame_start, frame_max);
        return;
    }
    uint8_t original_cid_len = *length_field_ptr;

    uint8_t* cid_start = length_field_ptr + 1;
    if (cid_start + original_cid_len > frame_max) {
        default_frame_fuzzer(fuzz_pilot, frame_start, frame_max);
        return;
    }
    uint8_t* token_start = cid_start + original_cid_len;
    if (token_start + PICOQUIC_STATELESS_RESET_TOKEN_SIZE > frame_max) {
        default_frame_fuzzer(fuzz_pilot, frame_start, frame_max);
        return;
    }

    if ((fuzz_pilot % 3) == 0) {
        fuzz_pilot >>=2;

        int target_choice = fuzz_pilot % 5;
        fuzz_pilot >>= 3;

        switch (target_choice) {
        case 0:
            {
                uint64_t new_seq_val;
                int val_choice = fuzz_pilot % 3;
                if (val_choice == 0) new_seq_val = 0;
                else if (val_choice == 1) new_seq_val = 0x3FFF;
                else new_seq_val = fuzz_pilot % 16;

                if (encode_and_overwrite_varint(seq_no_start, seq_no_end, frame_max, new_seq_val)) {
                    specific_fuzz_applied = 1;
                }
            }
            break;
        case 1:
            {
                uint64_t new_retire_val;
                int val_choice = fuzz_pilot % 3;
                if (val_choice == 0) new_retire_val = original_seq_no;
                else if (val_choice == 1) new_retire_val = 0;
                else new_retire_val = (original_seq_no > 0) ? (original_seq_no - 1) : 0;

                if (encode_and_overwrite_varint(retire_prior_to_start, retire_prior_to_end, frame_max, new_retire_val)) {
                    specific_fuzz_applied = 1;
                }
            }
            break;
        case 2:
            {
                int val_choice = fuzz_pilot % 3;
                if (val_choice == 0) *length_field_ptr = 0;
                else if (val_choice == 1) *length_field_ptr = PICOQUIC_CONNECTION_ID_MAX_SIZE;
                else *length_field_ptr = PICOQUIC_CONNECTION_ID_MAX_SIZE + 1;
                specific_fuzz_applied = 1;
            }
            break;
        case 3:
            if (original_cid_len > 0) {
                int flips = 1 + (fuzz_pilot % 2);
                for (int i = 0; i < flips; i++) {
                    if (original_cid_len == 0) break;
                    size_t idx = (fuzz_pilot >> (i*4)) % original_cid_len;
                    cid_start[idx] ^= (uint8_t)((fuzz_pilot >> (i*8 + 3)) & 0xFF);
                }
                specific_fuzz_applied = 1;
            }
            break;
        case 4:
            {
                int flips = 1 + (fuzz_pilot % 2);
                 for (int i = 0; i < flips; i++) {
                    size_t idx = (fuzz_pilot >> (i*4)) % PICOQUIC_STATELESS_RESET_TOKEN_SIZE;
                    token_start[idx] ^= (uint8_t)((fuzz_pilot >> (i*8 + 3)) & 0xFF);
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

void new_cid_frame_fuzzer(uint64_t fuzz_pilot, uint8_t* bytes, uint8_t* bytes_max)
{
    default_frame_fuzzer(fuzz_pilot, bytes, bytes_max);
}

void retire_connection_id_frame_fuzzer(uint64_t fuzz_pilot, uint8_t* bytes, uint8_t* frame_max)
{
    uint8_t* frame_payload_start = (uint8_t*)picoquic_frames_varint_skip(bytes, frame_max);

    if (frame_payload_start == NULL || frame_payload_start >= frame_max) {
        if (bytes < frame_max) {
            fuzz_random_byte(fuzz_pilot, bytes, frame_max);
        }
        return;
    }

    uint8_t* seq_num_start = frame_payload_start;
    uint64_t original_seq_no;
    uint8_t* seq_num_end = (uint8_t*)picoquic_frames_varint_decode(seq_num_start, frame_max, &original_seq_no);

    if (seq_num_end == NULL || seq_num_start == seq_num_end) {
      fuzz_in_place_or_skip_varint(fuzz_pilot >> 2, seq_num_start, frame_max, 1);
      return;
    }

    int choice = fuzz_pilot % 4;
    fuzz_pilot >>= 2;

    size_t varint_len = seq_num_end - seq_num_start;

    if (varint_len == 0 && choice !=3) {
        choice = 3;
    }

    switch (choice) {
    case 0:
        if (varint_len > 0) {
            uint8_t prefix = seq_num_start[0] & 0xC0;
            seq_num_start[0] = prefix;
            for (size_t i = 1; i < varint_len; i++) {
                seq_num_start[i] = 0x00;
            }
        }
        break;
    case 1:
        if (varint_len > 0) {
            uint8_t prefix = seq_num_start[0] & 0xC0;
            if (varint_len == 1) {
                seq_num_start[0] = prefix | 0x01;
            } else {
                seq_num_start[0] = prefix;
                for (size_t i = 1; i < varint_len -1; i++) {
                    seq_num_start[i] = 0x00;
                }
                seq_num_start[varint_len - 1] = 0x01;
            }
        }
        break;
    case 2:
        if (varint_len > 0) {
            seq_num_start[0] |= 0x3F;
            for (size_t i = 1; i < varint_len; i++) {
                seq_num_start[i] = 0xFF;
            }
        }
        break;
    default:
        if ((fuzz_pilot & 0x03) == 0) {
            fuzz_pilot >>=2;
            uint64_t small_seq_val = fuzz_pilot % 16;
            if (!encode_and_overwrite_varint(seq_num_start, seq_num_end, frame_max, small_seq_val)) {
                 fuzz_in_place_or_skip_varint(fuzz_pilot >> 4, seq_num_start, frame_max, 1);
            }
        } else {
            fuzz_in_place_or_skip_varint(fuzz_pilot >> 2, seq_num_start, frame_max, 1);
        }
        break;
    }
}

static int encode_and_overwrite_varint(uint8_t* field_start, uint8_t* field_end, uint8_t* frame_max, uint64_t new_value)
{
    if (field_start == NULL || field_end == NULL || field_start >= field_end || field_start >= frame_max) {
        return 0;
    }

    size_t original_varint_len = field_end - field_start;
    uint8_t temp_buffer[16];
    uint8_t* p_next_byte_in_temp;
    size_t encoded_len;

    // Use the standard picoquic_frames_varint_encode
    p_next_byte_in_temp = picoquic_frames_varint_encode(temp_buffer, temp_buffer + sizeof(temp_buffer), new_value);

    if (p_next_byte_in_temp == NULL) {
        // This indicates an encoding failure by picoquic_frames_varint_encode.
        // This shouldn't happen with a 16-byte temp_buffer for any valid uint64_t varint.
        return 0; 
    }

    encoded_len = p_next_byte_in_temp - temp_buffer;

    if (encoded_len == 0) {
        // This case implies picoquic_frames_varint_encode returned `temp_buffer` without writing,
        // or new_value itself implies a zero-length encoding (not standard for varints).
        // picoquic_frames_varint_encode should correctly produce encoded_len = 1 for new_value = 0.
        // Thus, encoded_len == 0 here is an actual error or unexpected behavior.
        return 0;
    }

    size_t new_varint_len = encoded_len;

    if (new_varint_len <= original_varint_len) {
        memcpy(field_start, temp_buffer, new_varint_len);
        if (new_varint_len < original_varint_len) {
            memset(field_start + new_varint_len, 0, original_varint_len - new_varint_len);
        }
        return 1;
    }
    return 0;
}

void path_abandon_frame_fuzzer(uint64_t fuzz_pilot, uint8_t* frame_start, uint8_t* bytes_max)
{
    uint8_t* p = frame_start;
    uint64_t frame_type;
    int specific_fuzz_done = 0;

    p = (uint8_t*)picoquic_frames_varint_decode(p, bytes_max, &frame_type);
    if (p == NULL || p >= bytes_max) {
        default_frame_fuzzer(fuzz_pilot, frame_start, bytes_max);
        return;
    }

    uint8_t* path_id_start = p;
    uint64_t original_path_id;
    uint8_t* path_id_end = (uint8_t*)picoquic_frames_varint_decode(path_id_start, bytes_max, &original_path_id);

    if (path_id_end == NULL || path_id_start == path_id_end) {
        default_frame_fuzzer(fuzz_pilot, frame_start, bytes_max);
        return;
    }

    uint8_t* error_code_start = path_id_end;
    uint64_t original_error_code;
    uint8_t* error_code_end = (uint8_t*)picoquic_frames_varint_decode(error_code_start, bytes_max, &original_error_code);

    if (error_code_end == NULL || error_code_start == error_code_end) {
         error_code_start = NULL;
         error_code_end = NULL;
    }

    if ((fuzz_pilot & 0x03) == 0) {
        fuzz_pilot >>= 2;
        int fuzz_target_choice = fuzz_pilot % 2;
        fuzz_pilot >>= 1;

        if (fuzz_target_choice == 0) {
            if (path_id_start != NULL && path_id_end != NULL) {
                uint64_t new_path_id_val = ((fuzz_pilot >> 1) & 1) ? 0x3FFFFFFFFFFFFFFF : 0;
                if (encode_and_overwrite_varint(path_id_start, path_id_end, bytes_max, new_path_id_val)) {
                    specific_fuzz_done = 1;
                }
            }
        } else {
            if (error_code_start != NULL && error_code_end != NULL) {
                uint64_t new_error_code_val;
                int error_choice = fuzz_pilot % 3;
                fuzz_pilot >>= 2;
                if (error_choice == 0) {
                    new_error_code_val = 0;
                } else if (error_choice == 1) {
                    new_error_code_val = PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR;
                } else {
                    new_error_code_val = 0x3FFFFFFFFFFFFFFF;
                }
                if (encode_and_overwrite_varint(error_code_start, error_code_end, bytes_max, new_error_code_val)) {
                    specific_fuzz_done = 1;
                }
            }
        }
    }

    if (!specific_fuzz_done) {
        uint8_t* current_field = frame_start;
        current_field = (uint8_t*)picoquic_frames_varint_skip(current_field, bytes_max);

        if (current_field != NULL && current_field < bytes_max) {
            current_field = fuzz_in_place_or_skip_varint(fuzz_pilot, current_field, bytes_max, 1);
            fuzz_pilot >>= 8;
        }
        if (current_field != NULL && current_field < bytes_max) {
            fuzz_in_place_or_skip_varint(fuzz_pilot, current_field, bytes_max, 1);
        }
    }
}

void crypto_frame_fuzzer_logic(uint64_t fuzz_pilot, uint8_t* frame_start, uint8_t* frame_max, fuzzer_ctx_t* ctx, fuzzer_icid_ctx_t* icid_ctx)
{
    uint8_t* p = frame_start;
    int specific_fuzz_applied = 0;

    p = (uint8_t*)picoquic_frames_varint_skip(p, frame_max);
    if (p == NULL || p >= frame_max) {
        default_frame_fuzzer(fuzz_pilot, frame_start, frame_max);
        return;
    }

    uint8_t* offset_start = p;
    uint64_t original_offset;
    uint8_t* offset_end = (uint8_t*)picoquic_frames_varint_decode(offset_start, frame_max, &original_offset);
    if (offset_end == NULL || offset_start == offset_end) {
        default_frame_fuzzer(fuzz_pilot, frame_start, frame_max);
        return;
    }

    uint8_t* length_start = offset_end;
    uint64_t original_length;
    uint8_t* length_end = (uint8_t*)picoquic_frames_varint_decode(length_start, frame_max, &original_length);
    if (length_end == NULL || length_start == length_end) {
        default_frame_fuzzer(fuzz_pilot, frame_start, frame_max);
        return;
    }

    uint8_t* data_start = length_end;
    size_t data_present_len = 0;
    if (data_start < frame_max) {
        data_present_len = frame_max - data_start;
    }

    if ((fuzz_pilot & 0x01) == 0) {
        fuzz_pilot >>= 1;
        int choice = fuzz_pilot % 4;
        fuzz_pilot >>= 2;

        switch (choice) {
        case 0:
            if (offset_start && offset_end) {
                uint64_t new_offset_val = (fuzz_pilot & 1) ? 0x3FFFFFFFFFFFFFFF : 0;
                if (encode_and_overwrite_varint(offset_start, offset_end, frame_max, new_offset_val)) {
                    specific_fuzz_applied = 1;
                }
            }
            break;
        case 1:
            if (length_start && length_end) {
                uint64_t new_length_val = (fuzz_pilot & 1) ? 0x3FFFFFFFFFFFFFFF : 65536;
                if (encode_and_overwrite_varint(length_start, length_end, frame_max, new_length_val)) {
                    specific_fuzz_applied = 1;
                }
            }
            break;
        case 2:
            if (length_start && length_end) {
                if (encode_and_overwrite_varint(length_start, length_end, frame_max, 0)) {
                    specific_fuzz_applied = 1;
                }
            }
            break;
        case 3:
            if (data_present_len > 0) {
                size_t num_flips = 1 + (fuzz_pilot % 3);
                fuzz_pilot >>= 2;
                for (size_t i = 0; i < num_flips; i++) {
                    if (data_present_len == 0) break;
                    size_t flip_idx = fuzz_pilot % data_present_len;
                    if (icid_ctx == NULL && fuzz_pilot == 0) {
                        fuzz_pilot = frame_start[0];
                    } else if (fuzz_pilot == 0 && icid_ctx != NULL) {
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

void path_id_sequence_frame_fuzzer(uint64_t fuzz_pilot, uint8_t* frame_start, uint8_t* frame_max)
{
    uint8_t* p = frame_start;
    uint64_t frame_type;
    int specific_fuzz_done = 0;

    p = (uint8_t*)picoquic_frames_varint_decode(p, frame_max, &frame_type);
    if (p == NULL || p >= frame_max) {
        default_frame_fuzzer(fuzz_pilot, frame_start, frame_max);
        return;
    }

    uint8_t* path_id_start = p;
    uint64_t original_path_id;
    uint8_t* path_id_end = (uint8_t*)picoquic_frames_varint_decode(path_id_start, frame_max, &original_path_id);

    if (path_id_end == NULL || path_id_start == path_id_end) {
        default_frame_fuzzer(fuzz_pilot, frame_start, frame_max);
        return;
    }

    uint8_t* seq_no_start = path_id_end;
    uint64_t original_seq_no;
    uint8_t* seq_no_end = (uint8_t*)picoquic_frames_varint_decode(seq_no_start, frame_max, &original_seq_no);

    if (seq_no_end == NULL || seq_no_start == seq_no_end) {
        seq_no_start = NULL;
        seq_no_end = NULL;
    }

    int choice = fuzz_pilot % 3;
    fuzz_pilot >>= 2;

    if (choice == 0) {
        if (path_id_start && path_id_end) {
            uint64_t new_path_id_val = (fuzz_pilot & 1) ? 0x3FFFFFFFFFFFFFFF : 0;
            if (encode_and_overwrite_varint(path_id_start, path_id_end, frame_max, new_path_id_val)) {
                specific_fuzz_done = 1;
            }
        }
    } else if (choice == 1) {
        if (seq_no_start && seq_no_end) {
            uint64_t new_seq_no_val = (fuzz_pilot & 1) ? 0x3FFFFFFFFFFFFFFF : 0;
            if (encode_and_overwrite_varint(seq_no_start, seq_no_end, frame_max, new_seq_no_val)) {
                specific_fuzz_done = 1;
            }
        }
    }

    if (!specific_fuzz_done) {
        default_frame_fuzzer(fuzz_pilot, frame_start, frame_max);
    }
}

void default_frame_fuzzer(uint64_t fuzz_pilot, uint8_t* bytes, uint8_t* bytes_max)
{
    uint8_t* frame_byte = bytes;

    bytes = (uint8_t *)picoquic_frames_varint_skip(bytes, bytes_max);

    if (bytes == NULL || bytes >= bytes_max) {
        bytes = frame_byte;
    }
    if (bytes < bytes_max && bytes + 8 < bytes_max) { /* Check if there are 8 bytes to fuzz */
        bytes_max = bytes + 8;
    } else if (bytes >= bytes_max && frame_byte < bytes_max) { /* If type was whole frame, fuzz type */
        bytes = frame_byte;
    }
    /* Ensure bytes < bytes_max before fuzzing */
    if (bytes < bytes_max) {
        fuzz_random_byte(fuzz_pilot, bytes, bytes_max);
    }
}

void max_data_fuzzer(uint64_t fuzz_pilot, uint8_t* frame_start, uint8_t* frame_max, fuzzer_ctx_t* f_ctx, fuzzer_icid_ctx_t* icid_ctx)
{
    uint8_t* original_varint_start = frame_start;
    uint8_t* p_val = original_varint_start;
    uint64_t original_max_data;
    uint8_t* original_varint_end;

    if (p_val < frame_max) {
        p_val++;
    } else {
        default_frame_fuzzer(fuzz_pilot >> 2, frame_start, frame_max);
        return;
    }
    original_varint_start = p_val;

    original_varint_end = (uint8_t*)picoquic_frames_varint_decode(p_val, frame_max, &original_max_data);

    if (original_varint_end != NULL && original_varint_start < original_varint_end) {
        if (icid_ctx != NULL) {
            icid_ctx->last_sent_max_data = original_max_data;
            icid_ctx->has_sent_max_data = 1;
        }

        if ((fuzz_pilot & 0x03) == 0) {
            if (icid_ctx != NULL && icid_ctx->has_sent_max_data && icid_ctx->last_sent_max_data > 0) {
                uint64_t fuzzed_val = icid_ctx->last_sent_max_data / 2;
                if (fuzzed_val == icid_ctx->last_sent_max_data && fuzzed_val > 0) {
                    fuzzed_val--;
                }

                int fuzzed_varint_len = picoquic_varint_encode_length(fuzzed_val);
                size_t original_varint_len = original_varint_end - original_varint_start;

                if (fuzzed_varint_len <= original_varint_len) {
                    picoquic_varint_encode(original_varint_start, (size_t)(frame_max - original_varint_start), fuzzed_val);
                    if (fuzzed_varint_len < original_varint_len) {
                        size_t padding_len = original_varint_len - fuzzed_varint_len;
                        if (original_varint_start + fuzzed_varint_len + padding_len <= frame_max) {
                           memset(original_varint_start + fuzzed_varint_len, 0, padding_len);
                        }
                    }
                }
                default_frame_fuzzer(fuzz_pilot >> 2, frame_start, frame_max);
                return;
            }
        }
    }
    default_frame_fuzzer(fuzz_pilot >> 2, frame_start, frame_max);
}

/* frame_header_fuzzer: MODIFIED signature */
int frame_header_fuzzer(fuzzer_ctx_t* f_ctx, picoquic_cnx_t* cnx, fuzzer_icid_ctx_t* icid_ctx, uint64_t fuzz_pilot,
    uint8_t* bytes, size_t bytes_max, size_t length, size_t header_length)
{
    uint8_t* frame_head[FUZZER_MAX_NB_FRAMES];
    uint8_t* frame_next[FUZZER_MAX_NB_FRAMES];
    uint8_t* last_byte = bytes + bytes_max;
    size_t nb_frames = 0;
    int was_fuzzed = 1;

    bytes += header_length;

    while (bytes != NULL && bytes < last_byte && nb_frames < FUZZER_MAX_NB_FRAMES) {
        size_t consumed = 0;
        int is_pure_ack = 1;
        frame_head[nb_frames] = bytes;
        if (picoquic_skip_frame(bytes, (size_t)(last_byte - bytes), &consumed, &is_pure_ack) == 0) {
            bytes += consumed;
            frame_next[nb_frames] = bytes;
            nb_frames++;
        }
        else {
            frame_next[nb_frames] = last_byte;
            bytes = NULL;
        }
    }

    if (nb_frames > 0) {
        size_t fuzzed_frame_idx = (size_t)(fuzz_pilot % nb_frames);
        uint8_t* frame_byte = frame_head[fuzzed_frame_idx];
        uint8_t* frame_max = frame_next[fuzzed_frame_idx];

        fuzz_pilot >>= 5;

        /* HANDSHAKE_DONE tracking moved here */
        if (cnx != NULL && !picoquic_is_client(cnx) && icid_ctx != NULL && *frame_byte == picoquic_frame_type_handshake_done) {
            icid_ctx->handshake_done_sent_by_server = 1;
        }

        if (PICOQUIC_IN_RANGE(*frame_byte, picoquic_frame_type_stream_range_min, picoquic_frame_type_stream_range_max)) {
            stream_frame_fuzzer(fuzz_pilot, frame_byte, frame_max);
        }
        else {
            switch (*frame_byte) {
            case picoquic_frame_type_ack:
            case picoquic_frame_type_ack_ecn:
                ack_frame_fuzzer(fuzz_pilot, frame_byte, frame_max);
                break;
            case picoquic_frame_type_reset_stream:
                varint_frame_fuzzer(fuzz_pilot, frame_byte, frame_max, 4);
                break;
            case picoquic_frame_type_stop_sending:
                varint_frame_fuzzer(fuzz_pilot, frame_byte, frame_max, 3);
                break;
            case picoquic_frame_type_max_data:
                max_data_fuzzer(fuzz_pilot, frame_byte, frame_max, f_ctx, icid_ctx);
                break;
            case picoquic_frame_type_max_stream_data:
                varint_frame_fuzzer(fuzz_pilot, frame_byte, frame_max, 3);
                break;
            case picoquic_frame_type_max_streams_bidir:
            case picoquic_frame_type_max_streams_unidir:
                varint_frame_fuzzer(fuzz_pilot, frame_byte, frame_max, 2);
                break;
            case picoquic_frame_type_data_blocked:
                varint_frame_fuzzer(fuzz_pilot, frame_byte, frame_max, 2);
                break;
            case picoquic_frame_type_stream_data_blocked:
                varint_frame_fuzzer(fuzz_pilot, frame_byte, frame_max, 3);
                break;
            case picoquic_frame_type_streams_blocked_bidir:
            case picoquic_frame_type_streams_blocked_unidir:
                varint_frame_fuzzer(fuzz_pilot, frame_byte, frame_max, 2);
                break;
            case picoquic_frame_type_retire_connection_id:
                retire_connection_id_frame_fuzzer(fuzz_pilot, frame_byte, frame_max);
                break;
            case picoquic_frame_type_connection_close:
            case picoquic_frame_type_application_close:
                varint_frame_fuzzer(fuzz_pilot, frame_byte, frame_max, 4);
                break;
            case picoquic_frame_type_datagram:
            case picoquic_frame_type_datagram_l:
                datagram_frame_fuzzer(f_ctx, icid_ctx, fuzz_pilot, frame_byte, frame_max);
                break;
            case picoquic_frame_type_path_challenge:
            case picoquic_frame_type_path_response:
                challenge_frame_fuzzer(fuzz_pilot, frame_byte, frame_max);
                break;
            case picoquic_frame_type_crypto_hs:
                crypto_frame_fuzzer_logic(fuzz_pilot, frame_byte, frame_max, f_ctx, icid_ctx);
                break;
            case picoquic_frame_type_padding:
            case picoquic_frame_type_ping:
            case picoquic_frame_type_handshake_done:
                /* Pass cnx and icid_ctx for HANDSHAKE_DONE tracking and random replenishment */
                padding_frame_fuzzer(cnx, icid_ctx, fuzz_pilot, frame_byte, frame_max);
                break;
            case picoquic_frame_type_new_connection_id:
                new_connection_id_frame_fuzzer_logic(fuzz_pilot, frame_byte, frame_max, icid_ctx);
                break;
            case picoquic_frame_type_new_token:
                new_token_frame_fuzzer(fuzz_pilot, frame_byte, frame_max);
                break;
            default: {
                uint64_t frame_id64;
                if (picoquic_frames_varint_decode(frame_byte, frame_max, &frame_id64) != NULL) {
                    switch (frame_id64) {
                    case picoquic_frame_type_ack_frequency:
                        ack_frequency_frame_fuzzer(fuzz_pilot, frame_byte, frame_max);
                        break;
                    case picoquic_frame_type_time_stamp:
                        varint_frame_fuzzer(fuzz_pilot, frame_byte, frame_max, 2);
                        break;
                    case picoquic_frame_type_path_abandon:
                        path_abandon_frame_fuzzer(fuzz_pilot, frame_byte, frame_max);
                        break;
                    case picoquic_frame_type_path_available:
                    case picoquic_frame_type_path_backup:
                        path_id_sequence_frame_fuzzer(fuzz_pilot, frame_byte, frame_max);
                        break;
                    case picoquic_frame_type_paths_blocked:
                        varint_frame_fuzzer(fuzz_pilot, frame_byte, frame_max, 2);
                        break;
                    case picoquic_frame_type_bdp:
                        varint_frame_fuzzer(fuzz_pilot, frame_byte, frame_max, 5);
                        break;
                    default:
                        default_frame_fuzzer(fuzz_pilot, frame_byte, frame_max);
                        break;
                    }
                } else {
                     default_frame_fuzzer(fuzz_pilot, frame_byte, frame_max);
                }
                break;
            }
            }
        }
    } else {
        was_fuzzed = 0;
    }

    return was_fuzzed;
}

size_t length_non_padded(uint8_t* bytes, size_t length, size_t header_length)
{
    uint8_t* bytes_begin = bytes;
    uint8_t* bytes_last = bytes + length;
    uint8_t* final_pad = NULL;
    bytes += header_length;
    while (bytes != NULL && bytes < bytes_last) {
        if (*bytes == picoquic_frame_type_padding) {
            final_pad = bytes;
            do {
                bytes++;
            } while (bytes < bytes_last && *bytes == picoquic_frame_type_padding);
            if (bytes < bytes_last) {
                final_pad = NULL;
            }
        }
        else{
            size_t consumed = 0;
            int is_pure_ack = 0;

            if (picoquic_skip_frame(bytes, (size_t)(bytes_last - bytes), &consumed, &is_pure_ack) != 0) {
                bytes = NULL;
            }
            else {
                bytes += consumed;
            }
        }
    }

    return (final_pad == NULL) ? length : (final_pad - bytes_begin);
}

size_t version_negotiation_packet_fuzzer(uint64_t fuzz_pilot, uint8_t* bytes, size_t vn_header_len, size_t current_length, size_t bytes_max)
{
    size_t original_current_length = current_length;

    if (vn_header_len > current_length || vn_header_len > bytes_max) {
        return current_length;
    }

    uint8_t* version_list_start = bytes + vn_header_len;
    size_t version_list_len = current_length - vn_header_len;

    if (version_list_len % 4 != 0) {
        return current_length;
    }
    size_t num_versions = version_list_len / 4;

    int choice = fuzz_pilot % 16;
    fuzz_pilot >>= 4;

    switch (choice) {
    case 0:
        if (vn_header_len > 0) {
            bytes[0] ^= (uint8_t)(fuzz_pilot & 0x3F);
        }
        break;
    case 1: break;
    case 2:
        if (vn_header_len <= bytes_max) {
            current_length = vn_header_len;
        }
        break;
    case 3:
        if (num_versions > 0) {
            size_t bytes_to_remove = (fuzz_pilot % 3) + 1;
            fuzz_pilot >>= 2;
            if (current_length > vn_header_len + bytes_to_remove) {
                current_length -= bytes_to_remove;
            } else if (current_length > vn_header_len) {
                current_length = vn_header_len;
            }
        }
        break;
    case 4:
    case 5:
    case 6:
        if (num_versions > 0) {
            size_t version_idx = fuzz_pilot % num_versions;
            fuzz_pilot >>= 4;
            uint8_t* version_ptr = version_list_start + (version_idx * 4);

            if (version_ptr + 4 <= bytes + original_current_length) {
                if (choice == 4) {
                    picoquic_frames_uint32_encode(version_ptr, version_ptr + 4, 0x0A0A0A0A);
                } else if (choice == 5) {
                    picoquic_frames_uint32_encode(version_ptr, version_ptr + 4, 0x1A1A1A1A);
                } else {
                    version_ptr[0] ^= (uint8_t)(fuzz_pilot & 0xFF);
                    version_ptr[1] ^= (uint8_t)((fuzz_pilot >> 8) & 0xFF);
                    version_ptr[2] ^= (uint8_t)((fuzz_pilot >> 16) & 0xFF);
                    version_ptr[3] ^= (uint8_t)((fuzz_pilot >> 24) & 0xFF);
                }
            }
        }
        break;
    case 7:
        if (num_versions >= 2) {
            size_t v_idx_target = fuzz_pilot % num_versions;
            fuzz_pilot >>= 4;
            size_t v_idx_source = fuzz_pilot % num_versions;
            fuzz_pilot >>= 4;

            if (v_idx_target != v_idx_source) {
                uint8_t* target_ptr = version_list_start + (v_idx_target * 4);
                uint8_t* source_ptr = version_list_start + (v_idx_source * 4);
                if (target_ptr + 4 <= bytes + original_current_length && source_ptr + 4 <= bytes + original_current_length) {
                    memcpy(target_ptr, source_ptr, 4);
                }
            }
        }
        break;
    case 8:
        if (current_length + 4 <= bytes_max) {
            uint8_t* new_version_ptr = bytes + current_length;
            new_version_ptr[0] = (uint8_t)(fuzz_pilot & 0xFF);
            new_version_ptr[1] = (uint8_t)((fuzz_pilot >> 8) & 0xFF);
            new_version_ptr[2] = (uint8_t)((fuzz_pilot >> 16) & 0xFF);
            new_version_ptr[3] = (uint8_t)((fuzz_pilot >> 24) & 0xFF);
            current_length += 4;
        }
        break;
    case 9:
        if (num_versions >= 2) {
            size_t v_idx1 = fuzz_pilot % num_versions;
            fuzz_pilot >>= 4;
            size_t v_idx2 = fuzz_pilot % num_versions;
            fuzz_pilot >>= 4;

            if (v_idx1 != v_idx2) {
                uint8_t* ptr1 = version_list_start + (v_idx1 * 4);
                uint8_t* ptr2 = version_list_start + (v_idx2 * 4);
                if (ptr1 + 4 <= bytes + original_current_length && ptr2 + 4 <= bytes + original_current_length) {
                    uint32_t temp_version;
                    picoquic_frames_uint32_decode(ptr1, ptr1 + 4, &temp_version);
                    memcpy(ptr1, ptr2, 4);
                    picoquic_frames_uint32_encode(ptr2, ptr2 + 4, temp_version);
                }
            }
        }
        break;
    default:
        if (version_list_len > 0 && version_list_start < bytes + current_length ) {
            size_t fuzz_offset_in_list = fuzz_pilot % version_list_len;
            fuzz_pilot >>= 6;
            version_list_start[fuzz_offset_in_list] ^= (uint8_t)(fuzz_pilot & 0xFF);
        }
        break;
    }

    if (current_length < vn_header_len) {
        current_length = vn_header_len;
    }
    if (current_length > bytes_max) {
        current_length = bytes_max;
    }

    return current_length;
}

size_t retry_packet_fuzzer(uint64_t fuzz_pilot, uint8_t* bytes, size_t current_length, size_t bytes_max)
{
    size_t original_length = current_length;
    if (current_length < 23) {
        return current_length;
    }

    uint8_t dcid_len = bytes[5];
    if (dcid_len > PICOQUIC_CONNECTION_ID_MAX_SIZE) {
        return current_length;
    }

    size_t scid_len_offset = 1 + 4 + 1 + dcid_len;
    if (scid_len_offset >= original_length) return current_length;

    uint8_t scid_len = bytes[scid_len_offset];
    if (scid_len > PICOQUIC_CONNECTION_ID_MAX_SIZE) {
        return current_length;
    }

    uint8_t* token_start = bytes + scid_len_offset + 1 + scid_len;
    uint8_t* integrity_tag_start = bytes + original_length - 16;

    if (token_start > integrity_tag_start) {
        return current_length;
    }
    size_t token_len = integrity_tag_start - token_start;

    int choice = fuzz_pilot % 16;
    fuzz_pilot >>= 4;

    switch (choice) {
    case 0: bytes[0] ^= (uint8_t)(fuzz_pilot & 0x0F); break;
    case 1: if (original_length >= 5) { bytes[1 + (fuzz_pilot % 4)] ^= (uint8_t)(fuzz_pilot >> 2); } break;
    case 2:
        if (token_len > 0) {
            size_t num_flips = 1 + (fuzz_pilot % 3);
            fuzz_pilot >>= 2;
            for (size_t i = 0; i < num_flips; i++) {
                if (token_len == 0) break;
                size_t flip_idx = fuzz_pilot % token_len;
                fuzz_pilot >>= (token_len > 1 ? picoquic_max_bits(token_len -1) : 1);
                token_start[flip_idx] ^= (uint8_t)(fuzz_pilot & 0xFF);
                fuzz_pilot >>= 8;
            }
        }
        break;
    case 3:
        {
            size_t num_flips = 1 + (fuzz_pilot % 4);
            fuzz_pilot >>= 2;
            for (size_t i = 0; i < num_flips; i++) {
                size_t flip_idx = fuzz_pilot % 16;
                fuzz_pilot >>= 4;
                integrity_tag_start[flip_idx] ^= (uint8_t)(fuzz_pilot & 0xFF);
                fuzz_pilot >>= 8;
            }
        }
        break;
    case 4:
        if (original_length > 23) {
            size_t cut_amount = 1 + (fuzz_pilot % 15);
            fuzz_pilot >>= 4;
            if (original_length > cut_amount) {
                 current_length = original_length - cut_amount;
                 if (current_length < (scid_len_offset + 1 + scid_len + token_len)) {
                     current_length = scid_len_offset + 1 + scid_len + token_len;
                 }
            }
        }
        break;
    case 5:
        if (token_len > 0) {
            size_t cut_amount = 1 + (fuzz_pilot % token_len);
            fuzz_pilot >>= (token_len > 1 ? picoquic_max_bits(token_len-1):1);
            current_length = (token_start - bytes) + (token_len - cut_amount);
        } else if (original_length > (scid_len_offset + 1 + scid_len)) {
            current_length = scid_len_offset + 1 + scid_len;
        }
        break;
    case 6:
        if (bytes_max > original_length) {
            size_t add_amount = 1 + (fuzz_pilot % 8);
            fuzz_pilot >>= 3;
            if (original_length + add_amount > bytes_max) {
                add_amount = bytes_max - original_length;
            }
            if (add_amount > 0) {
                for (size_t i = 0; i < add_amount; i++) {
                    bytes[original_length + i] = (uint8_t)(fuzz_pilot & 0xFF);
                    fuzz_pilot >>= (i % 2 == 0 ? 3: 5) ;
                }
                current_length = original_length + add_amount;

                if (original_length >= 16) {
                    uint8_t* original_tag_loc = bytes + original_length - 16;
                    if (original_tag_loc < bytes + current_length - 16) {
                         original_tag_loc[fuzz_pilot % 16] ^= (uint8_t)((fuzz_pilot>>4)&0xFF);
                    }
                }
            }
        }
        break;
    case 7: if (original_length > 5) bytes[5] = 0; break;
    case 8: if (scid_len_offset < original_length) bytes[scid_len_offset] = 0; break;
    default:
        {
            size_t header_and_cid_len = scid_len_offset + 1 + scid_len;
            if (header_and_cid_len > 0) {
                 size_t flip_idx = fuzz_pilot % header_and_cid_len;
                 if (flip_idx < original_length) {
                    bytes[flip_idx] ^= (uint8_t)((fuzz_pilot >> 6) & 0xFF);
                 }
            } else if (token_len > 0) {
                 size_t flip_idx = fuzz_pilot % token_len;
                 token_start[flip_idx] ^= (uint8_t)((fuzz_pilot >> 6) & 0xFF);
            }
        }
        break;
    }

    size_t min_hdr_len_for_retry = 1 + 4 + 1 + 0 + 1 + 0;
    if (current_length < min_hdr_len_for_retry + 16) {
        current_length = min_hdr_len_for_retry + 16;
    }
    if (current_length > bytes_max) {
        current_length = bytes_max;
    }
    return current_length;
}

fuzzer_cnx_state_enum fuzzer_get_cnx_state(picoquic_cnx_t* cnx)
{
    picoquic_state_enum cnx_state = picoquic_get_cnx_state(cnx);
    fuzzer_cnx_state_enum fuzz_cnx_state = fuzzer_cnx_state_initial;

    if (cnx_state == picoquic_state_ready) {
        fuzz_cnx_state = fuzzer_cnx_state_ready;
    }
    else if (cnx_state > picoquic_state_ready) {
        fuzz_cnx_state = fuzzer_cnx_state_closing;
    }
    else if (cnx_state >= picoquic_state_client_almost_ready) {
        fuzz_cnx_state = fuzzer_cnx_state_not_ready;
    }
    return fuzz_cnx_state;
}

/* fuzi_q_fuzzer: MODIFIED for Handshake Interruption */
uint32_t fuzi_q_fuzzer(void* fuzz_ctx_param, picoquic_cnx_t* cnx,
    uint8_t* bytes, size_t bytes_max, size_t length, size_t header_length)
{
    fuzzer_ctx_t* ctx = (fuzzer_ctx_t*)fuzz_ctx_param;
    uint64_t current_time = (cnx != NULL && cnx->quic != NULL) ? picoquic_get_quic_time(cnx->quic) : 0;
    fuzzer_icid_ctx_t* icid_ctx = (cnx != NULL) ? fuzzer_get_icid_ctx(ctx, &cnx->initial_cnxid, current_time) : NULL;

    if (icid_ctx == NULL) { /* Should ideally not happen if cnx is valid */
        return (uint32_t)length;
    }

    uint64_t fuzz_pilot = picoquic_test_random(&icid_ctx->random_context);
    fuzzer_cnx_state_enum fuzz_cnx_state = (cnx != NULL) ? fuzzer_get_cnx_state(cnx) : fuzzer_cnx_state_closing;
    uint32_t fuzzed_length = (uint32_t)length;

    /* VN Packet Fuzzing */
    if (length >= 5 && (bytes[0] & 0x80) != 0) {
        uint32_t version_val;
        /* Assuming 'bytes + 5' is a safe upper bound based on 'length >= 5' */
        picoquic_frames_uint32_decode(bytes + 1, bytes + 5, &version_val);
        if (version_val == 0x00000000) {
            if (!icid_ctx->already_fuzzed || ((fuzz_pilot & 0xf) <= 7)) {
                fuzz_pilot >>=4;
                uint8_t dcid_len = 0;
            uint8_t scid_len = 0;
            size_t vn_header_len = 1 + 4;
            if (length >= vn_header_len + 1) {
                dcid_len = bytes[vn_header_len];
                vn_header_len += 1 + dcid_len;
                if (length >= vn_header_len + 1) {
                    /* Corrected SCID len offset: after Type, Version, DCID Len, DCID */
                    scid_len = bytes[1 + 4 + 1 + dcid_len];
                    vn_header_len += 1 + scid_len;
                    if (vn_header_len <= length) {
                        if (vn_header_len < length) {
                            fuzzed_length = (uint32_t)version_negotiation_packet_fuzzer(fuzz_pilot, bytes, vn_header_len, length, bytes_max);
                        }
                        if (icid_ctx->already_fuzzed == 0) {
                            icid_ctx->already_fuzzed = 1;
                             ctx->nb_cnx_tried[icid_ctx->target_state] += 1;
                             ctx->nb_cnx_fuzzed[fuzz_cnx_state] += 1;
                        }
                        ctx->nb_packets_fuzzed[fuzz_cnx_state] +=1;
                        return fuzzed_length;
                    }
                }
            }
        }
        return (uint32_t)length;
        }
    }
    /* Retry Packet Fuzzing */
    else if (length >= 23 && (bytes[0] & 0xF0) == 0xF0) {
        int condition_met = 0;
        if (length < 5) {
            condition_met = 1;
        } else {
            /* length >= 5, safe to decode version */
            uint32_t version_val;
            /* Assuming 'bytes + 5' is a safe upper bound */
            picoquic_frames_uint32_decode(bytes + 1, bytes + 5, &version_val);
            if (version_val != 0x00000000) {
                condition_met = 1;
            }
        }
        if (condition_met) {
            if (!icid_ctx->already_fuzzed || ((fuzz_pilot & 0xf) <= 7)) {
                fuzz_pilot >>=4;
                fuzzed_length = (uint32_t)retry_packet_fuzzer(fuzz_pilot, bytes, length, bytes_max);
            if (icid_ctx->already_fuzzed == 0) {
                icid_ctx->already_fuzzed = 1;
                ctx->nb_cnx_tried[icid_ctx->target_state] += 1;
                ctx->nb_cnx_fuzzed[fuzz_cnx_state] += 1;
            }
            ctx->nb_packets_fuzzed[fuzz_cnx_state] +=1;
            return fuzzed_length;
            }
        }
        return (uint32_t)length;
    }

    int fuzz_again = ((fuzz_pilot & 0xf) <= 7);
    fuzz_pilot >>= 4; /* Consume bits for fuzz_again for main packet fuzzing */

    if (fuzz_cnx_state < 0 || fuzz_cnx_state >= fuzzer_cnx_state_max) {
        fuzz_cnx_state = fuzzer_cnx_state_closing;
    }

    if (icid_ctx->target_state < fuzzer_cnx_state_max && icid_ctx->target_state >= 0) {
        ctx->nb_packets++;
        ctx->nb_packets_state[fuzz_cnx_state] += 1;
        icid_ctx->wait_count[fuzz_cnx_state]++;

        if (!icid_ctx->already_fuzzed && fuzz_cnx_state != fuzzer_cnx_state_closing &&
            icid_ctx->wait_count[fuzz_cnx_state] > ctx->wait_max[fuzz_cnx_state]) {
            ctx->wait_max[fuzz_cnx_state] = icid_ctx->wait_count[fuzz_cnx_state];
        }

        if ((fuzz_cnx_state > icid_ctx->target_state ||
            (fuzz_cnx_state == icid_ctx->target_state &&
                icid_ctx->wait_count[fuzz_cnx_state] >= icid_ctx->target_wait)) &&
            (!icid_ctx->already_fuzzed || fuzz_again)) {

            uint64_t main_strategy_choice = fuzz_pilot & 0x0F; /* Now 4 bits for up to 16 strategies */
            fuzz_pilot >>= 4; /* Consume these 4 bits */

            size_t final_pad = length_non_padded(bytes, length, header_length);
            int fuzz_more = ((fuzz_pilot >> 8) & 1) > 0; /* This bit is now relative to already shifted pilot */
            int was_fuzzed = 0;
            uint64_t sub_fuzzer_pilot = fuzz_pilot; /* Default for strategies not using list */

            if (main_strategy_choice < 3) { /* Strategies 0, 1, 2: Inject from fuzi_q_frame_list */
                size_t fuzz_frame_id = (size_t)((fuzz_pilot) % nb_fuzi_q_frame_list);
                sub_fuzzer_pilot = fuzz_pilot >> 5; /* Consume fuzz_frame_id bits */

                size_t len = fuzi_q_frame_list[fuzz_frame_id].len;
                switch (main_strategy_choice) {
                case 0: /* Add random frame at end */
                    if (final_pad + len <= bytes_max) {
                        memcpy(&bytes[final_pad], fuzi_q_frame_list[fuzz_frame_id].val, len);
                        final_pad += len; was_fuzzed++;
                    }
                    break;
                case 1: /* Add random frame at beginning */
                     if (final_pad + len <= bytes_max && header_length + len <= final_pad) {
                        memmove(bytes + header_length + len, bytes + header_length, final_pad - header_length);
                        memcpy(&bytes[header_length], fuzi_q_frame_list[fuzz_frame_id].val, len);
                        final_pad += len; was_fuzzed++;
                    } else if (header_length + len <= bytes_max) {
                        memcpy(&bytes[header_length], fuzi_q_frame_list[fuzz_frame_id].val, len);
                        final_pad = header_length + len; was_fuzzed++;
                    }
                    break;
                case 2: /* Replace packet with random frame */
                    if (header_length + len <= bytes_max) {
                        memcpy(&bytes[header_length], fuzi_q_frame_list[fuzz_frame_id].val, len);
                        final_pad = header_length + len; was_fuzzed++;
                    }
                    break;
                }
            } else if (main_strategy_choice == 3) { /* Fill with PINGs */
                sub_fuzzer_pilot = fuzz_pilot; /* Use remaining pilot for frame_header_fuzzer */
                if (bytes_max > header_length) {
                    size_t current_pos = header_length;
                    size_t ping_count = 0;
                    size_t available_space = bytes_max - header_length;
                    size_t max_pings_to_add = (available_space > 256) ? 256 : available_space;
                    while (current_pos < (header_length + max_pings_to_add) && current_pos < bytes_max) {
                        bytes[current_pos++] = picoquic_frame_type_ping;
                        ping_count++;
                    }
                    final_pad = current_pos;
                    if (ping_count > 0) was_fuzzed++;
                }
            } else if (main_strategy_choice == 4 && cnx != NULL && picoquic_is_client(cnx) &&
                       fuzzer_get_cnx_state(cnx) < fuzzer_cnx_state_ready && header_length + 1 <= bytes_max) {
                /* Client sends HANDSHAKE_DONE */
                sub_fuzzer_pilot = fuzz_pilot;
                bytes[header_length] = picoquic_frame_type_handshake_done;
                final_pad = header_length + 1;
                was_fuzzed++;
            } else if (main_strategy_choice == 5 && cnx != NULL && !picoquic_is_client(cnx) &&
                       icid_ctx->handshake_done_sent_by_server == 1) {
                /* Server sends CRYPTO after HANDSHAKE_DONE */
                sub_fuzzer_pilot = fuzz_pilot;
                size_t crypto_frame_idx = 0; /* Find a crypto frame */
                int found_crypto = 0;
                for (size_t i = 0; i < nb_fuzi_q_frame_list; i++) {
                    if (fuzi_q_frame_list[i].val[0] == picoquic_frame_type_crypto_hs) { /* Assuming type is first byte */
                        crypto_frame_idx = i;
                        found_crypto = 1;
                        break;
                    }
                }
                if (found_crypto) {
                    size_t len = fuzi_q_frame_list[crypto_frame_idx].len;
                    if (header_length + len <= bytes_max) {
                        memcpy(&bytes[header_length], fuzi_q_frame_list[crypto_frame_idx].val, len);
                        final_pad = header_length + len;
                        was_fuzzed++;
                    }
                }
            } else { /* Other strategies or no specific action taken by main_strategy_choice */
                 sub_fuzzer_pilot = fuzz_pilot; /* Use remaining pilot */
            }

            if (was_fuzzed) {
                 fuzzed_length = (uint32_t)final_pad;
                 if (final_pad < length) {
                     memset(&bytes[final_pad], 0, length - final_pad);
                 }
            } else {
                fuzzed_length = (uint32_t)length;
            }

            if (!was_fuzzed || fuzz_more) {
                int fuzzed_by_header_fuzzer = 0;
                if (final_pad > header_length) {
                    fuzzed_by_header_fuzzer = frame_header_fuzzer(ctx, cnx, icid_ctx, sub_fuzzer_pilot, bytes, bytes_max, final_pad, header_length);
                }
                if (!fuzzed_by_header_fuzzer && !was_fuzzed) {
                    fuzzed_length = basic_packet_fuzzer(ctx, sub_fuzzer_pilot, bytes, bytes_max, length, header_length);
                } else if (fuzzed_by_header_fuzzer) {
                     was_fuzzed = 1;
                     fuzzed_length = (uint32_t)final_pad;
                }
            }

            if (((fuzz_pilot >> 20) & 0x03) == 0) {
                if (icid_ctx->new_cid_seq_no_available == 1) {
                    uint8_t retire_frame_buffer[24];
                    uint8_t* p_retire = retire_frame_buffer;
                    uint8_t* p_retire_max = retire_frame_buffer + sizeof(retire_frame_buffer);
                    p_retire = picoquic_frames_varint_encode(p_retire, p_retire_max, picoquic_frame_type_retire_connection_id);
                    if (p_retire != NULL) {
                        p_retire = picoquic_frames_varint_encode(p_retire, p_retire_max, icid_ctx->last_new_cid_seq_no_sent);
                    }
                    if (p_retire != NULL) {
                        size_t retire_len = p_retire - retire_frame_buffer;
                        size_t current_packet_end = fuzzed_length;
                        if (current_packet_end + retire_len <= bytes_max) {
                            memcpy(&bytes[current_packet_end], retire_frame_buffer, retire_len);
                            fuzzed_length = (uint32_t)(current_packet_end + retire_len);
                        }
                    }
                    icid_ctx->new_cid_seq_no_available = 0;
                }
            }

            if (icid_ctx->already_fuzzed == 0) {
                icid_ctx->already_fuzzed = 1;
                ctx->nb_cnx_tried[icid_ctx->target_state] += 1;
                ctx->nb_cnx_fuzzed[fuzz_cnx_state] += 1;
                if (fuzz_cnx_state == icid_ctx->target_state && icid_ctx->wait_count[fuzz_cnx_state] > ctx->waited_max[icid_ctx->target_state]) {
                    ctx->waited_max[icid_ctx->target_state] = icid_ctx->wait_count[fuzz_cnx_state];
                }
            }
            ctx->nb_packets_fuzzed[fuzz_cnx_state] += 1;
        }

        if (ctx->parent != NULL) {
            fuzi_q_mark_active(ctx->parent, &icid_ctx->icid, current_time, icid_ctx->already_fuzzed);
        }
    }
    return fuzzed_length;
}
