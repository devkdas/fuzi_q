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

#include <picoquic.h>
#include <picoquic_utils.h>
#include <picoquic_internal.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "fuzi_q.h"

uint8_t* fuzz_in_place_or_skip_varint(uint64_t fuzz_pilot, uint8_t* bytes, uint8_t* bytes_max, int do_fuzz);

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
            /* This is an additional fuzz, independent of the main logic below.
             * We don't decrement ctx->nb_fuzzed here as the main logic might still run.
             * Consume some bits from initial_fuzz_pilot if it were to be reused for other
             * independent actions, but for now, the main fuzz_pilot is separate.
             */
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
        fuzz_pilot >>= 4;
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

/* Frame specific fuzzers.
 * Most frames contain a series of fields, with different fuzzing priorities:
 * - The frame type should generally not be fuzzed, except for the rare cases when
 *   it includes variables, e.g., stream data frames with Fin, Length and Offset bits.
 * - Some frames contain data fields, such as content of data frames, or reason
 *   phrase for connection close. Changing that content should be a very low
 *   priority.
 * - Some fields express lengths of content, e.g., length of data or length of
 *   a reason phrase. There are interesting values that can be tried, such as
 *   zero, larger than packet length, exactly 1 byte larger than packet length,
 *   and of course any random value -- see varints.
 * - When fields include stream identifiers, interesting values include streams
 *   that are not open yet, streams that are open and different from current,
 *   old streams that are now closed, and of course random values.
 * - When fields are expressed as varint, it might be interesting to try
 *   specific values like FFFFFFFF, FFFF, FFFFFFFFFFFFFFFF, etc. And of course
 *   any random value.
 * A fraction of fuzzing attempts should avoid being smart: just flip random
 * bytes somewhere in the frame. As the number of fuzzing attempts increase,
 * it may be a good idea to increase that fraction.
 */

void fuzz_random_byte(uint64_t fuzz_pilot, uint8_t* bytes, uint8_t* bytes_max)
{
    if (bytes != NULL) {
        size_t l = bytes_max - bytes;
        size_t x = fuzz_pilot % l;
        uint8_t byte_mask = (uint8_t)(fuzz_pilot >> 8);
        bytes[x] ^= byte_mask;
    }
}

/* ACK FREQUENCY frame fuzzer.
 * ACK_FREQUENCY Frame {
 *   Type (i) = 0xaf,
 *   Sequence Number (i),
 *   Packet Tolerance (i),
 *   Update Max Ack Delay (i)
 * }
 * Fuzz one of the three varint fields, or a random byte in the payload.
 */
void ack_frequency_frame_fuzzer(uint64_t fuzz_pilot, uint8_t* bytes, uint8_t* bytes_max)
{
    uint8_t* payload_start = bytes;
    uint8_t* current_field = bytes;

    // Skip frame type
    current_field = (uint8_t*)picoquic_frames_varint_skip(current_field, bytes_max);
    payload_start = current_field;

    if (current_field == NULL || current_field >= bytes_max) {
        // Not enough space for even the type, or type parsing failed.
        // Fallback to random byte fuzz on whatever is there, if anything.
        if (bytes < bytes_max) {
            fuzz_random_byte(fuzz_pilot, bytes, bytes_max);
        }
        return;
    }

    int choice = fuzz_pilot % 4;
    fuzz_pilot >>= 2;

    // Iterate to find the start of each field for potential fuzzing
    uint8_t* seq_num_start = payload_start;
    uint8_t* pkt_tol_start = NULL;
    uint8_t* upd_delay_start = NULL;

    if (seq_num_start < bytes_max) { // Check if payload_start is valid before using
        pkt_tol_start = (uint8_t*)picoquic_frames_varint_skip(seq_num_start, bytes_max);
    }
    if (pkt_tol_start != NULL && pkt_tol_start < bytes_max) {
        upd_delay_start = (uint8_t*)picoquic_frames_varint_skip(pkt_tol_start, bytes_max);
    }

    switch (choice) {
    case 0: // Fuzz Sequence Number
        if (seq_num_start != NULL && seq_num_start < bytes_max) {
            fuzz_in_place_or_skip_varint(fuzz_pilot, seq_num_start, bytes_max, 1);
        }
        break;
    case 1: // Fuzz Packet Tolerance
        if (pkt_tol_start != NULL && pkt_tol_start < bytes_max) {
            fuzz_in_place_or_skip_varint(fuzz_pilot, pkt_tol_start, bytes_max, 1);
        }
        break;
    case 2: // Fuzz Update Max Ack Delay
        if (upd_delay_start != NULL && upd_delay_start < bytes_max) {
            fuzz_in_place_or_skip_varint(fuzz_pilot, upd_delay_start, bytes_max, 1);
        }
        break;
    case 3: // Fuzz a random byte in the payload
        if (payload_start < bytes_max) {
            // Determine the end of the actual frame data if possible
            uint8_t* payload_end = bytes_max; // Default to bytes_max
            // Check upd_delay_start first as it's the last field
            if (upd_delay_start != NULL && upd_delay_start < bytes_max) {
                 uint8_t* temp_end = (uint8_t*)picoquic_frames_varint_skip(upd_delay_start, bytes_max);
                 if (temp_end != NULL && temp_end <= bytes_max) payload_end = temp_end; // temp_end can be == bytes_max if varint is last thing
            } else if (pkt_tol_start != NULL && pkt_tol_start < bytes_max) {
                 uint8_t* temp_end = (uint8_t*)picoquic_frames_varint_skip(pkt_tol_start, bytes_max);
                 if (temp_end != NULL && temp_end <= bytes_max) payload_end = temp_end;
            } else if (seq_num_start != NULL && seq_num_start < bytes_max) { // seq_num_start is payload_start
                 uint8_t* temp_end = (uint8_t*)picoquic_frames_varint_skip(seq_num_start, bytes_max);
                 if (temp_end != NULL && temp_end <= bytes_max) payload_end = temp_end;
            }
            // Ensure payload_start is strictly less than payload_end before fuzzing
            if (payload_start < payload_end) {
                 fuzz_random_byte(fuzz_pilot, payload_start, payload_end);
            } else if (payload_start < bytes_max) { // Fallback: fuzz between payload_start and bytes_max if payload_end logic was problematic
                 fuzz_random_byte(fuzz_pilot, payload_start, bytes_max);
            }
        }
        break;
    default:
        // Should not happen
        break;
    }
}

uint8_t* fuzz_in_place_or_skip_varint(uint64_t fuzz_pilot, uint8_t* bytes, uint8_t* bytes_max, int do_fuzz)
{
    if (bytes != NULL) {
        uint8_t* head_bytes = bytes;
        bytes = (uint8_t *)picoquic_frames_varint_skip(bytes, bytes_max);
        if (bytes != NULL && do_fuzz){
            size_t l = bytes - head_bytes;
            size_t x = fuzz_pilot % l;
            uint8_t byte_mask = (uint8_t)(fuzz_pilot >> 3);
            if (x == 0) {
                byte_mask &= 0x3f;
            }
            bytes[x] ^= byte_mask;
        }
    }
    return bytes;
}

/* Many frame types are just piles of varints, so we use
 * a simple fuzzer that flips one of the varints. 
 */
void varint_frame_fuzzer(uint64_t fuzz_pilot, uint8_t* bytes, uint8_t* bytes_max, size_t nb_varints)
{
    /* Assume that we have short integers, one per byte */
    size_t fuzz_target;
    uint8_t * first_byte = bytes;
    size_t nb_skipped = 0;

    /* Pick one element at random */
    if (nb_varints <= 1) {
        fuzz_target = 0;
    }
    else {
        fuzz_target = 1 + fuzz_pilot % (nb_varints - 1);
    }
    fuzz_pilot >>= 8;
    /* Skip all the varints before the selected one */
    bytes = first_byte;

    while (bytes != NULL && bytes < bytes_max && nb_skipped < fuzz_target) {
        nb_skipped++;
        bytes = (uint8_t *)picoquic_frames_varint_skip(bytes, bytes_max);
    }
    /* Fuzz the selected varint */
    fuzz_in_place_or_skip_varint(fuzz_pilot, bytes, bytes_max, 1);
}

/* ACK frame fuzzer.
 * ACK frame is composed of a series of varints. Default fuzz picks one of these varints
 * at random and flips it.
 */
void ack_frame_fuzzer(uint64_t fuzz_pilot, uint8_t* frame_start_bytes, uint8_t* frame_max_bytes)
{
    /* 2. Modify ack_frame_fuzzer for ACK Frame Reserved Bits */
    if (frame_start_bytes < frame_max_bytes) { /* Ensure frame_start_bytes is valid */
        if (((fuzz_pilot >> 16) & 0x07) == 1) { /* 1-in-8 chance, using different pilot bits */
            /* ACK frame type byte is 0x02 or 0x03. Bits 2-6 (0x7C) are reserved. */
            /* Bit numbers from MSB: 01234567. Reserved: xR RRRRx. Mask 0x7C = 01111100 */
            uint8_t bit_to_flip = 1 << (((fuzz_pilot >> 19) % 5) + 2); /* Selects one bit from mask 0x7C (bits 2,3,4,5,6) */
                                                                    /* ((pilot % 5) results in 0-4. +2 gives 2-6 for bit position) */
            frame_start_bytes[0] ^= bit_to_flip;
            /* This is an additional fuzz. */
        }
    }

    /* General varint fuzzing first */
    uint8_t* current_bytes = frame_start_bytes;
    size_t num_varints_in_frame = 0;
    while (current_bytes != NULL && current_bytes < frame_max_bytes) {
        num_varints_in_frame++;
        current_bytes = (uint8_t*)picoquic_frames_varint_skip(current_bytes, frame_max_bytes);
    }
    varint_frame_fuzzer(fuzz_pilot, frame_start_bytes, frame_max_bytes, num_varints_in_frame);

    /* Specific ACK field fuzzing with a small probability */
    if ((fuzz_pilot & 0xF) == 0x1) { /* 1 in 16 chance */
        fuzz_pilot >>= 4; /* Consume the bits used for the chance */

        uint8_t* largest_ack_ptr = NULL;
        uint8_t* ack_delay_ptr = NULL;
        uint8_t* ack_range_count_ptr = NULL;
        uint8_t* temp_ptr = frame_start_bytes;

        /* Skip Type field (already fuzzed by varint_frame_fuzzer if chosen) */
        temp_ptr = (uint8_t*)picoquic_frames_varint_skip(temp_ptr, frame_max_bytes);
        if (temp_ptr == NULL || temp_ptr >= frame_max_bytes) return;
        largest_ack_ptr = temp_ptr;

        temp_ptr = (uint8_t*)picoquic_frames_varint_skip(temp_ptr, frame_max_bytes);
        if (temp_ptr == NULL || temp_ptr >= frame_max_bytes) return;
        ack_delay_ptr = temp_ptr; /* Not used for specific value fuzzing here, but good to identify */

        temp_ptr = (uint8_t*)picoquic_frames_varint_skip(temp_ptr, frame_max_bytes);
        if (temp_ptr == NULL || temp_ptr >= frame_max_bytes) return;
        ack_range_count_ptr = temp_ptr;

        /* Fuzz 'Largest Acknowledged' to 0 or 1 */
        if ((fuzz_pilot & 0x1) == 0) { /* 1 in 2 chance for Largest Ack after specific fuzz is triggered */
            if (largest_ack_ptr != NULL && largest_ack_ptr < frame_max_bytes) {
                uint8_t value_to_write = (fuzz_pilot >> 1) & 0x1; /* 0 or 1 based on next bit */
                /* Overwrite the first byte of the varint.
                 * If it's a 1-byte varint (value < 64), this correctly sets it to 0 or 1.
                 * If it's a multi-byte varint, this makes it a 1-byte varint 0 or 1,
                 * effectively shortening it and changing its value. The parser will read it
                 * as 0 or 1. The remaining bytes of the original varint become part of the
                 * next field or garbage, which is acceptable for fuzzing.
                 */
                largest_ack_ptr[0] = value_to_write;
            }
        }
        fuzz_pilot >>= 2; /* Consume bits used for Largest Ack choice and value */

        /* Fuzz 'ACK Range Count' to 0 */
        /* This is done regardless of the Largest Ack fuzz choice if specific fuzz is triggered */
        if (ack_range_count_ptr != NULL && ack_range_count_ptr < frame_max_bytes) {
             /* Similar logic to Largest Acknowledged: setting the first byte to 0
              * makes the varint represent the value 0.
              */
            ack_range_count_ptr[0] = 0x00;
        }
    }
}

/* Stream frame fuzzer. 
 * Variations:
 *    -- flip a FIN bit
 *    -- fuzz length
 *    -- fuzz stream ID
 *    -- fuzz illegal offset
 * The fuzzing depends on how much space is available. It is always possible to
 * fuzz "in place", rewriting a var int by a var int of the same length, but if
 * there is space behind the frame it is also possible to extend the length of the
 * fields.
 */

void stream_frame_fuzzer(uint64_t fuzz_pilot, uint8_t* bytes, uint8_t* bytes_max)
{
    uint8_t* first_byte = bytes;
    /* From the type octet, get the various bits that could be flipped */
    int len = bytes[0] & 2;
    int off = bytes[0] & 4;
    int fuzz_length = 0;
    int fuzz_offset = 0;
    int fuzz_stream_id = 0;
    int fuzz_random = 0;

    /* From the random field, select a framing variant.
     * If selected field is omitted, fuzz the header instead.
     */
    uint64_t fuzz_variant = (fuzz_pilot ^ 0x57ea3f8a3ef822e8ull) % 5;

    switch (fuzz_variant) {
    case 0:
        bytes[0] ^= 1;
        break;
    case 1:
        if (len) {
            /* fuzz the length */
            fuzz_length = 1;
        }
        else {
            bytes[0] ^= 2;
        }
        break;
    case 2:
        if (off) {
            /* fuzz offset */
            fuzz_offset = 1;
        }
        else {
            bytes[0] ^= 4;
        }
        break;
    case 3:
        /* fuzz stream ID */
        fuzz_stream_id = 1;
        break;
    default:
        /* fuzz random byte */
        break;
    }

    if (bytes < bytes_max) {
        bytes++;
    }
    else {
        bytes = NULL;
    }

    bytes = fuzz_in_place_or_skip_varint(fuzz_pilot, bytes, bytes_max, fuzz_stream_id);

    // Fuzz Offset if present
    if (off) {
        if (fuzz_offset) { // Check if we decided to fuzz this field
            uint8_t* field_start = bytes;
            uint8_t* field_end = (uint8_t*)picoquic_frames_varint_skip(field_start, bytes_max);

            if (field_end != NULL) { // Successfully identified a varint
                if ((fuzz_pilot & 0x03) == 0) { // 1-in-4 chance for boundary value
                    fuzz_pilot >>= 2; // Consume bits
                    size_t varint_len = field_end - field_start;
                    if (varint_len > 0 && varint_len <= 8) {
                        // Set to maximal value for this varint length, preserving 2 MSB of first byte
                        field_start[0] |= 0x3F; // Set lower 6 bits of first byte to 1
                        for (size_t i = 1; i < varint_len; i++) {
                            field_start[i] = 0xFF;
                        }
                        bytes = field_end; // Advance bytes pointer
                    } else {
                        // Varint length invalid for this specific operation, fallback to regular fuzzing
                        bytes = fuzz_in_place_or_skip_varint(fuzz_pilot, field_start, bytes_max, 1);
                    }
                } else { 
                    fuzz_pilot >>= 2; // Consume bits if not taken by boundary value path
                    bytes = fuzz_in_place_or_skip_varint(fuzz_pilot, field_start, bytes_max, 1);
                }
            } else {
                // field_end is NULL, field_start is likely invalid or at/past bytes_max.
                // Regular fuzzing will handle this (likely skip or do nothing if bytes is already NULL/invalid).
                bytes = fuzz_in_place_or_skip_varint(fuzz_pilot, field_start, bytes_max, 1);
            }
        } else {
            // Just skip if not fuzzing this field
            bytes = (uint8_t*)picoquic_frames_varint_skip(bytes, bytes_max);
        }
    }

    // Fuzz Length if present
    if (len) {
        if (fuzz_length) { // Check if we decided to fuzz this field
            uint8_t* field_start = bytes;
            uint8_t* field_end = (uint8_t*)picoquic_frames_varint_skip(field_start, bytes_max);

            if (field_end != NULL) { // Successfully identified a varint
                if ((fuzz_pilot & 0x03) == 0) { // 1-in-4 chance for boundary value
                    fuzz_pilot >>= 2; // Consume bits
                    size_t varint_len = field_end - field_start;
                    if (varint_len > 0 && varint_len <= 8) {
                        // Set to maximal value for this varint length, preserving 2 MSB of first byte
                        field_start[0] |= 0x3F; // Set lower 6 bits of first byte to 1
                        for (size_t i = 1; i < varint_len; i++) {
                            field_start[i] = 0xFF;
                        }
                        bytes = field_end; // Advance bytes pointer
                    } else {
                        // Varint length invalid for this specific operation, fallback to regular fuzzing
                        bytes = fuzz_in_place_or_skip_varint(fuzz_pilot, field_start, bytes_max, 1);
                    }
                } else { 
                    fuzz_pilot >>= 2; // Consume bits if not taken by boundary value path
                    bytes = fuzz_in_place_or_skip_varint(fuzz_pilot, field_start, bytes_max, 1);
                }
            } else {
                // field_end is NULL. Regular fuzzing will handle this.
                bytes = fuzz_in_place_or_skip_varint(fuzz_pilot, field_start, bytes_max, 1);
            }
        } else {
            // Just skip if not fuzzing this field
            bytes = (uint8_t*)picoquic_frames_varint_skip(bytes, bytes_max);
        }
    }

    if (bytes != NULL && fuzz_random) {
        fuzz_random_byte(fuzz_pilot, first_byte + 1, bytes_max);
    }
}

/* datagram fuzzer */
void datagram_frame_fuzzer(uint64_t fuzz_pilot, uint8_t* bytes, uint8_t* bytes_max)
{
    int len = bytes[0] & 1;
    if (!len) {
        /* Add a length type, of some length, so it can be fuzzed */
        bytes[0] |= 1;
        if (bytes < bytes_max) {
            bytes[1] = (bytes[1] & 0x3f) | (((uint8_t)fuzz_pilot & 3) << 6);
        }
    }
    /* Fuzz the length */
    varint_frame_fuzzer(fuzz_pilot, bytes, bytes_max, 2);
}

/* Challenge frame fuzzer
 * Type, and then 8 bytes.
 * Can flip the type from response to challenge and vice verse,
 * or change the value of the 8 byte response.
 */
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

/* Padding fuzzer
 * Replacing ping, pad or handshake done by one of the other types is a nice way to
 * mess with the protocol machine. 
 * Padding also is a nice space for inserting random stuff, to test various 
 * potential failures.
 */
void padding_frame_fuzzer(uint64_t fuzz_pilot, uint8_t* bytes, uint8_t* bytes_max)
{
    size_t l = bytes_max - bytes;
    int fuzz_type = 1;

    /* Test whether to mess with the type itself */
    if (l > 1) {
        fuzz_type = (fuzz_pilot & 7) == 0;
        fuzz_pilot >>= 3;
    }

    /* if fuzzing the type.. */
    if (fuzz_type) {
        int flip = fuzz_pilot & 1;

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
            fuzz_pilot >>= 1;
            bytes[0] ^= (uint8_t)fuzz_pilot;
            break;
        }
    }
    else {
        /* Insert any of a set of candidate frames */
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
        /* find an insert compatible with available size */
        do {
            x_i = fuzz_pilot % x_m;
            x_m = x_i;
        } while (x_i > 0 && insert_table[x_i].i_count > l);
        bytes[0] = insert_table[x_i].i_type;
        fuzz_pilot >>= 4;
        /* Todo: initialize integer lengths compatible with available space */
        /* Fuzz that frame */
        varint_frame_fuzzer(fuzz_pilot, bytes, bytes_max, insert_table[x_i].i_count);
    }
}

/* New token fuzzer
 * Either fuzz one of the 2 parameters, or fuzz the token itself.
 * Fuzzing the token might cause an issue in a follow on connection.
 */
void new_token_frame_fuzzer(uint64_t fuzz_pilot, uint8_t* frame_start, uint8_t* bytes_max)
{
    uint8_t* token_len_varint_start;
    uint8_t* token_data_start;
    uint64_t actual_token_length_val;

    // Skip Frame Type
    token_len_varint_start = (uint8_t*)picoquic_frames_varint_skip(frame_start, bytes_max);

    if (token_len_varint_start == NULL || token_len_varint_start >= bytes_max) {
        if (frame_start < bytes_max) { // Fuzz type if nothing else
            fuzz_random_byte(fuzz_pilot, frame_start, bytes_max);
        }
        return;
    }

    // Decode where token data would start, to calculate available space later
    // This also decodes the current token length value
    token_data_start = (uint8_t*)picoquic_frames_varint_decode(token_len_varint_start, bytes_max, &actual_token_length_val);

    if (token_data_start == NULL) { // If token length varint itself is invalid / too long
        // Fuzz the token length varint in place as a fallback
        fuzz_in_place_or_skip_varint(fuzz_pilot, token_len_varint_start, bytes_max, 1);
        return;
    }

    int choice = fuzz_pilot % 4;
    fuzz_pilot >>= 2;

    switch (choice) {
    case 0: // Fuzz Token Length varint with specific boundary values
        {
            // size_t space_for_token_data = (bytes_max > token_data_start) ? (bytes_max - token_data_start) : 0; // Kept for context if needed later
            // uint64_t target_len_val = 0; // Removed as unused
            int len_choice = fuzz_pilot % 4;
            fuzz_pilot >>= 2;

            switch (len_choice) {
            case 0: /* target_len_val = 0; */ break; // Assignment removed
            case 1: /* target_len_val = space_for_token_data; */ break; // Assignment removed
            case 2: /* target_len_val = space_for_token_data + 1; */ break; // Assignment removed
            default: // Max value for current varint encoding of token_len_varint_start
                {
                    uint8_t* temp_len_end = (uint8_t*)picoquic_frames_varint_skip(token_len_varint_start, bytes_max);
                    size_t len_varint_byte_len = (temp_len_end > token_len_varint_start) ? (temp_len_end - token_len_varint_start) : 0;
                    if (len_varint_byte_len > 0) {
                        token_len_varint_start[0] |= 0x3F; // Max out 6 LSBs
                        for (size_t i = 1; i < len_varint_byte_len; i++) {
                            token_len_varint_start[i] = 0xFF;
                        }
                    }
                    // This case directly modifies, so return
                    return;
                }
            }
            // Encode target_len_val into token_len_varint_start. This is complex if it changes varint length.
            // Simplification: If target_len_val fits into existing varint_len_varint_start's byte length, write it. Otherwise, pick another strategy.
            // For now, let's just use the default varint fuzzer for token length for this sub-case if direct write is too complex for worker.
            // The "max value for current varint encoding" (len_choice == default) is already good.
            // Let's make cases 0,1,2 also use a direct write if simple, or fall to general fuzz for token length.
            // For simplicity in this subtask, this case will just use the powerful default varint fuzzer
            // on the token_len_varint_start. The "max value" case is specific enough.
            if (len_choice < 3) { // For 0, available_space, available_space + 1
                 // Picoquic doesn't have a public "picoquic_encode_varint_in_place".
                 // So, for these, we'll just fall through to the general varint fuzzer for Token Length.
            } else { // max value already handled
                 return;
            }
        }
        // Fall through to Choice 3 (fuzz token length varint generally) for simplicity for specific target_len_vals
        // NO BREAK: Deliberate fall-through for len_choice < 3

    case 3: // Fuzz Token Length varint generally (was Choice 3, also target for fall-through)
        fuzz_in_place_or_skip_varint(fuzz_pilot, token_len_varint_start, bytes_max, 1);
        break;

    case 1: // Fuzz Token Data with patterned data
        if (token_data_start < bytes_max && actual_token_length_val > 0) {
            uint8_t* effective_token_data_end = token_data_start + actual_token_length_val;
            if (effective_token_data_end > bytes_max) {
                effective_token_data_end = bytes_max;
            }
            if (token_data_start < effective_token_data_end) { // Ensure there's space to write
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

    case 2: // Fuzz Token Data with fuzz_random_byte
        if (token_data_start < bytes_max && actual_token_length_val > 0) {
            uint8_t* effective_token_data_end = token_data_start + actual_token_length_val;
            if (effective_token_data_end > bytes_max) {
                effective_token_data_end = bytes_max;
            }
            if (token_data_start < effective_token_data_end) { // Ensure there's space to write
                fuzz_random_byte(fuzz_pilot, token_data_start, effective_token_data_end);
            }
        }
        break;
    }
}

/* Step 3: Create new_connection_id_frame_fuzzer_logic */
void new_connection_id_frame_fuzzer_logic(uint64_t fuzz_pilot, uint8_t* frame_start, uint8_t* frame_max, fuzzer_icid_ctx_t* icid_ctx)
{
    uint8_t* p = frame_start;
    uint64_t frame_type;
    int specific_fuzz_applied = 0;

    /* Frame Type (already known to be NEW_CONNECTION_ID, but skip it) */
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
        case 0: /* Target Sequence Number */
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
        case 1: /* Target Retire Prior To */
            {
                uint64_t new_retire_val;
                int val_choice = fuzz_pilot % 3;
                if (val_choice == 0) new_retire_val = original_seq_no; /* Retire the one just sent */
                else if (val_choice == 1) new_retire_val = 0;
                else new_retire_val = (original_seq_no > 0) ? (original_seq_no - 1) : 0; /* Retire one before */
                
                if (encode_and_overwrite_varint(retire_prior_to_start, retire_prior_to_end, frame_max, new_retire_val)) {
                    specific_fuzz_applied = 1;
                }
            }
            break;
        case 2: /* Target Length field */
            {
                int val_choice = fuzz_pilot % 3;
                if (val_choice == 0) *length_field_ptr = 0;
                else if (val_choice == 1) *length_field_ptr = PICOQUIC_CONNECTION_ID_MAX_SIZE;
                else *length_field_ptr = PICOQUIC_CONNECTION_ID_MAX_SIZE + 1; /* Invalid length */
                specific_fuzz_applied = 1;
            }
            break;
        case 3: /* Target CID */
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
        case 4: /* Target Stateless Reset Token */
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

/* New CID frame fuzzer (old, to be replaced by logic above in frame_header_fuzzer)
 * Either fuzz one of the varint parameters, or in rare cases fuzz the
 * value of the CID. No point fuzzing the reset token. 
 * NEW_CONNECTION_ID Frame {
 *   Type (i) = 0x18,
 *   Sequence Number (i),
 *   Retire Prior To (i),
 *   Length (8),
 *   Connection ID (8..160),
 *   Stateless Reset Token (128),
 * }
 */
void new_cid_frame_fuzzer(uint64_t fuzz_pilot, uint8_t* bytes, uint8_t* bytes_max) 
{
    /* This function is effectively replaced by new_connection_id_frame_fuzzer_logic 
     * called directly from frame_header_fuzzer.
     * Keeping a stub or removing it depends on whether it's called elsewhere,
     * but the plan is to replace the call in frame_header_fuzzer.
     * For now, let it call the default.
     */
    default_frame_fuzzer(fuzz_pilot, bytes, bytes_max);
}

// retire_connection_id_frame_fuzzer
void retire_connection_id_frame_fuzzer(uint64_t fuzz_pilot, uint8_t* bytes, uint8_t* frame_max) /* Changed bytes_max to frame_max for consistency */
{
    uint8_t* frame_payload_start = (uint8_t*)picoquic_frames_varint_skip(bytes, frame_max); /* Use frame_max */

    if (frame_payload_start == NULL || frame_payload_start >= frame_max) { /* Use frame_max */
        if (bytes < frame_max) { /* Use frame_max */
            fuzz_random_byte(fuzz_pilot, bytes, frame_max); /* Use frame_max */
        }
        return;
    }

    uint8_t* seq_num_start = frame_payload_start;
    uint64_t original_seq_no; /* For context, though not directly used by older logic */
    uint8_t* seq_num_end = (uint8_t*)picoquic_frames_varint_decode(seq_num_start, frame_max, &original_seq_no); /* Use decode to get end */

    if (seq_num_end == NULL || seq_num_start == seq_num_end) { /* Check if decode failed or varint empty */
      fuzz_in_place_or_skip_varint(fuzz_pilot >> 2, seq_num_start, frame_max, 1); /* Use frame_max */
      return;
    }

    int choice = fuzz_pilot % 4; /* Original 4 choices: 0,1,2 for specific values, 3 for general fuzz */
    fuzz_pilot >>= 2;

    size_t varint_len = seq_num_end - seq_num_start;

    if (varint_len == 0 && choice !=3) { /* If varint_len is 0 (should not happen if seq_num_end > seq_num_start), default to general fuzz */
        choice = 3;
    }

    switch (choice) {
    case 0: // Set Sequence Number to 0
        if (varint_len > 0) {
            uint8_t prefix = seq_num_start[0] & 0xC0; // Preserve 2 MSBs encoding length
            seq_num_start[0] = prefix; // Set value bits to 0 for first byte
            for (size_t i = 1; i < varint_len; i++) {
                seq_num_start[i] = 0x00; // Set subsequent bytes to 0
            }
        }
        break;
    case 1: // Set Sequence Number to 1
        if (varint_len > 0) {
            uint8_t prefix = seq_num_start[0] & 0xC0; // Preserve 2 MSBs
            if (varint_len == 1) {
                seq_num_start[0] = prefix | 0x01; // Set value to 1 for 1-byte varint
            } else {
                // For multi-byte varint, set first byte's value part to 0,
                // all intermediate bytes to 0, and last byte to 1.
                seq_num_start[0] = prefix; 
                for (size_t i = 1; i < varint_len -1; i++) {
                    seq_num_start[i] = 0x00;
                }
                seq_num_start[varint_len - 1] = 0x01;
            }
        }
        break;
    case 2: // Set Sequence Number to max value for its current varint length
        if (varint_len > 0) {
            seq_num_start[0] |= 0x3F; 
            for (size_t i = 1; i < varint_len; i++) {
                seq_num_start[i] = 0xFF;
            }
        }
        break;
    /* Default case (3) is general fuzzing of the sequence number varint */
    default: 
        /* New: Add a 1-in-3 chance (within this default/general fuzz path) to pick a small value */
        if ((fuzz_pilot & 0x03) == 0) { /* Approx 1-in-4, let's make it 1-in-3 of this path */
            fuzz_pilot >>=2;
            uint64_t small_seq_val = fuzz_pilot % 16; /* Value 0-15 */
            if (!encode_and_overwrite_varint(seq_num_start, seq_num_end, frame_max, small_seq_val)) {
                 /* If encoding failed (e.g. new varint too long, though unlikely for 0-15), fallback to bit flip */
                 fuzz_in_place_or_skip_varint(fuzz_pilot >> 4, seq_num_start, frame_max, 1);
            }
        } else {
            /* Original general fuzzing for this path */
            fuzz_in_place_or_skip_varint(fuzz_pilot >> 2, seq_num_start, frame_max, 1);
        }
        break;
    }
}

/* Helper function to encode and overwrite/pad (similar to max_data_fuzzer) */
/* Returns 1 if successful, 0 otherwise. original_varint_end is the end of the original varint being replaced. */
static int encode_and_overwrite_varint(uint8_t* field_start, uint8_t* field_end, uint8_t* frame_max, uint64_t new_value)
{
    if (field_start == NULL || field_end == NULL || field_start >= field_end || field_start >= frame_max) {
        return 0; /* Invalid parameters or no space for original varint */
    }

    size_t original_varint_len = field_end - field_start;
    uint8_t temp_buffer[16]; /* Max varint is 8 bytes, plus some buffer */
    uint8_t* temp_encode_end = picoquic_varint_encode(temp_buffer, sizeof(temp_buffer), new_value);
    
    if (temp_encode_end == temp_buffer) { /* Encoding failed or value is zero and encode wrote nothing (should write 0x00 for 0) */
        if (new_value == 0) { /* Handle encoding of 0 explicitly if needed */
            temp_buffer[0] = 0;
            temp_encode_end = temp_buffer + 1;
        } else {
            return 0; /* Encoding error */
        }
    }
    
    size_t new_varint_len = temp_encode_end - temp_buffer;

    if (new_varint_len <= original_varint_len) {
        memcpy(field_start, temp_buffer, new_varint_len);
        if (new_varint_len < original_varint_len) {
            /* Pad with 0x00 if the new varint is shorter */
            memset(field_start + new_varint_len, 0, original_varint_len - new_varint_len);
        }
        return 1;
    }
    return 0; /* New varint is too long to fit in original space */
}


/* 1. Modify path_abandon_frame_fuzzer */
void path_abandon_frame_fuzzer(uint64_t fuzz_pilot, uint8_t* frame_start, uint8_t* bytes_max)
{
    uint8_t* p = frame_start;
    uint64_t frame_type;
    int specific_fuzz_done = 0;

    /* Decode frame type (varint) */
    p = (uint8_t*)picoquic_frames_varint_decode(p, bytes_max, &frame_type);
    if (p == NULL || p >= bytes_max) {
        default_frame_fuzzer(fuzz_pilot, frame_start, bytes_max);
        return;
    }

    uint8_t* path_id_start = p;
    uint64_t original_path_id;
    uint8_t* path_id_end = (uint8_t*)picoquic_frames_varint_decode(path_id_start, bytes_max, &original_path_id);

    if (path_id_end == NULL || path_id_start == path_id_end) { // Parsing failed or empty varint
        default_frame_fuzzer(fuzz_pilot, frame_start, bytes_max);
        return;
    }

    uint8_t* error_code_start = path_id_end;
    uint64_t original_error_code;
    uint8_t* error_code_end = (uint8_t*)picoquic_frames_varint_decode(error_code_start, bytes_max, &original_error_code);
    
    if (error_code_end == NULL || error_code_start == error_code_end) { // Parsing failed or empty varint
         /* If error code cannot be parsed, we might still fuzz Path ID or default */
         error_code_start = NULL; /* Mark as invalid */
         error_code_end = NULL;
    }

    /* With a 1-in-4 chance, attempt specific value fuzzing */
    if ((fuzz_pilot & 0x03) == 0) {
        fuzz_pilot >>= 2;
        int fuzz_target_choice = fuzz_pilot % 2; /* 0 for Path ID, 1 for Error Code */
        fuzz_pilot >>= 1;

        if (fuzz_target_choice == 0) { /* Fuzz Path ID */
            if (path_id_start != NULL && path_id_end != NULL) {
                uint64_t new_path_id_val = ((fuzz_pilot >> 1) & 1) ? 0x3FFFFFFFFFFFFFFF : 0;
                if (encode_and_overwrite_varint(path_id_start, path_id_end, bytes_max, new_path_id_val)) {
                    specific_fuzz_done = 1;
                }
            }
        } else { /* Fuzz Error Code */
            if (error_code_start != NULL && error_code_end != NULL) {
                uint64_t new_error_code_val;
                int error_choice = fuzz_pilot % 3;
                fuzz_pilot >>= 2;
                if (error_choice == 0) {
                    new_error_code_val = 0;
                } else if (error_choice == 1) {
                    new_error_code_val = PICOQUIC_TRANSPORT_FRAME_ENCODING_ERROR;
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
        /* Fallback to bit-flipping or default fuzzer */
        uint8_t* current_field = frame_start;
        current_field = (uint8_t*)picoquic_frames_varint_skip(current_field, bytes_max); // Skip Type

        if (current_field != NULL && current_field < bytes_max) { // Path ID
            current_field = fuzz_in_place_or_skip_varint(fuzz_pilot, current_field, bytes_max, 1);
            fuzz_pilot >>= 8; // Shift pilot for next field
        }
        if (current_field != NULL && current_field < bytes_max) { // Error Code
            fuzz_in_place_or_skip_varint(fuzz_pilot, current_field, bytes_max, 1);
        }
    }
}

/* 2. Create path_id_sequence_frame_fuzzer */
void path_id_sequence_frame_fuzzer(uint64_t fuzz_pilot, uint8_t* frame_start, uint8_t* frame_max)
{
    uint8_t* p = frame_start;
    uint64_t frame_type;
    int specific_fuzz_done = 0;

    /* Decode frame type (varint) */
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
        seq_no_start = NULL; /* Mark as invalid for specific fuzzing */
        seq_no_end = NULL;
    }

    int choice = fuzz_pilot % 3;
    fuzz_pilot >>= 2; 

    if (choice == 0) { /* 1-in-3: Target Path ID */
        if (path_id_start && path_id_end) {
            uint64_t new_path_id_val = (fuzz_pilot & 1) ? 0x3FFFFFFFFFFFFFFF : 0;
            if (encode_and_overwrite_varint(path_id_start, path_id_end, frame_max, new_path_id_val)) {
                specific_fuzz_done = 1;
            }
        }
    } else if (choice == 1) { /* 1-in-3: Target Sequence Number */
        if (seq_no_start && seq_no_end) {
            uint64_t new_seq_no_val = (fuzz_pilot & 1) ? 0x3FFFFFFFFFFFFFFF : 0;
            if (encode_and_overwrite_varint(seq_no_start, seq_no_end, frame_max, new_seq_no_val)) {
                specific_fuzz_done = 1;
            }
        }
    }
    /* Else (choice == 2, 1-in-3), no specific fuzzing, fall through to default */

    if (!specific_fuzz_done) {
        default_frame_fuzzer(fuzz_pilot, frame_start, frame_max);
    }
}

/* Default frame fuzzer. Skip the frame type, then flip at random one of the first 8 bytes */
void default_frame_fuzzer(uint64_t fuzz_pilot, uint8_t* bytes, uint8_t* bytes_max)
{
    uint8_t* frame_byte = bytes;

    bytes = (uint8_t *)picoquic_frames_varint_skip(bytes, bytes_max);

    if (bytes == NULL || bytes >= bytes_max) {
        bytes = frame_byte;
    }
    if (bytes + 8 < bytes_max) {
        bytes_max = bytes + 8;
    }
    fuzz_random_byte(fuzz_pilot, bytes, bytes_max); 
}

/* Step 3: Create a new function max_data_fuzzer in lib/fuzzer.c */
void max_data_fuzzer(uint64_t fuzz_pilot, uint8_t* frame_start, uint8_t* frame_max, fuzzer_ctx_t* f_ctx, fuzzer_icid_ctx_t* icid_ctx)
{
    uint8_t* original_varint_start = frame_start;
    uint8_t* p_val = original_varint_start;
    uint64_t original_max_data;
    uint8_t* original_varint_end;

    /* Skip the frame type to get to the Maximum Data field. */
    /* MAX_DATA frame type is 1 byte, not varint */
    if (p_val < frame_max) {
        p_val++; 
    } else {
        default_frame_fuzzer(fuzz_pilot >> 2, frame_start, frame_max);
        return;
    }
    original_varint_start = p_val; // Start of the Maximum Data varint

    original_varint_end = (uint8_t*)picoquic_frames_varint_decode(p_val, frame_max, &original_max_data);

    if (original_varint_end != NULL && original_varint_start < original_varint_end) { // Successfully parsed
        if (icid_ctx != NULL) { // Ensure icid_ctx is valid
            icid_ctx->last_sent_max_data = original_max_data;
            icid_ctx->has_sent_max_data = 1;
        }

        /* Probabilistic fuzzing: 1 in 4 chance */
        if ((fuzz_pilot & 0x03) == 0) {
            if (icid_ctx != NULL && icid_ctx->has_sent_max_data && icid_ctx->last_sent_max_data > 0) {
                uint64_t fuzzed_val = icid_ctx->last_sent_max_data / 2;
                if (fuzzed_val == icid_ctx->last_sent_max_data && fuzzed_val > 0) { // Avoid infinite loop if last_sent_max_data is 1
                    fuzzed_val--;
                }

                int fuzzed_varint_len = picoquic_frames_varint_encode_length(fuzzed_val);
                size_t original_varint_len = original_varint_end - original_varint_start;

                if (fuzzed_varint_len <= original_varint_len) {
                    picoquic_frames_varint_encode(original_varint_start, frame_max, fuzzed_val);
                    /* If new varint is shorter, pad with 0x00 if there's space within original varint length */
                    if (fuzzed_varint_len < original_varint_len) {
                        size_t padding_len = original_varint_len - fuzzed_varint_len;
                        if (original_varint_start + fuzzed_varint_len + padding_len <= frame_max) {
                           memset(original_varint_start + fuzzed_varint_len, 0, padding_len);
                        }
                    }
                }
                /* Else, if fuzzed_varint_len > original_varint_len, do nothing for this specific fuzz type */
                /* Fall through to default_frame_fuzzer is handled after this block */
                default_frame_fuzzer(fuzz_pilot >> 2, frame_start, frame_max);
                return; 
            }
        }
    }
    /* Fallback: Call default_frame_fuzzer if any step failed or probability check didn't pass */
    default_frame_fuzzer(fuzz_pilot >> 2, frame_start, frame_max);
}

#define FUZZER_MAX_NB_FRAMES 32

/* Step 4: Modify frame_header_fuzzer in lib/fuzzer.c */
/* New signature for frame_header_fuzzer */
int frame_header_fuzzer(fuzzer_ctx_t* ctx, fuzzer_icid_ctx_t* icid_ctx, uint64_t fuzz_pilot,
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
        if (picoquic_skip_frame(bytes, last_byte - bytes, &consumed, &is_pure_ack) == 0) {
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
        size_t fuzzed_frame = (size_t)(fuzz_pilot % nb_frames);
        uint8_t* frame_byte = frame_head[fuzzed_frame];
        uint8_t* frame_max = frame_next[fuzzed_frame];

        fuzz_pilot >>= 5;

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
                /* Call the new max_data_fuzzer */
                max_data_fuzzer(fuzz_pilot, frame_byte, frame_max, ctx, icid_ctx);
                break;
            case picoquic_frame_type_max_stream_data:
                varint_frame_fuzzer(fuzz_pilot, frame_byte, frame_max, 3);
                break;
            case picoquic_frame_type_max_streams_bidir:
            case picoquic_frame_type_max_streams_unidir:
                /* TODO: maybe fuzz the low bit of type */
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
                /* TODO: maybe fuzz the low bit of type */
                varint_frame_fuzzer(fuzz_pilot, frame_byte, frame_max, 2);
                break;
            case picoquic_frame_type_retire_connection_id:
                retire_connection_id_frame_fuzzer(fuzz_pilot, frame_byte, frame_max);
                break;
            case picoquic_frame_type_connection_close:
            case picoquic_frame_type_application_close:
                /* Not fuzzing the reason string */
                varint_frame_fuzzer(fuzz_pilot, frame_byte, frame_max, 4);
                break;
            case picoquic_frame_type_datagram:
            case picoquic_frame_type_datagram_l:
                datagram_frame_fuzzer(fuzz_pilot, frame_byte, frame_max);
                break;
            case picoquic_frame_type_path_challenge:
            case picoquic_frame_type_path_response:
                challenge_frame_fuzzer(fuzz_pilot, frame_byte, frame_max);
                break;
            case picoquic_frame_type_crypto_hs:
                /* Not fuzzing the crypto content */
                varint_frame_fuzzer(fuzz_pilot, frame_byte, frame_max, 3);
                break;
            case picoquic_frame_type_padding:
            case picoquic_frame_type_ping:
            case picoquic_frame_type_handshake_done:
                padding_frame_fuzzer(fuzz_pilot, frame_byte, frame_max);
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
                    case picoquic_frame_type_path_ack:
                    case picoquic_frame_type_path_ack_ecn:
                    case picoquic_frame_type_ack:
                    case picoquic_frame_type_ack_ecn:
                        ack_frame_fuzzer(fuzz_pilot, frame_byte, frame_max);
                        break;
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
                        /* Not fuzzing the IP address */
                        varint_frame_fuzzer(fuzz_pilot, frame_byte, frame_max, 5);
                        break;
                    default:
                        default_frame_fuzzer(fuzz_pilot, frame_byte, frame_max);
                        break;
                    }
                }
                break;
            }
            }
        }
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

            if (picoquic_skip_frame(bytes, bytes_last - bytes, &consumed, &is_pure_ack) != 0) {
                bytes = NULL;
            }
            else {
                bytes += consumed;
            }
        }
    }

    return (final_pad == NULL) ? length : (final_pad - bytes_begin);
}

/* Create version_negotiation_packet_fuzzer function */
size_t version_negotiation_packet_fuzzer(uint64_t fuzz_pilot, uint8_t* bytes, size_t vn_header_len, size_t current_length, size_t bytes_max)
{
    size_t original_current_length = current_length;

    if (vn_header_len > current_length || vn_header_len > bytes_max) {
        /* Invalid input, header alone is longer than current_length or buffer */
        return current_length;
    }

    uint8_t* version_list_start = bytes + vn_header_len;
    size_t version_list_len = current_length - vn_header_len;
    
    if (version_list_len % 4 != 0) {
        /* Malformed version list length, not a multiple of 4. Don't fuzz further. */
        return current_length;
    }
    size_t num_versions = version_list_len / 4;

    int choice = fuzz_pilot % 16; /* More choices for VN packet */
    fuzz_pilot >>= 4;

    switch (choice) {
    case 0: /* Corrupt First Byte (Type/Flags) */
        if (vn_header_len > 0) { 
            bytes[0] ^= (uint8_t)(fuzz_pilot & 0x3F);
        }
        break;

    case 1: /* Corrupt DCID/SCID lengths - No-op as per previous decision, focus on version list */
        break;

    case 2: /* Empty Version List */
        if (vn_header_len <= bytes_max) {
            current_length = vn_header_len;
        }
        break;

    case 3: /* Truncate Version List (incomplete last version) */
        if (num_versions > 0) {
            size_t bytes_to_remove = (fuzz_pilot % 3) + 1; /* Remove 1, 2, or 3 bytes */
            fuzz_pilot >>= 2;
            if (current_length > vn_header_len + bytes_to_remove) {
                current_length -= bytes_to_remove;
            } else if (current_length > vn_header_len) {
                current_length = vn_header_len; /* Max truncation */
            }
        }
        break;

    case 4: /* Corrupt a Version Value - Overwrite with reserved (0x0A0A0A0A) */
    case 5: /* Corrupt a Version Value - Overwrite with reserved (0x1A1A1A1A) */
    case 6: /* Corrupt a Version Value - Flip bits */
        if (num_versions > 0) {
            size_t version_idx = fuzz_pilot % num_versions;
            fuzz_pilot >>= 4; 
            uint8_t* version_ptr = version_list_start + (version_idx * 4);

            if (version_ptr + 4 <= bytes + original_current_length) { // Check against original_current_length for read/write
                if (choice == 4) {
                    picoquic_val32be_to_bytes(0x0A0A0A0A, version_ptr);
                } else if (choice == 5) {
                    picoquic_val32be_to_bytes(0x1A1A1A1A, version_ptr);
                } else { // choice == 6
                    version_ptr[0] ^= (uint8_t)(fuzz_pilot & 0xFF);
                    version_ptr[1] ^= (uint8_t)((fuzz_pilot >> 8) & 0xFF);
                    version_ptr[2] ^= (uint8_t)((fuzz_pilot >> 16) & 0xFF);
                    version_ptr[3] ^= (uint8_t)((fuzz_pilot >> 24) & 0xFF);
                }
            }
        }
        break;

    case 7: /* Duplicate Versions */
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

    case 8: /* Add Too Many Versions (Overflow) - append one garbage version if space */
        if (current_length + 4 <= bytes_max) {
            uint8_t* new_version_ptr = bytes + current_length;
            new_version_ptr[0] = (uint8_t)(fuzz_pilot & 0xFF);
            new_version_ptr[1] = (uint8_t)((fuzz_pilot >> 8) & 0xFF);
            new_version_ptr[2] = (uint8_t)((fuzz_pilot >> 16) & 0xFF);
            new_version_ptr[3] = (uint8_t)((fuzz_pilot >> 24) & 0xFF);
            current_length += 4;
        }
        break;
    
    case 9: /* Swap two versions */
        if (num_versions >= 2) {
            size_t v_idx1 = fuzz_pilot % num_versions;
            fuzz_pilot >>= 4;
            size_t v_idx2 = fuzz_pilot % num_versions;
            fuzz_pilot >>= 4;

            if (v_idx1 != v_idx2) {
                uint8_t* ptr1 = version_list_start + (v_idx1 * 4);
                uint8_t* ptr2 = version_list_start + (v_idx2 * 4);
                if (ptr1 + 4 <= bytes + original_current_length && ptr2 + 4 <= bytes + original_current_length) {
                    uint32_t temp_version = picoquic_val32be(ptr1);
                    memcpy(ptr1, ptr2, 4);
                    picoquic_val32be_to_bytes(temp_version, ptr2);
                }
            }
        }
        break;

    default: /* No specific VN fuzz or other choices, could be random byte on versions */
        if (version_list_len > 0 && version_list_start < bytes + current_length ) { /* check version_list_len > 0 */
            size_t fuzz_offset_in_list = fuzz_pilot % version_list_len;
            fuzz_pilot >>= 6; 
            version_list_start[fuzz_offset_in_list] ^= (uint8_t)(fuzz_pilot & 0xFF);
        }
        break;
    }

    /* Ensure current_length is not less than vn_header_len, especially after truncation. */
    if (current_length < vn_header_len) {
        current_length = vn_header_len;
    }
    /* Ensure current_length does not exceed bytes_max */
    if (current_length > bytes_max) {
        current_length = bytes_max;
    }

    return current_length;
}

/* Create retry_packet_fuzzer function */
size_t retry_packet_fuzzer(uint64_t fuzz_pilot, uint8_t* bytes, size_t current_length, size_t bytes_max)
{
    size_t original_length = current_length;

    /* Minimum length: 1 (type) + 4 (version) + 1 (DCID len) + 0 (DCID) + 1 (SCID len) + 0 (SCID) + 0 (token) + 16 (tag) = 23 */
    /* However, RFC 9000 states first byte is 0xF?, Version (4), DCID Len (1), DCID (0-20), SCID Len (1), SCID (0-20), Retry Token, Integrity Tag (16) */
    /* Smallest possible ODCID is 0 length, so ODCID Len byte itself is not present in Retry Packet as per Figure 18.
     * The packet contains DCID and SCID, which are the server's choice for its new CIDs.
     * The ODCID is what the client initially sent. It's implicitly used for the tag calculation but not in the packet fields directly other than for token generation.
     * The header contains: Type (1), Version (4), DCID Len (1), DCID (dcid_len), SCID Len (1), SCID (scid_len).
     * So minimal header before token is 1+4+1+0+1+0 = 7.
     * Minimal packet is 7 (header) + 0 (token) + 16 (tag) = 23.
     */
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
    case 0: /* Corrupt First Byte (lower 4 bits - "unused" in RFC for Retry type 0xF) */
        bytes[0] ^= (uint8_t)(fuzz_pilot & 0x0F);
        break;

    case 1: /* Corrupt Version (one byte of it) */
        if (original_length >= 5) { 
            bytes[1 + (fuzz_pilot % 4)] ^= (uint8_t)(fuzz_pilot >> 2);
        }
        break;

    case 2: /* Flip random bytes in Token */
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

    case 3: /* Corrupt Retry Integrity Tag */
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

    case 4: /* Truncate Packet: Cut off part of Integrity Tag */
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

    case 5: /* Truncate Packet: Cut off part of Token (and all of Integrity Tag) */
        if (token_len > 0) {
            size_t cut_amount = 1 + (fuzz_pilot % token_len);
            fuzz_pilot >>= (token_len > 1 ? picoquic_max_bits(token_len-1):1);
            current_length = (token_start - bytes) + (token_len - cut_amount);
        } else if (original_length > (scid_len_offset + 1 + scid_len)) {
            current_length = scid_len_offset + 1 + scid_len;
        }
        break;

    case 6: /* Extend Packet and corrupt tag */
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
                     /* Check if original_tag_loc is still within the potentially shorter current_length after other fuzzing.
                      * However, this case extends, so original_length is the key.
                      * The goal is to corrupt the *original* tag bytes if they are not part of the *new* tag location.
                      */
                    if (original_tag_loc < bytes + current_length - 16) { 
                         original_tag_loc[fuzz_pilot % 16] ^= (uint8_t)((fuzz_pilot>>4)&0xFF);
                    }
                }
            }
        }
        break;

    case 7: /* Zero out DCID len */
        if (original_length > 5) bytes[5] = 0;
        break;

    case 8: /* Zero out SCID len */
         if (scid_len_offset < original_length) bytes[scid_len_offset] = 0;
        break;
        
    default: 
        {
            size_t header_and_cid_len = scid_len_offset + 1 + scid_len;
            if (header_and_cid_len > 0) {
                 size_t flip_idx = fuzz_pilot % header_and_cid_len;
                 if (flip_idx < original_length) { // Ensure flip_idx is within original bounds
                    bytes[flip_idx] ^= (uint8_t)((fuzz_pilot >> 6) & 0xFF);
                 }
            } else if (token_len > 0) { 
                 size_t flip_idx = fuzz_pilot % token_len;
                 token_start[flip_idx] ^= (uint8_t)((fuzz_pilot >> 6) & 0xFF);
            }
        }
        break;
    }

    size_t min_hdr_len_for_retry = 1 + 4 + 1 + 0 + 1 + 0; /* type, ver, dcid_len, 0-dcid, scid_len, 0-scid */
    if (current_length < min_hdr_len_for_retry + 16) { /* min header + tag */
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

uint32_t fuzi_q_fuzzer(void* fuzz_ctx, picoquic_cnx_t* cnx,
    uint8_t* bytes, size_t bytes_max, size_t length, size_t header_length)
{
    /* Get the global fuzzing context */
    fuzzer_ctx_t* ctx = (fuzzer_ctx_t*)fuzz_ctx;
    /* Get the fuzzing context for this CID */
    uint64_t current_time = picoquic_get_quic_time(cnx->quic);
    fuzzer_icid_ctx_t* icid_ctx = fuzzer_get_icid_ctx(ctx, &cnx->initial_cnxid, current_time);
    uint64_t fuzz_pilot = picoquic_test_random(&icid_ctx->random_context);
    fuzzer_cnx_state_enum fuzz_cnx_state = fuzzer_get_cnx_state(cnx);
    uint32_t fuzzed_length = (uint32_t)length;

    /* Check for Version Negotiation Packet */
    if (length >= 5 && (bytes[0] & 0x80) != 0 && picoquic_val32be(bytes + 1) == 0x00000000) {
        if (icid_ctx != NULL && icid_ctx->target_state < fuzzer_cnx_state_max && icid_ctx->target_state >= 0 &&
            (!icid_ctx->already_fuzzed || ((fuzz_pilot & 0xf) <= 7))) { 
            
            fuzz_pilot >>=4; 

            uint8_t dcid_len = 0;
            uint8_t scid_len = 0;
            size_t vn_header_len = 1 + 4; /* Type + Version Zero */

            if (length >= vn_header_len + 1) { /* Check space for DCID len */
                dcid_len = bytes[vn_header_len];
                vn_header_len += 1 + dcid_len;
                if (length >= vn_header_len + 1) { /* Check space for SCID len */
                    scid_len = bytes[vn_header_len - dcid_len]; /* SCID len is after DCID value */
                    vn_header_len += 1 + scid_len;

                    if (vn_header_len <= length) { /* Check if calculated header is valid */
                         /* Only call VN fuzzer if there's potential for a version list, 
                            though VN fuzzer itself can handle empty list case.
                            The prompt says vn_header_len < current_length, so we ensure there's *some* list.
                         */
                        if (vn_header_len < length) { 
                            fuzzed_length = (uint32_t)version_negotiation_packet_fuzzer(fuzz_pilot, bytes, vn_header_len, length, bytes_max);
                        }
                        /* Update fuzzing stats for VN packet */
                        if (icid_ctx->already_fuzzed == 0) {
                            icid_ctx->already_fuzzed = 1;
                             ctx->nb_cnx_tried[icid_ctx->target_state] += 1; /* Or a specific VN counter? */
                             ctx->nb_cnx_fuzzed[fuzz_cnx_state] += 1;
                        }
                        ctx->nb_packets_fuzzed[fuzz_cnx_state] +=1;
                        return fuzzed_length;
                    }
                }
            }
        }
        /* If not fuzzed (e.g. already_fuzzed and no fuzz_again), return original length for VN */
        return (uint32_t)length;
    }
    /* Check for Retry Packet */
    /* Condition: Type bits are 0xF (Retry), and it's not a VN packet (version is not 0) */
    /* Also ensure length is minimal for a retry packet (e.g. >= 23 bytes) */
    else if (length >= 23 && (bytes[0] & 0xF0) == 0xF0 && (length < 5 || picoquic_val32be(bytes + 1) != 0x00000000) ) {
        if (icid_ctx != NULL && icid_ctx->target_state < fuzzer_cnx_state_max && icid_ctx->target_state >= 0 &&
            (!icid_ctx->already_fuzzed || ((fuzz_pilot & 0xf) <= 7))) {
            
            fuzz_pilot >>=4; /* Consume already_fuzzed choice bits */
            fuzzed_length = (uint32_t)retry_packet_fuzzer(fuzz_pilot, bytes, length, bytes_max);

            if (icid_ctx->already_fuzzed == 0) {
                icid_ctx->already_fuzzed = 1;
                ctx->nb_cnx_tried[icid_ctx->target_state] += 1; /* Or a specific Retry counter? */
                ctx->nb_cnx_fuzzed[fuzz_cnx_state] += 1;
            }
            ctx->nb_packets_fuzzed[fuzz_cnx_state] +=1;
            return fuzzed_length;
        }
        return (uint32_t)length; /* Not fuzzed due to already_fuzzed logic */
    }


    int fuzz_again = ((fuzz_pilot & 0xf) <= 7); 

    if (fuzz_cnx_state < 0 || fuzz_cnx_state >= fuzzer_cnx_state_max) {
        fuzz_cnx_state = fuzzer_cnx_state_closing;
    }

    /* fuzz_pilot was already shifted by 4 if VN packet was not identified and fuzzed.
     * If VN packet was identified, its fuzz_pilot was shifted.
     * The main fuzzing logic needs its own shift if it's not a VN packet.
     */
    /* The main fuzz_pilot shift (fuzz_pilot >>= 4;) is done after the VN check. */


    if (icid_ctx != NULL && icid_ctx->target_state < fuzzer_cnx_state_max && icid_ctx->target_state >= 0) {
        fuzz_pilot >>= 4; /* Shift pilot for main fuzzing logic if not VN */
        ctx->nb_packets++;
        ctx->nb_packets_state[fuzz_cnx_state] += 1;
        icid_ctx->wait_count[fuzz_cnx_state]++;
        /* Compute the max number of packets that could be waited for.
         */
        if (!icid_ctx->already_fuzzed && fuzz_cnx_state != fuzzer_cnx_state_closing &&
            icid_ctx->wait_count[fuzz_cnx_state] > ctx->wait_max[fuzz_cnx_state]) {
            ctx->wait_max[fuzz_cnx_state] = icid_ctx->wait_count[fuzz_cnx_state];
        }
        /* Only perform fuzzing if the connection has reached or passed the target state. */
        if ((fuzz_cnx_state > icid_ctx->target_state ||
            (fuzz_cnx_state == icid_ctx->target_state &&
                icid_ctx->wait_count[fuzz_cnx_state] >= icid_ctx->target_wait)) &&
            (!icid_ctx->already_fuzzed || fuzz_again)) {
            /* Based on the fuzz pilot, pick one of the following */
            uint64_t next_step = fuzz_pilot & 0x03;
            size_t final_pad = length_non_padded(bytes, length, header_length);
            size_t fuzz_frame_id = (size_t)((fuzz_pilot >> 3) % nb_fuzi_q_frame_list);
            size_t len = fuzi_q_frame_list[fuzz_frame_id].len;
            int fuzz_more = ((fuzz_pilot >> 8) & 1) > 0;
            int was_fuzzed = 0;
            fuzz_pilot >>= 9;

            switch (next_step) {
            case 0:
                if (final_pad + len <= bytes_max) {
                    /* First test variant: add a random frame at the end of the packet */
                    memcpy(&bytes[final_pad], fuzi_q_frame_list[fuzz_frame_id].val, len);
                    final_pad += len;
                    was_fuzzed++;
                }
                break;
            case 1:
                if (final_pad + len <= bytes_max) {
                    /* Second test variant: add a random frame at the beginning of the packet */
                    memmove(bytes + header_length + len, bytes + header_length, final_pad);
                    memcpy(&bytes[header_length], fuzi_q_frame_list[fuzz_frame_id].val, len);
                    final_pad += len;
                    was_fuzzed++;
                }
                break;
            case 2:
                if (header_length + len <= bytes_max) {
                    /* Third test variant: replace the packet by a random frame */
                    memcpy(&bytes[header_length], fuzi_q_frame_list[fuzz_frame_id].val, len);
                    was_fuzzed++;
                    final_pad = header_length + len;
                }
                break;
            default:
                len = 0;
                break;
            }
            /* TODO: based on the fuzz pilot, consider padding multiple frames */

            if (final_pad > length) {
                fuzzed_length = (uint32_t)final_pad;
            }
            else {
                /* If there is room left, pad. */
                memset(&bytes[header_length + len], 0, length - (header_length + len));
            }

            if (!was_fuzzed || fuzz_more) {
                was_fuzzed |= frame_header_fuzzer(ctx, icid_ctx, fuzz_pilot, bytes, bytes_max, final_pad, header_length);
                if (!was_fuzzed) {
                    fuzzed_length = basic_packet_fuzzer(ctx, fuzz_pilot, bytes, bytes_max, length, header_length);
                }
            }
            
            /* Step 5: Implement "Immediate Retire" logic */
            if (((fuzz_pilot >> 20) & 0x03) == 0) { /* Approx 1-in-4 chance, using different pilot bits */
                if (icid_ctx->new_cid_seq_no_available == 1) {
                    uint8_t retire_frame_buffer[24]; /* Max type varint + max seq_no varint */
                    uint8_t* p_retire = retire_frame_buffer;
                    uint8_t* p_retire_max = retire_frame_buffer + sizeof(retire_frame_buffer);

                    p_retire = picoquic_frames_varint_encode(p_retire, p_retire_max, picoquic_frame_type_retire_connection_id);
                    if (p_retire != NULL) {
                        p_retire = picoquic_frames_varint_encode(p_retire, p_retire_max, icid_ctx->last_new_cid_seq_no_sent);
                    }

                    if (p_retire != NULL) {
                        size_t retire_len = p_retire - retire_frame_buffer;
                        /* Ensure final_pad reflects the true end of current frames before appending */
                        /* If fuzzed_length was changed by frame_header_fuzzer, use that as basis. */
                        /* However, frame_header_fuzzer returns int, not the length. */
                        /* We need to use `final_pad` which is calculated based on original `length` or `header_length + len` if replaced. */
                        /* If `was_fuzzed` by adding/replacing, `final_pad` is the new end. */
                        /* If `was_fuzzed` by `frame_header_fuzzer`, `final_pad` might not be accurate if `frame_header_fuzzer` changed length. */
                        /* Let's use `fuzzed_length` if it was modified by earlier steps, otherwise `final_pad`. */
                        size_t current_packet_end = fuzzed_length; /* fuzzed_length is current end of packet data */
                        
                        if (current_packet_end + retire_len <= bytes_max) {
                            memcpy(&bytes[current_packet_end], retire_frame_buffer, retire_len);
                            fuzzed_length = (uint32_t)(current_packet_end + retire_len);
                            /* was_fuzzed is already true or set by frame_header_fuzzer */
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

        /* Mark the connection as active */
        if (ctx->parent != NULL) {
            /* Mark active */
            fuzi_q_mark_active(ctx->parent, &icid_ctx->icid, current_time, icid_ctx->already_fuzzed);
        }
    }

    return fuzzed_length;
}
