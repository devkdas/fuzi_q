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
#include <picoquic_internal.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "fuzi_q.h"

/* This module holds a collection of QUIc frames, that can be inserted at
 * random positions in fuzzed frames.
 * 
 * The first set of test frames is copied for picoquic tests.
 */

static uint8_t test_frame_type_padding[] = { 0, 0, 0 };

static uint8_t test_frame_type_padding_5_bytes[] = { 0, 0, 0, 0, 0 };

static uint8_t test_frame_type_padding_7_bytes[] = { 0, 0, 0, 0, 0, 0, 0 };

static uint8_t test_frame_type_padding_13_bytes[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

static uint8_t test_frame_padding_2_bytes[] = { 0x00, 0x00 };

static uint8_t test_frame_padding_10_bytes[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

static uint8_t test_frame_padding_50_bytes[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 10
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 20
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 30
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 40
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // 50
};

static uint8_t test_frame_type_reset_stream[] = {
    picoquic_frame_type_reset_stream,
    17,
    1,
    1
};

static uint8_t test_frame_type_reset_stream_high_error[] = {
    picoquic_frame_type_reset_stream,
    0x11,
    0xBF, 0xFF, 0xAA, 0xAA, // Application Protocol Error Code: 0x3FFFAAAA
    0x41, 0x00 // Final Size: 0x100
};

static uint8_t test_frame_reset_stream_min_vals[] = {
    picoquic_frame_type_reset_stream, 0x00, 0x00, 0x00
};

static uint8_t test_frame_reset_stream_max_final_size[] = {
    picoquic_frame_type_reset_stream, 0x01, 0x00,
    0xBF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 // Varint for 0x3F00112233445566
};

static uint8_t test_frame_reset_stream_app_error_specific[] = {
    picoquic_frame_type_reset_stream, 0x02, 0x41, 0x00, 0x42, 0x00
};

static uint8_t test_type_connection_close[] = {
    picoquic_frame_type_connection_close,
    0x80, 0x00, 0xCF, 0xFF, 0,
    9,
    '1', '2', '3', '4', '5', '6', '7', '8', '9'
};

static uint8_t test_frame_connection_close_transport_long_reason[] = {
    picoquic_frame_type_connection_close, 0x1A, 0x00, 0x20,
    'T','h','i','s',' ','i','s',' ','a',' ','v','e','r','y',' ','l','o','n','g',' ','t','e','s','t',' ','r','e','a','s','o','n','.'
};

static uint8_t test_type_application_close[] = {
    picoquic_frame_type_application_close,
    0,
    0
};

static uint8_t test_type_application_close_reason[] = {
    picoquic_frame_type_application_close,
    0x44, 4,
    4,
    't', 'e', 's', 't'
};

static uint8_t test_frame_application_close_long_reason[] = {
    picoquic_frame_type_application_close, 0x2B, 0x1E,
    'A','n','o','t','h','e','r',' ','l','o','n','g',' ','a','p','p','l','i','c','a','t','i','o','n',' ','e','r','r','o','r','.'
};

static uint8_t test_frame_type_max_data[] = {
    picoquic_frame_type_max_data,
    0xC0, 0, 0x01, 0, 0, 0, 0, 0
};

static uint8_t test_frame_type_max_data_large[] = {
    picoquic_frame_type_max_data,
    0xBF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF
};

static uint8_t test_frame_max_data_zero[] = {
    picoquic_frame_type_max_data, 0x00
};

static uint8_t test_frame_type_max_stream_data[] = {
    picoquic_frame_type_max_stream_data,
    1,
    0x80, 0x01, 0, 0
};

static uint8_t test_frame_max_stream_data_zero[] = {
    picoquic_frame_type_max_stream_data, 0x02, 0x00
};

static uint8_t test_frame_type_max_streams_bidir[] = {
    picoquic_frame_type_max_streams_bidir,
    0x41, 0
};

static uint8_t test_frame_type_max_streams_unidir[] = {
    picoquic_frame_type_max_streams_unidir,
    0x41, 7
};

static uint8_t test_frame_type_max_streams_bidir_alt[] = {
    picoquic_frame_type_max_streams_bidir,
    0x42, 0x0A
};

static uint8_t test_frame_type_max_streams_bidir_zero[] = {
    picoquic_frame_type_max_streams_bidir,
    0x00
};

static uint8_t test_frame_max_streams_bidi_very_high[] = {
    picoquic_frame_type_max_streams_bidir, 0xBF, 0xFF, 0xFF, 0xFF
};

static uint8_t test_frame_type_max_streams_unidir_zero[] = {
    picoquic_frame_type_max_streams_unidir,
    0x00
};

static uint8_t test_frame_max_streams_uni_very_high[] = {
    picoquic_frame_type_max_streams_unidir, 0xBF, 0xFF, 0xFF, 0xFE
};

static uint8_t test_frame_type_ping[] = {
    picoquic_frame_type_ping
};

static uint8_t test_frame_type_blocked[] = {
    picoquic_frame_type_data_blocked,
    0x80, 0x01, 0, 0
};

static uint8_t test_frame_type_data_blocked_large_offset[] = {
    picoquic_frame_type_data_blocked,
    0xBF, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE
};

static uint8_t test_frame_type_stream_blocked[] = {
    picoquic_frame_type_stream_data_blocked,
    0x80, 1, 0, 0,
    0x80, 0x02, 0, 0
};

static uint8_t test_frame_type_stream_data_blocked_large_limits[] = {
    picoquic_frame_type_stream_data_blocked,
    0xBA, 0x1B, 0x2C, 0x3D, // Stream ID
    0xBE, 0x4F, 0x5D, 0x6C  // Stream Data Limit
};

static uint8_t test_frame_type_streams_blocked_bidir[] = {
    picoquic_frame_type_streams_blocked_bidir,
    0x41, 0
};

static uint8_t test_frame_type_streams_blocked_unidir[] = {
    picoquic_frame_type_streams_blocked_unidir,
    0x81, 2, 3, 4
};

static uint8_t test_frame_type_new_connection_id[] = {
    picoquic_frame_type_new_connection_id,
    7,
    0,
    8,
    1, 2, 3, 4, 5, 6, 7, 8,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF
};

static uint8_t test_frame_type_stop_sending[] = {
    picoquic_frame_type_stop_sending,
    17,
    0x17
};

static uint8_t test_frame_type_stop_sending_high_error[] = {
    picoquic_frame_type_stop_sending,
    0x12,
    0xBF, 0xFF, 0xBB, 0xBB // Application Protocol Error Code: 0x3FFFBBBB
};

static uint8_t test_frame_stop_sending_min_vals[] = {
    picoquic_frame_type_stop_sending, 0x00, 0x00
};

static uint8_t test_frame_stop_sending_app_error_specific[] = {
    picoquic_frame_type_stop_sending, 0x01, 0x41, 0x00
};

static uint8_t test_frame_type_path_challenge[] = {
    picoquic_frame_type_path_challenge,
    1, 2, 3, 4, 5, 6, 7, 8
};

static uint8_t test_frame_type_path_challenge_alt_data[] = {
    picoquic_frame_type_path_challenge,
    0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88
};

static uint8_t test_frame_type_path_response[] = {
    picoquic_frame_type_path_response,
    1, 2, 3, 4, 5, 6, 7, 8
};

static uint8_t test_frame_type_path_response_alt_data[] = {
    picoquic_frame_type_path_response,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
};

static uint8_t test_frame_type_new_token[] = {
    picoquic_frame_type_new_token,
    17, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17
};

static uint8_t test_frame_new_token_long[] = {
    picoquic_frame_type_new_token, 0x40, 0x64,
    0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB, // 10
    0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB, // 20
    0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB, // 30
    0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB, // 40
    0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB, // 50
    0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB, // 60
    0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB, // 70
    0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB, // 80
    0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB, // 90
    0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB  // 100
};

static uint8_t test_frame_new_token_short[] = {
    picoquic_frame_type_new_token, 0x08, 0xCD,0xCD,0xCD,0xCD,0xCD,0xCD,0xCD,0xCD
};

static uint8_t test_frame_type_ack[] = {
    picoquic_frame_type_ack,
    0xC0, 0, 0, 1, 2, 3, 4, 5,
    0x44, 0,
    2,
    5,
    0, 0,
    5, 12
};

static uint8_t test_frame_ack_empty[] = {
    picoquic_frame_type_ack, 0x0A, 0x01, 0x00, 0x00
};

static uint8_t test_frame_ack_multiple_ranges[] = {
    picoquic_frame_type_ack, 0x20, 0x02, 0x03, 0x02,  0x01, 0x04,  0x03, 0x01,  0x05, 0x0A
};

static uint8_t test_frame_ack_large_delay[] = {
    picoquic_frame_type_ack, 0x05, 0x7F, 0xFF, /*0x3FFF encoded*/ 0x00, 0x01
};

static uint8_t test_frame_type_ack_ecn[] = {
    picoquic_frame_type_ack_ecn,
    0xC0, 0, 0, 1, 2, 3, 4, 5,
    0x44, 0,
    2,
    5,
    0, 0,
    5, 12,
    3, 0, 1
};

static uint8_t test_frame_ack_ecn_counts_high[] = {
    picoquic_frame_type_ack_ecn, 0x10, 0x01, 0x00, 0x00,  0x41, 0x00,  0x42, 0x00,  0x43, 0x00
};

static uint8_t test_frame_type_stream_range_min[] = {
    picoquic_frame_type_stream_range_min,
    1,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF
};

static uint8_t test_frame_type_stream_range_max[] = {
    picoquic_frame_type_stream_range_min + 2 + 4,
    1,
    0x44, 0,
    0x10,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF
};

static uint8_t test_frame_stream_no_offset_no_len_fin[] = { 0x09, 0x01, 'd','a','t','a' };
static uint8_t test_frame_stream_offset_no_len_no_fin[] = { 0x0C, 0x01, 0x40, 0x20, 'd','a','t','a' };
static uint8_t test_frame_stream_no_offset_len_no_fin[] = { 0x0A, 0x01, 0x04, 'd','a','t','a' };
static uint8_t test_frame_stream_all_bits_set[] = { 0x0F, 0x01, 0x40, 0x20, 0x04, 'd','a','t','a' };
static uint8_t test_frame_stream_zero_len_data[] = { 0x0A, 0x01, 0x00 };
static uint8_t test_frame_stream_max_offset_final[] = { 0x0D, 0x01, 0x52, 0x34, 'e','n','d' };

static uint8_t test_frame_type_crypto_hs[] = {
    picoquic_frame_type_crypto_hs,
    0,
    0x10,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF
};

static uint8_t test_frame_type_crypto_hs_alt[] = {
    picoquic_frame_type_crypto_hs,
    0x40, 0x10, /* Offset */
    0x08, /* Length */
    0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7 /* Crypto Data */
};

static uint8_t test_frame_crypto_zero_len[] = {
    picoquic_frame_type_crypto, 0x00, 0x00
};

static uint8_t test_frame_crypto_large_offset[] = {
    picoquic_frame_type_crypto, 0x50, 0x00, 0x05, 'd','u','m','m','y'
};

static uint8_t test_frame_crypto_fragment1[] = {
    picoquic_frame_type_crypto, 0x00, 0x05, 'H','e','l','l','o'
};

static uint8_t test_frame_crypto_fragment2[] = {
    picoquic_frame_type_crypto, 0x05, 0x05, 'W','o','r','l','d'
};

static uint8_t test_frame_type_retire_connection_id[] = {
    picoquic_frame_type_retire_connection_id,
    1
};

static uint8_t test_frame_type_datagram[] = {
    picoquic_frame_type_datagram,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF
};

static uint8_t test_frame_type_datagram_l[] = {
    picoquic_frame_type_datagram_l,
    0x10,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF
};

static uint8_t test_frame_type_handshake_done[] = {
    picoquic_frame_type_handshake_done
};

static uint8_t test_frame_type_ack_frequency[] = {
    0x40, picoquic_frame_type_ack_frequency,
    17, 0x0A, 0x44, 0x20, 0x01
};

static uint8_t test_frame_type_time_stamp[] = {
    (uint8_t)(0x40 | (picoquic_frame_type_time_stamp >> 8)), (uint8_t)(picoquic_frame_type_time_stamp & 0xFF),
    0x44, 0
};

static uint8_t test_frame_type_path_abandon_0[] = {
    (uint8_t)(0x80 | (picoquic_frame_type_path_abandon >> 24)), (uint8_t)(picoquic_frame_type_path_abandon >> 16),
    (uint8_t)(picoquic_frame_type_path_abandon >> 8), (uint8_t)(picoquic_frame_type_path_abandon & 0xFF),
    0x01, /* Path 0 */
    0x00 /* No error */
};

static uint8_t test_frame_type_path_abandon_1[] = {
    (uint8_t)(0x80 | (picoquic_frame_type_path_abandon >> 24)), (uint8_t)(picoquic_frame_type_path_abandon >> 16),
    (uint8_t)(picoquic_frame_type_path_abandon >> 8), (uint8_t)(picoquic_frame_type_path_abandon & 0xFF),
    0x01,
    0x11 /* Some new error */
};

static uint8_t test_frame_type_path_backup[] = {
    (uint8_t)(0x80 | (picoquic_frame_type_path_backup >> 24)), (uint8_t)(picoquic_frame_type_path_backup >> 16),
    (uint8_t)(picoquic_frame_type_path_backup >> 8), (uint8_t)(picoquic_frame_type_path_backup & 0xFF),
    0x00, /* Path 0 */
    0x0F, /* Sequence = 0x0F */
};

static uint8_t test_frame_type_path_available[] = {
    (uint8_t)(0x80 | (picoquic_frame_type_path_available >> 24)), (uint8_t)(picoquic_frame_type_path_available >> 16),
    (uint8_t)(picoquic_frame_type_path_available >> 8), (uint8_t)(picoquic_frame_type_path_available & 0xFF),
    0x00, /* Path 0 */
    0x0F, /* Sequence = 0x0F */
};

static uint8_t test_frame_type_path_blocked[] = {
    (uint8_t)(0x80 | (picoquic_frame_type_paths_blocked >> 24)), (uint8_t)(picoquic_frame_type_paths_blocked >> 16),
    (uint8_t)(picoquic_frame_type_paths_blocked >> 8), (uint8_t)(picoquic_frame_type_paths_blocked & 0xFF),
    0x11, /* max paths = 17 */
};

static uint8_t test_frame_type_bdp[] = {
    (uint8_t)(0x80 | (picoquic_frame_type_bdp >> 24)), (uint8_t)(picoquic_frame_type_bdp >> 16),
    (uint8_t)(picoquic_frame_type_bdp >> 8), (uint8_t)(picoquic_frame_type_bdp & 0xFF),
    0x01, 0x02, 0x03,
    0x04, 0x0A, 0x0, 0x0, 0x01
};

static uint8_t test_frame_type_bad_reset_stream_offset[] = {
    picoquic_frame_type_reset_stream,
    17,
    1,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

static uint8_t test_frame_type_bad_reset_stream[] = {
    picoquic_frame_type_reset_stream,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    1,
    1
};

static uint8_t test_type_bad_connection_close[] = {
    picoquic_frame_type_connection_close,
    0x80, 0x00, 0xCF, 0xFF, 0,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    '1', '2', '3', '4', '5', '6', '7', '8', '9'
};


static uint8_t test_type_bad_application_close[] = {
    picoquic_frame_type_application_close,
    0x44, 4,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    't', 'e', 's', 't'
};

static uint8_t test_frame_type_bad_max_stream_stream[] = {
    picoquic_frame_type_max_stream_data,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x80, 0x01, 0, 0
};

static uint8_t test_frame_type_max_bad_streams_bidir[] = {
    picoquic_frame_type_max_streams_bidir,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

static uint8_t test_frame_type_bad_max_streams_unidir[] = {
    picoquic_frame_type_max_streams_unidir,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

static uint8_t test_frame_type_bad_new_cid_length[] = {
    picoquic_frame_type_new_connection_id,
    7,
    0,
    0x3F,
    1, 2, 3, 4, 5, 6, 7, 8,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF
};

static uint8_t test_frame_type_bad_new_cid_retire[] = {
    picoquic_frame_type_new_connection_id,
    7,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    8,
    1, 2, 3, 4, 5, 6, 7, 8,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF
};

static uint8_t test_frame_type_bad_stop_sending[] = {
    picoquic_frame_type_stop_sending,
    19,
    0x17
};

static uint8_t test_frame_type_bad_new_token[] = {
    picoquic_frame_type_new_token,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17
};

static uint8_t test_frame_type_bad_ack_range[] = {
    picoquic_frame_type_ack,
    0xC0, 0, 0, 1, 2, 3, 4, 5,
    0x44, 0,
    2,
    5,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0,
    5, 12
};

static uint8_t test_frame_type_bad_ack_gaps[] = {
    picoquic_frame_type_ack,
    0xC0, 0, 0, 1, 2, 3, 4, 5,
    0x44, 0,
    2,
    5,
    0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    5, 12
};

static uint8_t test_frame_type_bad_ack_blocks[] = {
    picoquic_frame_type_ack_ecn,
    0xC0, 0, 0, 1, 2, 3, 4, 5,
    0x44, 0,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    5,
    0, 0,
    5, 12,
    3, 0, 1
};

static uint8_t test_frame_type_bad_crypto_hs[] = {
    picoquic_frame_type_crypto_hs,
    0,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF
};

static uint8_t test_frame_type_bad_datagram[] = {
    picoquic_frame_type_datagram_l,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF
};

static uint8_t test_frame_type_new_connection_id_alt[] = {
    picoquic_frame_type_new_connection_id,
    0x0A, /* Sequence Number */
    0x03, /* Retire Prior To */
    8,    /* Length */
    8, 7, 6, 5, 4, 3, 2, 1, /* Connection ID */
    0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7,
    0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF /* Stateless Reset Token */
};

static uint8_t test_frame_stream_hang[] = {
    0x01, 0x00, 0x0D, 0xFF, 0xFF, 0xFF, 0x01, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

static uint8_t test_frame_type_path_abandon_bad_0[] = {
    (uint8_t)(0x80 | (picoquic_frame_type_path_abandon >> 24)), (uint8_t)(picoquic_frame_type_path_abandon >> 16),
    (uint8_t)(picoquic_frame_type_path_abandon >> 8), (uint8_t)(picoquic_frame_type_path_abandon & 0xFF),
    0x00, /* type 0 */
    /* 0x01, missing type */
    0x00, /* No error */
    0x00 /* No phrase */
};

static uint8_t test_frame_type_path_abandon_bad_1[] = {
    (uint8_t)(0x80 | (picoquic_frame_type_path_abandon >> 24)),
    (uint8_t)(picoquic_frame_type_path_abandon >> 16),
    (uint8_t)(picoquic_frame_type_path_abandon >> 8),
    (uint8_t)(picoquic_frame_type_path_abandon & 0xFF),
    0x01, /* type 1 */
    0x01,
    0x11, /* Some new error */
    0x4f,
    0xff, /* bad length */
    (uint8_t)'b',
    (uint8_t)'a',
    (uint8_t)'d',
};

static uint8_t test_frame_type_path_abandon_bad_2[] = {
    (uint8_t)(0x80 | (picoquic_frame_type_path_abandon >> 24)), (uint8_t)(picoquic_frame_type_path_abandon >> 16),
    (uint8_t)(picoquic_frame_type_path_abandon >> 8), (uint8_t)(picoquic_frame_type_path_abandon & 0xFF),
    0x03, /* unknown type */
    0x00, /* No error */
    0x00 /* No phrase */
};


static uint8_t test_frame_type_bdp_bad[] = {
    (uint8_t)(0x80 | (picoquic_frame_type_bdp >> 24)), (uint8_t)(picoquic_frame_type_bdp >> 16),
    (uint8_t)(picoquic_frame_type_bdp >> 8), (uint8_t)(picoquic_frame_type_bdp & 0xFF),
    0x01, 0x02, 0x04
};

static uint8_t test_frame_type_bdp_bad_addr[] = {
    (uint8_t)(0x80 | (picoquic_frame_type_bdp >> 24)), (uint8_t)(picoquic_frame_type_bdp >> 16),
    (uint8_t)(picoquic_frame_type_bdp >> 8), (uint8_t)(picoquic_frame_type_bdp & 0xFF),
    0x01, 0x02, 0x04, 0x05, 1, 2, 3, 4, 5
};

static uint8_t test_frame_type_bdp_bad_length[] = {
    (uint8_t)(0x80 | (picoquic_frame_type_bdp >> 24)), (uint8_t)(picoquic_frame_type_bdp >> 16),
    (uint8_t)(picoquic_frame_type_bdp >> 8), (uint8_t)(picoquic_frame_type_bdp & 0xFF),
    0x08, 0x02, 0x04, 0x8F, 0xFF, 0xFF, 0xFF, 1, 2, 3, 4
};

#define FUZI_Q_ITEM(n, x) \
    {                        \
        n, x, sizeof(x),     \
    }

fuzi_q_frames_t fuzi_q_frame_list[] = {
    FUZI_Q_ITEM("padding", test_frame_type_padding),
    FUZI_Q_ITEM("padding_2_bytes", test_frame_padding_2_bytes),
    FUZI_Q_ITEM("padding_5_bytes", test_frame_type_padding_5_bytes),
    FUZI_Q_ITEM("padding_7_bytes", test_frame_type_padding_7_bytes),
    FUZI_Q_ITEM("padding_10_bytes", test_frame_padding_10_bytes),
    FUZI_Q_ITEM("padding_13_bytes", test_frame_type_padding_13_bytes),
    FUZI_Q_ITEM("padding_50_bytes", test_frame_padding_50_bytes),
    FUZI_Q_ITEM("reset_stream", test_frame_type_reset_stream),
    FUZI_Q_ITEM("reset_stream_high_error", test_frame_type_reset_stream_high_error),
    FUZI_Q_ITEM("reset_stream_min_vals", test_frame_reset_stream_min_vals),
    FUZI_Q_ITEM("reset_stream_max_final_size", test_frame_reset_stream_max_final_size),
    FUZI_Q_ITEM("reset_stream_app_error_specific", test_frame_reset_stream_app_error_specific),
    FUZI_Q_ITEM("connection_close", test_type_connection_close),
    FUZI_Q_ITEM("connection_close_transport_long_reason", test_frame_connection_close_transport_long_reason),
    FUZI_Q_ITEM("application_close", test_type_application_close),
    FUZI_Q_ITEM("application_close", test_type_application_close_reason),
    FUZI_Q_ITEM("application_close_long_reason", test_frame_application_close_long_reason),
    FUZI_Q_ITEM("max_data", test_frame_type_max_data),
    FUZI_Q_ITEM("max_data_large", test_frame_type_max_data_large),
    FUZI_Q_ITEM("max_data_zero", test_frame_max_data_zero),
    FUZI_Q_ITEM("max_stream_data", test_frame_type_max_stream_data),
    FUZI_Q_ITEM("max_stream_data_zero", test_frame_max_stream_data_zero),
    FUZI_Q_ITEM("max_streams_bidir", test_frame_type_max_streams_bidir),
    FUZI_Q_ITEM("max_streams_unidir", test_frame_type_max_streams_unidir),
    FUZI_Q_ITEM("max_streams_bidir_alt", test_frame_type_max_streams_bidir_alt),
    FUZI_Q_ITEM("max_streams_bidir_zero", test_frame_type_max_streams_bidir_zero),
    FUZI_Q_ITEM("max_streams_bidi_very_high", test_frame_max_streams_bidi_very_high),
    FUZI_Q_ITEM("max_streams_unidir_zero", test_frame_type_max_streams_unidir_zero),
    FUZI_Q_ITEM("max_streams_uni_very_high", test_frame_max_streams_uni_very_high),
    FUZI_Q_ITEM("ping", test_frame_type_ping),
    FUZI_Q_ITEM("blocked", test_frame_type_blocked),
    FUZI_Q_ITEM("data_blocked_large_offset", test_frame_type_data_blocked_large_offset),
    FUZI_Q_ITEM("stream_data_blocked", test_frame_type_stream_blocked),
    FUZI_Q_ITEM("stream_data_blocked_large_limits", test_frame_type_stream_data_blocked_large_limits),
    FUZI_Q_ITEM("streams_blocked_bidir", test_frame_type_streams_blocked_bidir),
    FUZI_Q_ITEM("streams_blocked_unidir", test_frame_type_streams_blocked_unidir),
    FUZI_Q_ITEM("new_connection_id", test_frame_type_new_connection_id),
    FUZI_Q_ITEM("new_connection_id_alt", test_frame_type_new_connection_id_alt),
    FUZI_Q_ITEM("stop_sending", test_frame_type_stop_sending),
    FUZI_Q_ITEM("stop_sending_high_error", test_frame_type_stop_sending_high_error),
    FUZI_Q_ITEM("stop_sending_min_vals", test_frame_stop_sending_min_vals),
    FUZI_Q_ITEM("stop_sending_app_error_specific", test_frame_stop_sending_app_error_specific),
    FUZI_Q_ITEM("challenge", test_frame_type_path_challenge),
    FUZI_Q_ITEM("path_challenge_alt_data", test_frame_type_path_challenge_alt_data),
    FUZI_Q_ITEM("response", test_frame_type_path_response),
    FUZI_Q_ITEM("path_response_alt_data", test_frame_type_path_response_alt_data),
    FUZI_Q_ITEM("new_token", test_frame_type_new_token),
    FUZI_Q_ITEM("new_token_long", test_frame_new_token_long),
    FUZI_Q_ITEM("new_token_short", test_frame_new_token_short),
    FUZI_Q_ITEM("ack", test_frame_type_ack),
    FUZI_Q_ITEM("ack_empty", test_frame_ack_empty),
    FUZI_Q_ITEM("ack_multiple_ranges", test_frame_ack_multiple_ranges),
    FUZI_Q_ITEM("ack_large_delay", test_frame_ack_large_delay),
    FUZI_Q_ITEM("ack_ecn", test_frame_type_ack_ecn),
    FUZI_Q_ITEM("ack_ecn_counts_high", test_frame_ack_ecn_counts_high),
    FUZI_Q_ITEM("stream_min", test_frame_type_stream_range_min),
    FUZI_Q_ITEM("stream_max", test_frame_type_stream_range_max),
    FUZI_Q_ITEM("stream_no_offset_no_len_fin", test_frame_stream_no_offset_no_len_fin),
    FUZI_Q_ITEM("stream_offset_no_len_no_fin", test_frame_stream_offset_no_len_no_fin),
    FUZI_Q_ITEM("stream_no_offset_len_no_fin", test_frame_stream_no_offset_len_no_fin),
    FUZI_Q_ITEM("stream_all_bits_set", test_frame_stream_all_bits_set),
    FUZI_Q_ITEM("stream_zero_len_data", test_frame_stream_zero_len_data),
    FUZI_Q_ITEM("stream_max_offset_final", test_frame_stream_max_offset_final),
    FUZI_Q_ITEM("crypto_hs", test_frame_type_crypto_hs),
    FUZI_Q_ITEM("crypto_hs_alt", test_frame_type_crypto_hs_alt),
    FUZI_Q_ITEM("crypto_zero_len", test_frame_crypto_zero_len),
    FUZI_Q_ITEM("crypto_large_offset", test_frame_crypto_large_offset),
    FUZI_Q_ITEM("crypto_fragment1", test_frame_crypto_fragment1),
    FUZI_Q_ITEM("crypto_fragment2", test_frame_crypto_fragment2),
    FUZI_Q_ITEM("retire_connection_id", test_frame_type_retire_connection_id),
    FUZI_Q_ITEM("datagram", test_frame_type_datagram),
    FUZI_Q_ITEM("datagram_l", test_frame_type_datagram_l),
    FUZI_Q_ITEM("handshake_done", test_frame_type_handshake_done),
    FUZI_Q_ITEM("ack_frequency", test_frame_type_ack_frequency),
    FUZI_Q_ITEM("time_stamp", test_frame_type_time_stamp),
    FUZI_Q_ITEM("path_abandon_0", test_frame_type_path_abandon_0),
    FUZI_Q_ITEM("path_abandon_1", test_frame_type_path_abandon_1),
    FUZI_Q_ITEM("path_available", test_frame_type_path_available),
    FUZI_Q_ITEM("path_backup", test_frame_type_path_backup),
    FUZI_Q_ITEM("path_blocked", test_frame_type_path_blocked),
    FUZI_Q_ITEM("bdp", test_frame_type_bdp),
    FUZI_Q_ITEM("bad_reset_stream_offset", test_frame_type_bad_reset_stream_offset),
    FUZI_Q_ITEM("bad_reset_stream", test_frame_type_bad_reset_stream),
    FUZI_Q_ITEM("bad_connection_close", test_type_bad_connection_close),
    FUZI_Q_ITEM("bad_application_close", test_type_bad_application_close),
    FUZI_Q_ITEM("bad_max_stream_stream", test_frame_type_bad_max_stream_stream),
    FUZI_Q_ITEM("bad_max_streams_bidir", test_frame_type_max_bad_streams_bidir),
    FUZI_Q_ITEM("bad_max_streams_unidir", test_frame_type_bad_max_streams_unidir),
    FUZI_Q_ITEM("bad_new_connection_id_length", test_frame_type_bad_new_cid_length),
    FUZI_Q_ITEM("bad_new_connection_id_retire", test_frame_type_bad_new_cid_retire),
    FUZI_Q_ITEM("bad_stop_sending", test_frame_type_bad_stop_sending),
    FUZI_Q_ITEM("bad_new_token", test_frame_type_bad_new_token),
    FUZI_Q_ITEM("bad_ack_range", test_frame_type_bad_ack_range),
    FUZI_Q_ITEM("bad_ack_gaps", test_frame_type_bad_ack_gaps),
    FUZI_Q_ITEM("bad_ack_blocks", test_frame_type_bad_ack_blocks),
    FUZI_Q_ITEM("bad_crypto_hs", test_frame_type_bad_crypto_hs),
    FUZI_Q_ITEM("bad_datagram", test_frame_type_bad_datagram),
    FUZI_Q_ITEM("stream_hang", test_frame_stream_hang),
    FUZI_Q_ITEM("bad_abandon_0", test_frame_type_path_abandon_bad_0),
    FUZI_Q_ITEM("bad_abandon_1", test_frame_type_path_abandon_bad_1),
    FUZI_Q_ITEM("bad_abandon_2", test_frame_type_path_abandon_bad_2),
    FUZI_Q_ITEM("bad_bdp", test_frame_type_bdp_bad),
    FUZI_Q_ITEM("bad_bdp", test_frame_type_bdp_bad_addr),
    FUZI_Q_ITEM("bad_bdp", test_frame_type_bdp_bad_length)
};

size_t nb_fuzi_q_frame_list = sizeof(fuzi_q_frame_list) / sizeof(fuzi_q_frames_t);
