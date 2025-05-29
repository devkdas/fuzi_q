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
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 10 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 20 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 30 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 40 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  /* 50 */
};

/* PADDING frame (type 0x00) followed by non-zero bytes that are part of the padding */
static uint8_t test_frame_padding_mixed_payload[] = {
    0x00,       /* Type: PADDING frame */
    0xFF,       /* Arbitrary byte 1 */
    0xAA,       /* Arbitrary byte 2 */
    0x55,       /* Arbitrary byte 3 */
    0xCC        /* Arbitrary byte 4 */
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
    0xBF, 0xFF, 0xAA, 0xAA, /* Application Protocol Error Code: 0x3FFFAAAA */
    0x41, 0x00 /* Final Size: 0x100 */
};

static uint8_t test_frame_reset_stream_min_vals[] = {
    picoquic_frame_type_reset_stream, 0x00, 0x00, 0x00
};

static uint8_t test_frame_reset_stream_max_final_size[] = {
    picoquic_frame_type_reset_stream, 0x01, 0x00,
    0xBF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 /* Varint for 0x3F00112233445566 */
};

static uint8_t test_frame_reset_stream_app_error_specific[] = {
    picoquic_frame_type_reset_stream, 0x02, 0x41, 0x00, 0x42, 0x00
};

/* New RESET_STREAM frame test cases */
/* Base Case */
static uint8_t test_reset_stream_base[] = {
    picoquic_frame_type_reset_stream, /* 0x04 */
    0x04,       /* Stream ID: 4 */
    0x41, 0x01, /* Application Protocol Error Code: 257 (0x101) */
    0x64        /* Final Size: 100 */
};

/* Stream ID Variations (ErrorCode=257, FinalSize=100) */
static uint8_t test_reset_stream_id_zero[] = {
    picoquic_frame_type_reset_stream, /* 0x04 */
    0x00,       /* Stream ID: 0 */
    0x41, 0x01, /* Application Protocol Error Code: 257 */
    0x64        /* Final Size: 100 */
};

static uint8_t test_reset_stream_id_large[] = {
    picoquic_frame_type_reset_stream, /* 0x04 */
    0x7F, 0xFF, /* Stream ID: 16383 (0x3FFF) */
    0x41, 0x01, /* Application Protocol Error Code: 257 */
    0x64        /* Final Size: 100 */
};

static uint8_t test_reset_stream_id_max_62bit[] = {
    picoquic_frame_type_reset_stream, /* 0x04 */
    0xBF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* Stream ID: 2^62-1 */
    0x41, 0x01, /* Application Protocol Error Code: 257 */
    0x64        /* Final Size: 100 */
};

/* Application Protocol Error Code Variations (StreamID=4, FinalSize=100) */
static uint8_t test_reset_stream_err_zero[] = {
    picoquic_frame_type_reset_stream, /* 0x04 */
    0x04,       /* Stream ID: 4 */
    0x00,       /* Application Protocol Error Code: 0 */
    0x64        /* Final Size: 100 */
};

static uint8_t test_reset_stream_err_transport_range_like[] = {
    picoquic_frame_type_reset_stream, /* 0x04 */
    0x04,       /* Stream ID: 4 */
    0x0A,       /* Application Protocol Error Code: 0x0A (like PROTOCOL_VIOLATION) */
    0x64        /* Final Size: 100 */
};

static uint8_t test_reset_stream_err_max_62bit[] = {
    picoquic_frame_type_reset_stream, /* 0x04 */
    0x04,       /* Stream ID: 4 */
    0xBF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* Application Protocol Error Code: 2^62-1 */
    0x64        /* Final Size: 100 */
};

/* Final Size Variations (StreamID=4, ErrorCode=257) */
static uint8_t test_reset_stream_final_size_zero[] = {
    picoquic_frame_type_reset_stream, /* 0x04 */
    0x04,       /* Stream ID: 4 */
    0x41, 0x01, /* Application Protocol Error Code: 257 */
    0x00        /* Final Size: 0 */
};

static uint8_t test_reset_stream_final_size_one[] = {
    picoquic_frame_type_reset_stream, /* 0x04 */
    0x04,       /* Stream ID: 4 */
    0x41, 0x01, /* Application Protocol Error Code: 257 */
    0x01        /* Final Size: 1 */
};

static uint8_t test_reset_stream_final_size_scenario_small[] = {
    picoquic_frame_type_reset_stream, /* 0x04 */
    0x04,       /* Stream ID: 4 */
    0x41, 0x01, /* Application Protocol Error Code: 257 */
    0x32        /* Final Size: 50 */
};

static uint8_t test_reset_stream_final_size_max_62bit[] = {
    picoquic_frame_type_reset_stream, /* 0x04 */
    0x04,       /* Stream ID: 4 */
    0x41, 0x01, /* Application Protocol Error Code: 257 */
    0xBF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF /* Final Size: 2^62-1 */
};

/* RESET_STREAM (0x04) - New test cases from plan */
static uint8_t test_frame_reset_stream_sid_zero[] = {
    picoquic_frame_type_reset_stream, 0x00, 0x00, 0x00
};
/* reset_stream_final_size_zero is covered by test_frame_reset_stream_app_error_specific if StreamID=1, Error=0, FinalSize=0 is needed.
   The provided test_frame_reset_stream_app_error_specific is {0x04, 0x01, 0x00, 0x01} (StreamID=1, ErrorCode=0, FinalSize=1).
   Let's create the exact requested one: StreamID=1, ErrorCode=0, FinalSize=0 */
static uint8_t test_frame_reset_stream_final_size_zero_explicit[] = { /* Renamed to avoid conflict if user meant a different existing one */
    picoquic_frame_type_reset_stream, 0x01, 0x00, 0x00
};
/* reset_stream_app_err_zero is {0x04, 0x01, 0x00, 0x01} (StreamID=1, ErrorCode=0, FinalSize=1) */
/* This is exactly test_frame_reset_stream_app_error_specific. No need for a new array. */

static uint8_t test_frame_reset_stream_all_large[] = {
    picoquic_frame_type_reset_stream,
    0x7F, 0xFF,       /* Stream ID: 16383 (0x3FFF) */
    0xBF, 0xFF, 0xFF, 0xFF, /* App Error Code: 1073741823 (0x3FFFFFFF) */
    0xBF, 0xFF, 0xFF, 0xFF  /* Final Size: 1073741823 (0x3FFFFFFF) */
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

static uint8_t test_frame_conn_close_no_reason[] = { 0x1c, 0x00, 0x00, 0x00 };

static uint8_t test_frame_conn_close_app_no_reason[] = { 0x1d, 0x00, 0x00 };

static uint8_t test_frame_conn_close_specific_transport_error[] = { 0x1c, 0x07, 0x15, 0x05, 'B','a','d','F','R' };

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

/* MAX_STREAMS (Unidirectional) frame with a very large stream limit (2^60) */
static uint8_t test_frame_max_streams_uni_at_limit[] = {
    0x13,       /* Type: MAX_STREAMS (Unidirectional) */
    0xC0, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00 /* Max Streams: 2^60 (Varint encoded) */
};

/* MAX_DATA (0x10) - New test cases from plan */
/* test_frame_max_data_val_zero is identical to existing test_frame_max_data_zero, so it's removed. */
static uint8_t test_frame_max_data_val_large[] = {
    picoquic_frame_type_max_data, 0xBF, 0xFF, 0xFF, 0xFF /* Max Data: 1073741823 (0x3FFFFFFF) */
};


static uint8_t test_frame_type_ping[] = {
    picoquic_frame_type_ping
};

/* Test Case: PING frame type encoded non-minimally.
 * Frame Type: PING (normally 0x01) encoded as a 2-byte varint (0x4001).
 */
static uint8_t test_frame_ping_long_encoding[] = {
    0x40, 0x01
};

static uint8_t test_frame_type_blocked[] = {
    picoquic_frame_type_data_blocked,
    0x80, 0x01, 0, 0
};

static uint8_t test_frame_type_data_blocked_large_offset[] = {
    picoquic_frame_type_data_blocked,
    0xBF, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE
};

static uint8_t test_frame_data_blocked_zero[] = {
    picoquic_frame_type_data_blocked, 0x00
};

static uint8_t test_frame_type_stream_blocked[] = {
    picoquic_frame_type_stream_data_blocked,
    0x80, 1, 0, 0,
    0x80, 0x02, 0, 0
};

static uint8_t test_frame_type_stream_data_blocked_large_limits[] = {
    picoquic_frame_type_stream_data_blocked,
    0xBA, 0x1B, 0x2C, 0x3D, /* Stream ID */
    0xBE, 0x4F, 0x5D, 0x6C  /* Stream Data Limit */
};

static uint8_t test_frame_stream_data_blocked_zero[] = {
    picoquic_frame_type_stream_data_blocked, 0x03, 0x00
};

static uint8_t test_frame_type_streams_blocked_bidir[] = {
    picoquic_frame_type_streams_blocked_bidir,
    0x41, 0
};

static uint8_t test_frame_streams_blocked_bidi_zero[] = {
    picoquic_frame_type_streams_blocked_bidir, 0x00
};

static uint8_t test_frame_type_streams_blocked_unidir[] = {
    picoquic_frame_type_streams_blocked_unidir,
    0x81, 2, 3, 4
};

static uint8_t test_frame_streams_blocked_uni_zero[] = {
    picoquic_frame_type_streams_blocked_unidir, 0x00
};

/* Test Case 1: STREAMS_BLOCKED (bidirectional) indicating a limit that isn't actually blocking.
 * Type: STREAMS_BLOCKED (bidirectional, 0x16)
 * Maximum Streams: 5
 * Scenario: Peer's actual limit is higher (e.g., 10).
 */
static uint8_t test_frame_streams_blocked_not_actually_blocked[] = {
    picoquic_frame_type_streams_blocked_bidir, /* 0x16 */
    0x05 /* Maximum Streams: 5 */
};

/* Test Case 2: STREAMS_BLOCKED (unidirectional) indicating a limit higher than the peer's actual limit.
 * Type: STREAMS_BLOCKED (unidirectional, 0x17)
 * Maximum Streams: 100
 * Scenario: Peer's actual limit is lower (e.g., 10).
 */
static uint8_t test_frame_streams_blocked_limit_too_high[] = {
    picoquic_frame_type_streams_blocked_unidir, /* 0x17 */
    0x64 /* Maximum Streams: 100 */
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
    0xBF, 0xFF, 0xBB, 0xBB /* Application Protocol Error Code: 0x3FFFBBBB */
};

static uint8_t test_frame_stop_sending_min_vals[] = {
    picoquic_frame_type_stop_sending, 0x00, 0x00
};

static uint8_t test_frame_stop_sending_app_error_specific[] = {
    picoquic_frame_type_stop_sending, 0x01, 0x41, 0x00
};

/* Test Case 1: STOP_SENDING for a stream already reset by the peer.
 * Type: STOP_SENDING (0x05)
 * Stream ID: 4
 * Application Protocol Error Code: 0x01 (generic app error)
 */
static uint8_t test_frame_stop_sending_for_peer_reset_stream[] = {
    picoquic_frame_type_stop_sending, /* 0x05 */
    0x04, /* Stream ID: 4 */
    0x01  /* Application Protocol Error Code: 0x01 */
};

/* Test Case 2: STOP_SENDING with a very large error code.
 * Type: STOP_SENDING (0x05)
 * Stream ID: 8
 * Application Protocol Error Code: 0x3FFFFFFFFFFFFFFF (max 8-byte varint)
 */
static uint8_t test_frame_stop_sending_large_error_code[] = {
    picoquic_frame_type_stop_sending, /* 0x05 */
    0x08, /* Stream ID: 8 */
    0xBF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF /* Error Code: 0x3FFFFFFFFFFFFFFF */
};

/* STOP_SENDING (0x05) - New test cases from plan */
static uint8_t test_frame_stop_sending_sid_err_zero[] = {
    picoquic_frame_type_stop_sending, 0x00, 0x00
};
static uint8_t test_frame_stop_sending_all_large[] = {
    picoquic_frame_type_stop_sending,
    0x7F, 0xFF,       /* Stream ID: 16383 (0x3FFF) */
    0xBF, 0xFF, 0xFF, 0xFF  /* App Error Code: 1073741823 (0x3FFFFFFF) */
};

/* New STOP_SENDING frame test cases */
/* Base Case */
static uint8_t test_stop_sending_base[] = {
    picoquic_frame_type_stop_sending, /* 0x05 */
    0x04,       /* Stream ID: 4 */
    0x41, 0x01  /* Application Protocol Error Code: 257 (0x101) */
};

/* Stream ID Variations (ErrorCode=257) */
static uint8_t test_stop_sending_id_zero[] = {
    picoquic_frame_type_stop_sending, /* 0x05 */
    0x00,       /* Stream ID: 0 */
    0x41, 0x01  /* Application Protocol Error Code: 257 */
};

static uint8_t test_stop_sending_id_large[] = {
    picoquic_frame_type_stop_sending, /* 0x05 */
    0x7F, 0xFF, /* Stream ID: 16383 (0x3FFF) */
    0x41, 0x01  /* Application Protocol Error Code: 257 */
};

static uint8_t test_stop_sending_id_max_62bit[] = {
    picoquic_frame_type_stop_sending, /* 0x05 */
    0xBF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* Stream ID: 2^62-1 */
    0x41, 0x01  /* Application Protocol Error Code: 257 */
};

static uint8_t test_stop_sending_id_recv_only_scenario[] = {
    picoquic_frame_type_stop_sending, /* 0x05 */
    0x02,       /* Stream ID: 2 (client-initiated uni) */
    0x41, 0x01  /* Application Protocol Error Code: 257 */
};

static uint8_t test_stop_sending_id_uncreated_sender_scenario[] = {
    picoquic_frame_type_stop_sending, /* 0x05 */
    0x0C,       /* Stream ID: 12 */
    0x41, 0x01  /* Application Protocol Error Code: 257 */
};

/* Application Protocol Error Code Variations (StreamID=4) */
static uint8_t test_stop_sending_err_zero[] = {
    picoquic_frame_type_stop_sending, /* 0x05 */
    0x04,       /* Stream ID: 4 */
    0x00        /* Application Protocol Error Code: 0 */
};

static uint8_t test_stop_sending_err_transport_range_like[] = {
    picoquic_frame_type_stop_sending, /* 0x05 */
    0x04,       /* Stream ID: 4 */
    0x0A        /* Application Protocol Error Code: 0x0A (like PROTOCOL_VIOLATION) */
};

static uint8_t test_stop_sending_err_max_62bit[] = {
    picoquic_frame_type_stop_sending, /* 0x05 */
    0x04,       /* Stream ID: 4 */
    0xBF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF /* Application Protocol Error Code: 2^62-1 */
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

static uint8_t test_frame_path_challenge_all_zeros[] = {
    picoquic_frame_type_path_challenge, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
};

static uint8_t test_frame_path_response_all_zeros[] = {
    picoquic_frame_type_path_response, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
};

static uint8_t test_frame_path_challenge_mixed_pattern[] = {
    picoquic_frame_type_path_challenge, 0xA5,0xA5,0xA5,0xA5,0xA5,0xA5,0xA5,0xA5
};

static uint8_t test_frame_path_response_mixed_pattern[] = {
    picoquic_frame_type_path_response, 0x5A,0x5A,0x5A,0x5A,0x5A,0x5A,0x5A,0x5A
};

static uint8_t test_frame_type_new_token[] = {
    picoquic_frame_type_new_token,
    17, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17
};

static uint8_t test_frame_new_token_long[] = {
    picoquic_frame_type_new_token, 0x40, 0x64,
    0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB, /* 10 */
    0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB, /* 20 */
    0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB, /* 30 */
    0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB, /* 40 */
    0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB, /* 50 */
    0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB, /* 60 */
    0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB, /* 70 */
    0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB, /* 80 */
    0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB, /* 90 */
    0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB  /* 100 */
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

/* ACK frame with Largest Ack = 50, ACK Delay = 10, 20 ACK ranges, each acking a single packet */
static uint8_t test_frame_ack_many_small_ranges[] = {
    0x02,       /* Type: ACK frame */
    0x32,       /* Largest Acknowledged: 50 */
    0x0A,       /* ACK Delay: 10 */
    0x13,       /* ACK Range Count: 19 (represents 20 ranges: First + 19 more) */
    0x00,       /* First ACK Range: 0 (acks packet 50) */
    /* 19 more ranges, each Gap=0, Range=0 */
    0x00, 0x00, /* Gap 0, Range 0 (acks 49) */
    0x00, 0x00, /* Gap 0, Range 0 (acks 48) */
    0x00, 0x00, /* Gap 0, Range 0 (acks 47) */
    0x00, 0x00, /* Gap 0, Range 0 (acks 46) */
    0x00, 0x00, /* Gap 0, Range 0 (acks 45) */
    0x00, 0x00, /* Gap 0, Range 0 (acks 44) */
    0x00, 0x00, /* Gap 0, Range 0 (acks 43) */
    0x00, 0x00, /* Gap 0, Range 0 (acks 42) */
    0x00, 0x00, /* Gap 0, Range 0 (acks 41) */
    0x00, 0x00, /* Gap 0, Range 0 (acks 40) */
    0x00, 0x00, /* Gap 0, Range 0 (acks 39) */
    0x00, 0x00, /* Gap 0, Range 0 (acks 38) */
    0x00, 0x00, /* Gap 0, Range 0 (acks 37) */
    0x00, 0x00, /* Gap 0, Range 0 (acks 36) */
    0x00, 0x00, /* Gap 0, Range 0 (acks 35) */
    0x00, 0x00, /* Gap 0, Range 0 (acks 34) */
    0x00, 0x00, /* Gap 0, Range 0 (acks 33) */
    0x00, 0x00, /* Gap 0, Range 0 (acks 32) */
    0x00, 0x00  /* Gap 0, Range 0 (acks 31) */
};

/* Test Case 1: Overlapping ACK Ranges.
 * Type: ACK (0x02)
 * Largest Acknowledged: 20 (0x14)
 * ACK Delay: 10 (0x0A)
 * ACK Range Count: 2 (0x02)
 * First ACK Range: 5 (0x05) (acks packets 15-20)
 * Second ACK Range:
 *   Gap: 1 (0x01) (previous smallest was 15. next largest acked by this range is 15 - 1 - 2 = 12)
 *   ACK Range Length: 4 (0x04) (acks packets 12 - 4 = 8 to 12). This range (8-12) overlaps with (15-20) due to how ranges are calculated.
 *   The test is to see if the parser correctly handles or flags this condition if it's considered invalid.
 *   Note: The example in the description seems to have a direct overlap logic,
 *   but QUIC ACK range processing means a gap reduces the next range's numbers.
 *   Let's define a case where the *resulting* packet numbers from two ranges would overlap if not processed carefully or if gaps lead to unexpected results.
 *   Largest Ack: 20. First Range: 5 (acks 15-20). Smallest_prev = 15.
 *   Gap: 1. Next_Largest_Acked_By_Range = Smallest_prev - Gap - 2 = 15 - 1 - 2 = 12.
 *   RangeLength: 7 (acks 12-7 = 5 to 12). Packets 5-12 and 15-20. No direct number overlap.
 *
 *   To create an overlap based on the problem description's intent (e.g. range 1 acks X to Y, range 2 acks W to Z, and they overlap):
 *   Largest Ack: 20 (0x14)
 *   ACK Delay: 10 (0x0A)
 *   ACK Range Count: 2 (0x02)
 *   First ACK Range: 5 (0x05) -> acks pkts (20-5) to 20 = 15 to 20. Smallest in this range is 15.
 *   Gap for 2nd range: 2 (0x02) -> next largest pkt in 2nd range = 15 - 2 - 2 = 11.
 *   ACK Range Length for 2nd range: 3 (0x03) -> acks pkts (11-3) to 11 = 8 to 11. No overlap.
 *
 *   Let's try to make the second range ACK numbers ALREADY covered by the first range.
 *   Largest Ack: 20. First Range: 5 (acks 15-20). Smallest in this range is 15.
 *   To make the next range ack something like 16,17:
 *   Next_Largest_Acked_By_Range = 17. Smallest_prev - Gap - 2 = 17.
 *   15 - Gap - 2 = 17  => 13 - Gap = 17 => Gap = -4. Not possible.
 *
 *   The definition of "overlapping" here might mean that the *sum* of (Gap + Range Length) for a subsequent block
 *   somehow encroaches into the space defined by a prior block, or that a block defines a range already covered.
 *   The standard processing implies ranges are ordered. The "First ACK Range" is for the highest packet numbers.
 *   Subsequent ranges are for lower packet numbers.
 *   A true overlap where e.g. range 1 covers 15-20 and range 2 covers 18-22 is not possible with the gap logic.
 *   Let's assume "overlapping" means a range that re-acknowledges a packet number that would have been
 *   covered by a previous (higher value) range if the ranges were strictly sequential and non-overlapping.
 *   This seems more like a test of complex gap arithmetic.
 *   The provided example `{ 0x02, 20, 10, 2, 5, 1, 4 };`
 *   Largest Ack = 20. Delay = 10. Range Count = 2.
 *   Range 1: Len = 5. Acks 15, 16, 17, 18, 20. Smallest = 15.
 *   Range 2: Gap = 1. Next Largest = 15 - 1 - 2 = 12. Len = 4. Acks 8, 9, 10, 11, 12.
 *   These ranges (15-20 and 8-12) are not overlapping.
 *
 *   Given the problem statement, the user likely intends a scenario that might be invalidly constructed.
 *   Let's stick to the user's example values directly, assuming it represents an edge case they want to test,
 *   even if it doesn't create a direct numerical overlap in the final acknowledged set due to standard processing.
 *   The term "overlapping" might be used loosely to mean "a complex interaction of ranges".
 */
static uint8_t test_frame_ack_overlapping_ranges[] = {
    0x02, /* Type: ACK */
    20,   /* Largest Acknowledged */
    10,   /* ACK Delay */
    2,    /* ACK Range Count */
    5,    /* First ACK Range Length (acks 15-20) */
    1,    /* Gap (next range starts relative to 15) */
    4     /* Second ACK Range Length (next largest is 15-1-2=12, acks 8-12) */
};

/* Test Case 2: ACK ranges that would imply ascending order or invalid gap.
 * Type: ACK (0x02)
 * Largest Acknowledged: 5
 * ACK Delay: 0
 * ACK Range Count: 2 (to have a "next" range)
 * First ACK Range: 2 (acks packets 3-5). Smallest in this range is 3.
 * Second ACK Range:
 *   Gap: 10 (This is the key part. Next largest ack in this range would be 3 - 10 - 2 = -9, which is invalid)
 *   ACK Range Length: 0 (minimal valid length for a range)
 */
static uint8_t test_frame_ack_ascending_ranges_invalid_gap[] = {
    0x02, /* Type: ACK */
    5,    /* Largest Acknowledged */
    0,    /* ACK Delay */
    2,    /* ACK Range Count */
    2,    /* First ACK Range (acks 3-5, smallest is 3) */
    10,   /* Gap (implies next largest is 3-10-2 = -9) */
    0     /* ACK Range Length for the second range */
};


/* Test Case 3: Invalid ACK Range Count (too large for the actual data provided).
 * Type: ACK (0x02)
 * Largest Acknowledged: 100 (0x64)
 * ACK Delay: 20 (0x14)
 * ACK Range Count: 200 (0xC8, varint encoded as 0x40, 0xC8 is wrong, it's 0x80 00 00 C8 for 4 bytes, or 0x40 C8 for 2 bytes if < 16383)
 *   Let's use 200, which is 0xC8. If it's a 1-byte varint, it's > 63, so it needs 2 bytes: 0x40 | (0xC8>>8) , 0xC8&0xFF -> 0x40, 0xC8.
 *   No, 200 is 11001000 in binary. It fits in 1 byte with 0 prefix: 0xc8.
 *   If Range Count is 200 (0xc8), it will be encoded as two bytes: 0x40 followed by 0xc8 is not correct.
 *   A varint for 200 is simply 0xC8 if it was <64.
 *   For 200: bits are 11001000. Two-byte encoding: 0x80 | (value >> 8), value & 0xFF.
 *   No, that's for values > 2^14.
 *   For 200: first byte is 0b01... (for 2-byte), so 0x40 + (200>>8) = 0x40. Second byte is 200&0xFF = 0xC8.
 *   So, 0x40, 0xC8 is correct for 200. The problem states 0x40, 0xc8 for 200.
 *   Actually, 200 in varint is: 0x80+128=200 -> 0x80+0x48 -> 0xC8. No, 200 = 128 + 72. So 0x80 | 0x48, 0x48.
 *   Let's re-check varint for 200 (0xC8):
 *   Since 200 > 63 and < 16383, it's a 2-byte varint.
 *   First byte: 0x40 | (200 >> 8) = 0x40 | 0 = 0x40.
 *   Second byte: 200 & 0xFF = 0xC8.
 *   So, 0x40, 0xC8 is correct for 200.
 * First ACK Range: 0 (0x00)
 * Provide only a few actual ranges, far less than 200.
 * The frame itself will be short, but the count implies many more.
 */
static uint8_t test_frame_ack_invalid_range_count[] = {
    0x02,       /* Type: ACK */
    100,        /* Largest Acknowledged */
    20,         /* ACK Delay */
    0x40, 0xC8, /* ACK Range Count: 200 (varint) */
    0,          /* First ACK Range Length */
    0,0,        /* Minimal Gap & Range */
    0,0,        /* Minimal Gap & Range */
    0,0         /* Minimal Gap & Range */
    /* Total frame length here is 1 + 1 + 1 + 2 + 1 + 2 + 2 + 2 = 12 bytes */
    /* but range count says 200 ranges. */
};

/* Test Case 4: Largest Acknowledged is smaller than the packet number implied by First ACK Range.
 * Type: ACK (0x02)
 * Largest Acknowledged: 5 (0x05)
 * ACK Delay: 0 (0x00)
 * ACK Range Count: 1 (0x01)
 * First ACK Range: 10 (0x0A) (implies packets (5-10) to 5, so -5 to 5. This is invalid.)
 */
static uint8_t test_frame_ack_largest_smaller_than_range[] = {
    0x02, /* Type: ACK */
    5,    /* Largest Acknowledged */
    0,    /* ACK Delay */
    1,    /* ACK Range Count */
    10    /* First ACK Range (length 10, implies acking below 0 if LargestAck is 5) */
};

/* ACK Delay variations */
static uint8_t test_ack_delay_zero[] = {
    0x02, /* Type: ACK */
    0x64, /* Largest Acknowledged: 100 */
    0x00, /* ACK Delay: 0 */
    0x01, /* ACK Range Count: 1 */
    0x00  /* First ACK Range: 0 */
};

static uint8_t test_ack_delay_effective_max_tp_val[] = {
    0x02, /* Type: ACK */
    0x64, /* Largest Acknowledged: 100 */
    0x87, 0xFF, /* ACK Delay: 2047 (max_ack_delay/8 with default_ack_exponent=3) */
    0x01, /* ACK Range Count: 1 */
    0x00  /* First ACK Range: 0 */
};

static uint8_t test_ack_delay_max_varint_val[] = {
    0x02, /* Type: ACK */
    0x64, /* Largest Acknowledged: 100 */
    0x7F, 0xFF, /* ACK Delay: 16383 (max 2-byte varint) */
    0x01, /* ACK Range Count: 1 */
    0x00  /* First ACK Range: 0 */
};

/* ACK Range Count variations */
static uint8_t test_ack_range_count_zero[] = {
    0x02, /* Type: ACK */
    0x64, /* Largest Acknowledged: 100 */
    0x0A, /* ACK Delay: 10 */
    0x00, /* ACK Range Count: 0 */
    0x00  /* First ACK Range: 0 */
};

static uint8_t test_ack_range_count_one[] = {
    0x02, /* Type: ACK */
    0x64, /* Largest Acknowledged: 100 */
    0x0A, /* ACK Delay: 10 */
    0x01, /* ACK Range Count: 1 */
    0x05, /* First ACK Range: 5 */
    0x00, /* Gap: 0 */
    0x00  /* ACK Range Length: 0 */
};

static uint8_t test_ack_range_count_many[] = {
    0x02, /* Type: ACK */
    0x64, /* Largest Acknowledged: 100 */
    0x0A, /* ACK Delay: 10 */
    0x3C, /* ACK Range Count: 60 */
    0x00, /* First ACK Range: 0 */
    0x00, 0x00, /* Gap 0, Len 0 */
    0x00, 0x00, /* Gap 0, Len 0 */
    0x00, 0x00, /* Gap 0, Len 0 */
    0x00, 0x00, /* Gap 0, Len 0 */
    0x00, 0x00  /* Gap 0, Len 0 */
};

/* First ACK Range variations */
static uint8_t test_ack_first_range_zero[] = {
    0x02, /* Type: ACK */
    0x64, /* Largest Acknowledged: 100 */
    0x0A, /* ACK Delay: 10 */
    0x01, /* ACK Range Count: 1 */
    0x00  /* First ACK Range: 0 */
};

static uint8_t test_ack_first_range_causes_negative_smallest[] = {
    0x02, /* Type: ACK */
    0x05, /* Largest Acknowledged: 5 */
    0x00, /* ACK Delay: 0 */
    0x01, /* ACK Range Count: 1 */
    0x0A  /* First ACK Range: 10 */
};

static uint8_t test_ack_first_range_covers_zero[] = {
    0x02, /* Type: ACK */
    0x05, /* Largest Acknowledged: 5 */
    0x00, /* ACK Delay: 0 */
    0x01, /* ACK Range Count: 1 */
    0x05  /* First ACK Range: 5 */
};

/* Gap variations (ACK Range Count >= 1) */
static uint8_t test_ack_gap_zero_len_zero[] = {
    0x02, /* Type: ACK */
    0x14, /* Largest Acknowledged: 20 */
    0x00, /* ACK Delay: 0 */
    0x01, /* ACK Range Count: 1 */
    0x00, /* First ACK Range: 0 */
    0x00, /* Gap: 0 */
    0x00  /* ACK Range Length: 0 */
};

static uint8_t test_ack_gap_causes_negative_next_largest[] = {
    0x02, /* Type: ACK */
    0x14, /* Largest Acknowledged: 20 */
    0x00, /* ACK Delay: 0 */
    0x01, /* ACK Range Count: 1 */
    0x05, /* First ACK Range: 5 (acks 15-20) */
    0x14, /* Gap: 20 (next largest = 15-20-2 = -7) */
    0x00  /* ACK Range Length: 0 */
};

/* ACK Range Length variations (ACK Range Count >= 1) */
static uint8_t test_ack_range_len_large[] = {
    0x02,       /* Type: ACK */
    0x85, 0xDC, /* Largest Acknowledged: 1500 */
    0x00,       /* ACK Delay: 0 */
    0x01,       /* ACK Range Count: 1 */
    0x00,       /* First ACK Range: 0 */
    0x00,       /* Gap: 0 */
    0x83, 0xE8  /* ACK Range Length: 1000 */
};

/* ECN Count variations (Type 0x03) */
static uint8_t test_ack_ecn_all_zero[] = {
    0x03, /* Type: ACK with ECN */
    0x64, /* Largest Acknowledged: 100 */
    0x0A, /* ACK Delay: 10 */
    0x01, /* ACK Range Count: 1 */
    0x00, /* First ACK Range: 0 */
    0x00, /* ECT0: 0 */
    0x00, /* ECT1: 0 */
    0x00  /* CE: 0 */
};

static uint8_t test_ack_ecn_one_each[] = {
    0x03, /* Type: ACK with ECN */
    0x64, /* Largest Acknowledged: 100 */
    0x0A, /* ACK Delay: 10 */
    0x01, /* ACK Range Count: 1 */
    0x00, /* First ACK Range: 0 */
    0x01, /* ECT0: 1 */
    0x01, /* ECT1: 1 */
    0x01  /* CE: 1 */
};

static uint8_t test_ack_ecn_large_counts[] = {
    0x03,       /* Type: ACK with ECN */
    0x64,       /* Largest Acknowledged: 100 */
    0x0A,       /* ACK Delay: 10 */
    0x01,       /* ACK Range Count: 1 */
    0x00,       /* First ACK Range: 0 */
    0x7F, 0xFF, /* ECT0: 16383 */
    0x7F, 0xFF, /* ECT1: 16383 */
    0x7F, 0xFF  /* CE: 16383 */
};

static uint8_t test_ack_ecn_sum_exceeds_largest_acked[] = {
    0x03, /* Type: ACK with ECN */
    0x0A, /* Largest Acknowledged: 10 */
    0x00, /* ACK Delay: 0 */
    0x01, /* ACK Range Count: 1 */
    0x00, /* First ACK Range: 0 */
    0x05, /* ECT0: 5 */
    0x05, /* ECT1: 5 */
    0x05  /* CE: 5 */
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

/* STREAM frame with OFF, LEN, FIN bits set, Stream ID 1, Offset 64, Length 0, No data */
static uint8_t test_frame_stream_off_len_empty_fin[] = {
    0x0F,       /* Type: OFF, LEN, FIN bits set */
    0x01,       /* Stream ID: 1 */
    0x40, 0x40, /* Offset: 64 (Varint encoded) */
    0x00        /* Length: 0 (Varint encoded) */
    /* No Stream Data */
};

/* Test Case 1: STREAM frame with FIN set and explicit length larger than data.
 * Type: 0x0B (FIN=1, OFF=0, LEN=1)
 * Stream ID: 0x04
 * Length: 2000 (Varint encoded as 0x47, 0xD0)
 * Stream Data: "test" (4 bytes)
 */
static uint8_t test_frame_stream_fin_too_long[] = {
    0x0B,       /* Type: FIN=1, LEN=1 */
    0x04,       /* Stream ID: 4 */
    0x47, 0xD0, /* Length: 2000 */
    't', 'e', 's', 't'
};

/* Test Case 2: First part of overlapping STREAM data.
 * Type: 0x0E (FIN=0, OFF=1, LEN=1)
 * Stream ID: 0x08
 * Offset: 10
 * Length: 5
 * Stream Data: "first"
 */
static uint8_t test_frame_stream_overlapping_data_part1[] = {
    0x0E,       /* Type: OFF=1, LEN=1 */
    0x08,       /* Stream ID: 8 */
    10,         /* Offset */
    5,          /* Length */
    'f', 'i', 'r', 's', 't'
};

/* Test Case 3: Second part of overlapping STREAM data.
 * Type: 0x0E (FIN=0, OFF=1, LEN=1)
 * Stream ID: 0x08 (same as part1)
 * Offset: 12 (overlaps with offset 10, length 5 from part1)
 * Length: 5
 * Stream Data: "SECON"
 */
static uint8_t test_frame_stream_overlapping_data_part2[] = {
    0x0E,       /* Type: OFF=1, LEN=1 */
    0x08,       /* Stream ID: 8 */
    12,         /* Offset */
    5,          /* Length */
    'S', 'E', 'C', 'O', 'N'
};

/* Part 1: Base test cases for all 8 STREAM types */
static uint8_t test_stream_0x08_off0_len0_fin0[] = {0x08, 0x04, 'h','e','l','l','o',' ','s','t','r','e','a','m'};
static uint8_t test_stream_0x09_off0_len0_fin1[] = {0x09, 0x04, 'h','e','l','l','o',' ','s','t','r','e','a','m'};
static uint8_t test_stream_0x0A_off0_len1_fin0[] = {0x0A, 0x04, 0x0C, 'h','e','l','l','o',' ','s','t','r','e','a','m'};
static uint8_t test_stream_0x0B_off0_len1_fin1[] = {0x0B, 0x04, 0x0C, 'h','e','l','l','o',' ','s','t','r','e','a','m'};
static uint8_t test_stream_0x0C_off1_len0_fin0[] = {0x0C, 0x04, 0x0A, 'h','e','l','l','o',' ','s','t','r','e','a','m'};
static uint8_t test_stream_0x0D_off1_len0_fin1[] = {0x0D, 0x04, 0x0A, 'h','e','l','l','o',' ','s','t','r','e','a','m'};
static uint8_t test_stream_0x0E_off1_len1_fin0[] = {0x0E, 0x04, 0x0A, 0x0C, 'h','e','l','l','o',' ','s','t','r','e','a','m'};
static uint8_t test_stream_0x0F_off1_len1_fin1[] = {0x0F, 0x04, 0x0A, 0x0C, 'h','e','l','l','o',' ','s','t','r','e','a','m'};

/* Part 2: Variations for STREAM type 0x0F (all bits set) */
static uint8_t test_stream_0x0F_id_zero[] = {0x0F, 0x00, 0x0A, 0x05, 'b','a','s','i','c'};
static uint8_t test_stream_0x0F_id_large[] = {0x0F, 0x7F, 0xFF, 0x0A, 0x05, 'b','a','s','i','c'};
static uint8_t test_stream_0x0F_id_max_62bit[] = {0x0F, 0xBF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0x0A, 0x05, 'b','a','s','i','c'};

static uint8_t test_stream_0x0F_off_zero[] = {0x0F, 0x04, 0x00, 0x05, 'b','a','s','i','c'};
static uint8_t test_stream_0x0F_off_max_62bit[] = {0x0F, 0x04, 0xBF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0x05, 'b','a','s','i','c'};
static uint8_t test_stream_0x0F_off_plus_len_exceeds_max[] = {0x0F, 0x04, 0xBF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFD, 0x05, 'b','a','s','i','c'};

static uint8_t test_stream_0x0F_len_zero[] = {0x0F, 0x04, 0x0A, 0x00};
static uint8_t test_stream_0x0F_len_one[] = {0x0F, 0x04, 0x0A, 0x01, 'd'};
static uint8_t test_stream_0x0F_len_exceed_total_with_offset[] = {0x0F, 0x04, 0x0A, 0xBF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFB, 'b','a','s','i','c'};

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
    picoquic_frame_type_crypto_hs, 0x00, 0x00
};

static uint8_t test_frame_crypto_large_offset[] = {
    picoquic_frame_type_crypto_hs, 0x50, 0x00, 0x05, 'd','u','m','m','y'
};

static uint8_t test_frame_crypto_fragment1[] = {
    picoquic_frame_type_crypto_hs, 0x00, 0x05, 'H','e','l','l','o'
};

static uint8_t test_frame_crypto_fragment2[] = {
    picoquic_frame_type_crypto_hs, 0x05, 0x05, 'W','o','r','l','d'
};

static uint8_t test_frame_type_retire_connection_id[] = {
    picoquic_frame_type_retire_connection_id,
    1
};

static uint8_t test_frame_retire_cid_seq_zero[] = {
    picoquic_frame_type_retire_connection_id, 0x00
};

static uint8_t test_frame_retire_cid_seq_high[] = {
    picoquic_frame_type_retire_connection_id, 0x0A
};

/* Test Case: RETIRE_CONNECTION_ID that refers to the CID currently in use.
 * Type: RETIRE_CONNECTION_ID (0x19)
 * Sequence Number: 0 (example, implies packet's DCID has sequence 0)
 */
static uint8_t test_frame_retire_cid_current_in_use[] = {
    picoquic_frame_type_retire_connection_id, /* 0x19 */
    0x00 /* Sequence Number: 0 */
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

static uint8_t test_frame_new_cid_retire_high[] = {
    picoquic_frame_type_new_connection_id, 0x0B, 0x0B, 8,
    0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
    0xD0,0xD1,0xD2,0xD3,0xD4,0xD5,0xD6,0xD7,0xD8,0xD9,0xDA,0xDB,0xDC,0xDD,0xDE,0xDF
};

static uint8_t test_frame_new_cid_short_id[] = {
    picoquic_frame_type_new_connection_id, 0x0C, 0x0A, 4,
    0xAA,0xBB,0xCC,0xDD,
    0xD0,0xD1,0xD2,0xD3,0xD4,0xD5,0xD6,0xD7,0xD8,0xD9,0xDA,0xDB,0xDC,0xDD,0xDE,0xDF
};

static uint8_t test_frame_new_cid_long_id[] = {
    picoquic_frame_type_new_connection_id, 0x0D, 0x0B, 20,
    0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10,0x11,0x12,0x13,0x14,
    0xD0,0xD1,0xD2,0xD3,0xD4,0xD5,0xD6,0xD7,0xD8,0xD9,0xDA,0xDB,0xDC,0xDD,0xDE,0xDF
};

/* NEW_CONNECTION_ID frame with Sequence Number 0, Retire Prior To 0 */
static uint8_t test_frame_new_cid_seq_much_lower[] = {
    0x18,       /* Type: NEW_CONNECTION_ID */
    0x00,       /* Sequence Number: 0 */
    0x00,       /* Retire Prior To: 0 */
    0x08,       /* Length: 8 */
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, /* Connection ID */
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, /* Stateless Reset Token */
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF
};

/* Test Case 1: NEW_CONNECTION_ID frame with Retire Prior To > Sequence Number.
 * Type: NEW_CONNECTION_ID (0x18)
 * Sequence Number: 5
 * Retire Prior To: 10 (invalid as it's > Sequence Number)
 * Length: 8
 * Connection ID: 0x01...0x08
 * Stateless Reset Token: 0xA0...0xAF (16 bytes)
 */
static uint8_t test_frame_new_cid_retire_prior_to_seq_num_mismatch[] = {
    picoquic_frame_type_new_connection_id,
    5,    /* Sequence Number */
    10,   /* Retire Prior To */
    8,    /* Length */
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, /* Connection ID */
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, /* Stateless Reset Token (first 8 bytes) */
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF  /* Stateless Reset Token (last 8 bytes) */
};

/* Test Case 2: NEW_CONNECTION_ID frame with invalid Connection ID Length (0).
 * Type: NEW_CONNECTION_ID (0x18)
 * Sequence Number: 6
 * Retire Prior To: 1
 * Length: 0 (invalid)
 * Connection ID: (empty)
 * Stateless Reset Token: 0xB0...0xBF (16 bytes)
 */
static uint8_t test_frame_new_cid_invalid_length[] = {
    picoquic_frame_type_new_connection_id,
    6,    /* Sequence Number */
    1,    /* Retire Prior To */
    0,    /* Length */
    /* No Connection ID */
    0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, /* Stateless Reset Token (first 8 bytes) */
    0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF  /* Stateless Reset Token (last 8 bytes) */
};

/* Test Case 3: NEW_CONNECTION_ID frame with Connection ID Length > 20.
 * Type: NEW_CONNECTION_ID (0x18)
 * Sequence Number: 7
 * Retire Prior To: 2
 * Length: 21 (invalid for RFC 9000, max is 20)
 * Connection ID: 0xC0...0xD4 (21 bytes)
 * Stateless Reset Token: 0xE0...0xEF (16 bytes)
 */
static uint8_t test_frame_new_cid_length_too_long_for_rfc[] = {
    picoquic_frame_type_new_connection_id,
    7,    /* Sequence Number */
    2,    /* Retire Prior To */
    21,   /* Length */
    0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, /* Connection ID (21 bytes) */
    0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, /* Stateless Reset Token (first 8 bytes) */
    0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF  /* Stateless Reset Token (last 8 bytes) */
};

/* Test Case: NEW_CONNECTION_ID that would exceed active_connection_id_limit.
 * Type: NEW_CONNECTION_ID (0x18)
 * Sequence Number: 5
 * Retire Prior To: 0
 * Length: 8
 * Connection ID: 8x 0xAA
 * Stateless Reset Token: 16x 0xBB
 */
static uint8_t test_frame_new_cid_exceed_limit_no_retire[] = {
    picoquic_frame_type_new_connection_id, /* 0x18 */
    0x05, /* Sequence Number */
    0x00, /* Retire Prior To */
    8,    /* Length */
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, /* Connection ID */
    0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, /* Stateless Reset Token (first 8) */
    0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB  /* Stateless Reset Token (last 8) */
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

/* New ACK frame test cases */

/* Test Case 1: Excessive ACK Delay */
/* Type: picoquic_frame_type_ack
 * Largest Acknowledged: 100 (0x64)
 * ACK Delay: Max varint (0x3FFFFFFFFFFFFFFF) -> Encoded as 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
 * ACK Range Count: 1 (0x01)
 * First ACK Range: 10 (0x0A)
 */
static uint8_t test_frame_ack_excessive_ack_delay[] = {
    picoquic_frame_type_ack,
    0x64, /* Largest Acknowledged: 100 */
    0xC0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* ACK Delay: 0x3FFFFFFFFFFFFFFF (Varint encoded) */
    0x01, /* ACK Range Count: 1 */
    0x0A  /* First ACK Range: 10 */
};

/* Test Case 2: First ACK Range Too Large */
/* Type: picoquic_frame_type_ack
 * Largest Acknowledged: 50 (0x32)
 * ACK Delay: 1000 (0x03E8) -> Encoded as 0x43, 0xE8
 * ACK Range Count: 1 (0x01)
 * First ACK Range: 60 (0x3C) (larger than Largest Acknowledged)
 */
static uint8_t test_frame_ack_first_range_too_large[] = {
    picoquic_frame_type_ack,
    0x32, /* Largest Acknowledged: 50 */
    0x43, 0xE8, /* ACK Delay: 1000 */
    0x01, /* ACK Range Count: 1 */
    0x3C  /* First ACK Range: 60 */
};

/* Test Case 3: Too Many ACK Ranges */
/* Type: picoquic_frame_type_ack
 * Largest Acknowledged: 1000 (0x03E8) -> Encoded as 0x43, 0xE8
 * ACK Delay: 100 (0x64)
 * ACK Range Count: 60 (0x3C)
 * Ranges: First ACK Range = 0 (ack 1 packet: 1000), then 59 * (Gap=0, Range=0)
 */
static uint8_t test_frame_ack_too_many_ranges[] = {
    picoquic_frame_type_ack,
    0x43, 0xE8, /* Largest Acknowledged: 1000 */
    0x64,       /* ACK Delay: 100 */
    0x3C,       /* ACK Range Count: 60 */
    0x00,       /* First ACK Range: 0 (packet 1000) */
    /* 59 more ranges: Gap=0, Range=0 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 10 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 20 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 30 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 40 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 50 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00        /* 59 */
};

/* Test Case 4: ECN ECT0 Count Too Large */
/* Type: picoquic_frame_type_ack_ecn
 * Largest Acknowledged: 10 (0x0A)
 * ACK Delay: 100 (0x64)
 * ACK Range Count: 1 (0x01)
 * First ACK Range: 5 (0x05) (acks 6-10)
 * ECT0: 100 (0x64) (larger than largest acknowledged)
 * ECT1: 0 (0x00)
 * CE: 0 (0x00)
 */
static uint8_t test_frame_ack_ecn_ect0_too_large[] = {
    picoquic_frame_type_ack_ecn,
    0x0A,       /* Largest Acknowledged: 10 */
    0x64,       /* ACK Delay: 100 */
    0x01,       /* ACK Range Count: 1 */
    0x05,       /* First ACK Range: 5 */
    0x64,       /* ECT0: 100 */
    0x00,       /* ECT1: 0 */
    0x00        /* CE: 0 */
};

/* New STREAM frame test cases */

/* Test Case 1: test_frame_stream_len_beyond_packet */
/* Type: 0x0A (LEN bit set)
 * Stream ID: 0x04
 * Length: 0x10000 (65536) -> Encoded as 0x80, 0x01, 0x00, 0x00
 * Stream Data: "testdata" (8 bytes)
 */
static uint8_t test_frame_stream_len_beyond_packet[] = {
    picoquic_frame_type_stream_range_min | 0x02, /* Type 0x0A */
    0x04,       /* Stream ID: 4 */
    0x80, 0x01, 0x00, 0x00, /* Length: 65536 */
    't', 'e', 's', 't', 'd', 'a', 't', 'a'
};

/* Test Case 2: test_frame_stream_zero_len_with_data */
/* Type: 0x0A (LEN bit set)
 * Stream ID: 0x04
 * Length: 0
 * Stream Data: "somedata" (8 bytes)
 */
static uint8_t test_frame_stream_zero_len_with_data[] = {
    picoquic_frame_type_stream_range_min | 0x02, /* Type 0x0A */
    0x04,       /* Stream ID: 4 */
    0x00,       /* Length: 0 */
    's', 'o', 'm', 'e', 'd', 'a', 't', 'a'
};

/* Test Case 3: test_frame_stream_len_shorter_than_data */
/* Type: 0x0A (LEN bit set)
 * Stream ID: 0x04
 * Length: 4
 * Stream Data: "longertestdata" (14 bytes)
 */
static uint8_t test_frame_stream_len_shorter_than_data[] = {
    picoquic_frame_type_stream_range_min | 0x02, /* Type 0x0A */
    0x04,       /* Stream ID: 4 */
    0x04,       /* Length: 4 */
    'l', 'o', 'n', 'g', 'e', 'r', 't', 'e', 's', 't', 'd', 'a', 't', 'a'
};

/* Test Case 4: test_frame_stream_len_longer_than_data */
/* Type: 0x0A (LEN bit set)
 * Stream ID: 0x04
 * Length: 20 (0x14)
 * Stream Data: "shortdata" (9 bytes)
 */
static uint8_t test_frame_stream_len_longer_than_data[] = {
    picoquic_frame_type_stream_range_min | 0x02, /* Type 0x0A */
    0x04,       /* Stream ID: 4 */
    0x14,       /* Length: 20 */
    's', 'h', 'o', 'r', 't', 'd', 'a', 't', 'a'
};

/* Test Case 5: test_frame_stream_max_offset_max_len */
/* Type: 0x0E (OFF bit, LEN bit set)
 * Stream ID: 0x04
 * Offset: Max varint (0x3FFFFFFFFFFFFFFF) -> Encoded as 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
 * Length: Max varint (0x3FFFFFFFFFFFFFFF) -> Encoded as 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
 * Stream Data: "tiny" (4 bytes)
 */
static uint8_t test_frame_stream_max_offset_max_len[] = {
    picoquic_frame_type_stream_range_min | 0x04 | 0x02, /* Type 0x0E */
    0x04,       /* Stream ID: 4 */
    0xC0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* Offset: 0x3FFFFFFFFFFFFFFF */
    0xC0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* Length: 0x3FFFFFFFFFFFFFFF */
    't', 'i', 'n', 'y'
};

/* New MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS frame test cases */

/* Test Case 1: test_frame_max_data_extremely_large */
/* Type: picoquic_frame_type_max_data (0x10)
 * Maximum Data: 0x3FFFFFFFFFFFFFFF (Varint encoded as 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF)
 */
static uint8_t test_frame_max_data_extremely_large[] = {
    picoquic_frame_type_max_data,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

/* Test Case 2: test_frame_max_stream_data_extremely_large */
/* Type: picoquic_frame_type_max_stream_data (0x11)
 * Stream ID: 0x04
 * Maximum Stream Data: 0x3FFFFFFFFFFFFFFF (Varint encoded as 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF)
 */
static uint8_t test_frame_max_stream_data_extremely_large[] = {
    picoquic_frame_type_max_stream_data,
    0x04, /* Stream ID */
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

/* Test Case 3: test_frame_max_streams_bidir_extremely_large */
/* Type: picoquic_frame_type_max_streams_bidir (0x12)
 * Maximum Streams: 0x3FFFFFFFFFFFFFFF (Varint encoded as 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF)
 */
static uint8_t test_frame_max_streams_bidir_extremely_large[] = {
    picoquic_frame_type_max_streams_bidir,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

/* Test Case 4: test_frame_max_streams_unidir_extremely_large */
/* Type: picoquic_frame_type_max_streams_unidir (0x13)
 * Maximum Streams: 0x3FFFFFFFFFFFFFFF (Varint encoded as 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF)
 */
static uint8_t test_frame_max_streams_unidir_extremely_large[] = {
    picoquic_frame_type_max_streams_unidir,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

/* Test Case for MAX_DATA in a post-close scenario.
 * Type: MAX_DATA (0x10)
 * Maximum Data: 200000 (Varint encoded as 0x80, 0x03, 0x0D, 0x40)
 */
static uint8_t test_frame_max_data_after_close_scenario[] = {
    picoquic_frame_type_max_data,
    0x80, 0x03, 0x0D, 0x40 /* 200000 */
};

/* Test Case for MAX_STREAM_DATA on a reset stream.
 * Type: MAX_STREAM_DATA (0x11)
 * Stream ID: 4
 * Maximum Stream Data: 10000 (Varint encoded as 0x80, 0x00, 0x27, 0x10)
 */
static uint8_t test_frame_max_stream_data_for_reset_stream_scenario[] = {
    picoquic_frame_type_max_stream_data,
    0x04,       /* Stream ID: 4 */
    0x80, 0x00, 0x27, 0x10 /* 10000 */
};

/* New CONNECTION_CLOSE and APPLICATION_CLOSE frame test cases */

/* Test Case 1: test_frame_connection_close_reason_len_too_large */
/* Type: picoquic_frame_type_connection_close (0x1c)
 * Error Code: 0x01 (INTERNAL_ERROR)
 * Frame Type: 0x00 (Padding, chosen as an example)
 * Reason Phrase Length: 2000 (Varint encoded as 0x47, 0xD0)
 * Reason Phrase: "short actual phrase" (19 bytes)
 */
static uint8_t test_frame_connection_close_reason_len_too_large[] = {
    picoquic_frame_type_connection_close,
    0x01,       /* Error Code: INTERNAL_ERROR */
    0x00,       /* Frame Type: PADDING_FRAME */
    0x47, 0xD0, /* Reason Phrase Length: 2000 */
    's', 'h', 'o', 'r', 't', ' ', 'a', 'c', 't', 'u', 'a', 'l', ' ', 'p', 'h', 'r', 'a', 's', 'e'
};

/* Test Case 2: test_frame_application_close_reason_len_too_large */
/* Type: picoquic_frame_type_application_close (0x1d)
 * Error Code: 0x0101 (Application specific, encoded as 0x41, 0x01)
 * Reason Phrase Length: 2000 (Varint encoded as 0x47, 0xD0)
 * Reason Phrase: "short actual phrase" (19 bytes)
 */
static uint8_t test_frame_application_close_reason_len_too_large[] = {
    picoquic_frame_type_application_close,
    0x41, 0x01, /* Error Code: 0x0101 */
    0x47, 0xD0, /* Reason Phrase Length: 2000 */
    's', 'h', 'o', 'r', 't', ' ', 'a', 'c', 't', 'u', 'a', 'l', ' ', 'p', 'h', 'r', 'a', 's', 'e'
};

/* Test Case 3: test_frame_connection_close_reason_len_shorter */
/* Type: picoquic_frame_type_connection_close (0x1c)
 * Error Code: 0x01
 * Frame Type: 0x00
 * Reason Phrase Length: 5 (Varint encoded as 0x05)
 * Reason Phrase: "this is much longer than five" (29 bytes)
 */
static uint8_t test_frame_connection_close_reason_len_shorter[] = {
    picoquic_frame_type_connection_close,
    0x01,       /* Error Code: INTERNAL_ERROR */
    0x00,       /* Frame Type: PADDING_FRAME */
    0x05,       /* Reason Phrase Length: 5 */
    't', 'h', 'i', 's', ' ', 'i', 's', ' ', 'm', 'u', 'c', 'h', ' ', 'l', 'o', 'n', 'g', 'e', 'r', ' ', 't', 'h', 'a', 'n', ' ', 'f', 'i', 'v', 'e'
};

/* Test Case 4: test_frame_application_close_reason_len_shorter */
/* Type: picoquic_frame_type_application_close (0x1d)
 * Error Code: 0x0101 (encoded as 0x41, 0x01)
 * Reason Phrase Length: 5 (Varint encoded as 0x05)
 * Reason Phrase: "this is much longer than five" (29 bytes)
 */
static uint8_t test_frame_application_close_reason_len_shorter[] = {
    picoquic_frame_type_application_close,
    0x41, 0x01, /* Error Code: 0x0101 */
    0x05,       /* Reason Phrase Length: 5 */
    't', 'h', 'i', 's', ' ', 'i', 's', ' ', 'm', 'u', 'c', 'h', ' ', 'l', 'o', 'n', 'g', 'e', 'r', ' ', 't', 'h', 'a', 'n', ' ', 'f', 'i', 'v', 'e'
};

/* Test Case 5: test_frame_connection_close_reason_len_longer */
/* Type: picoquic_frame_type_connection_close (0x1c)
 * Error Code: 0x01
 * Frame Type: 0x00
 * Reason Phrase Length: 30 (Varint encoded as 0x1E)
 * Reason Phrase: "short" (5 bytes)
 */
static uint8_t test_frame_connection_close_reason_len_longer[] = {
    picoquic_frame_type_connection_close,
    0x01,       /* Error Code: INTERNAL_ERROR */
    0x00,       /* Frame Type: PADDING_FRAME */
    0x1E,       /* Reason Phrase Length: 30 */
    's', 'h', 'o', 'r', 't'
};

/* Test Case 6: test_frame_application_close_reason_len_longer */
/* Type: picoquic_frame_type_application_close (0x1d)
 * Error Code: 0x0101 (encoded as 0x41, 0x01)
 * Reason Phrase Length: 30 (Varint encoded as 0x1E)
 * Reason Phrase: "short" (5 bytes)
 */
static uint8_t test_frame_application_close_reason_len_longer[] = {
    picoquic_frame_type_application_close,
    0x41, 0x01, /* Error Code: 0x0101 */
    0x1E,       /* Reason Phrase Length: 30 */
    's', 'h', 'o', 'r', 't'
};

/* Test Case 1: CONNECTION_CLOSE (transport error) with an invalid inner Frame Type
 * for the packet type it might be placed in (e.g. STREAM frame in Initial).
 * Type: CONNECTION_CLOSE (transport error, 0x1c)
 * Error Code: 0x0a (PROTOCOL_VIOLATION)
 * Frame Type: 0x08 (STREAM frame type)
 * Reason Phrase Length: 4
 * Reason Phrase: "test"
 */
static uint8_t test_frame_connection_close_invalid_inner_frame_type[] = {
    picoquic_frame_type_connection_close, /* 0x1c */
    0x0a,       /* Error Code: PROTOCOL_VIOLATION */
    0x08,       /* Frame Type: STREAM (example of an invalid type in certain contexts) */
    0x04,       /* Reason Phrase Length: 4 */
    't', 'e', 's', 't'
};

/* Test Case 2: CONNECTION_CLOSE (application error) with a non-UTF-8 reason phrase.
 * Type: CONNECTION_CLOSE (application error, 0x1d)
 * Error Code: 0x0101 (application error, varint 0x4101)
 * Reason Phrase Length: 4
 * Reason Phrase: { 0xC3, 0x28, 0xA0, 0xA1 } (invalid UTF-8)
 */
static uint8_t test_frame_connection_close_reason_non_utf8[] = {
    picoquic_frame_type_application_close, /* 0x1d */
    0x41, 0x01, /* Error Code: 0x0101 */
    0x04,       /* Reason Phrase Length: 4 */
    0xC3, 0x28, 0xA0, 0xA1 /* Invalid UTF-8 sequence */
};

/* New NEW_CONNECTION_ID frame test cases */

/* Test Case 1: test_frame_new_cid_retire_prior_to_greater */
/* Type: picoquic_frame_type_new_connection_id (0x18)
 * Sequence Number: 5 (0x05)
 * Retire Prior To: 10 (0x0A)
 * Length: 8 (0x08)
 * Connection ID: 0x01, ..., 0x08
 * Stateless Reset Token: 0xA0, ..., 0xAF
 */
static uint8_t test_frame_new_cid_retire_prior_to_greater[] = {
    picoquic_frame_type_new_connection_id,
    0x05, /* Sequence Number */
    0x0A, /* Retire Prior To */
    0x08, /* Length */
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, /* Connection ID */
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, /* Stateless Reset Token */
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF
};

/* Test Case 2: test_frame_new_cid_zero_length */
/* Type: picoquic_frame_type_new_connection_id (0x18)
 * Sequence Number: 7 (0x07)
 * Retire Prior To: 2 (0x02)
 * Length: 0 (0x00)
 * Connection ID: (empty)
 * Stateless Reset Token: 0xB0, ..., 0xBF
 */
static uint8_t test_frame_new_cid_zero_length[] = {
    picoquic_frame_type_new_connection_id,
    0x07, /* Sequence Number */
    0x02, /* Retire Prior To */
    0x00, /* Length */
    /* No Connection ID */
    0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, /* Stateless Reset Token */
    0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF
};

/* Test Case 3: test_frame_new_cid_length_too_large */
/* Type: picoquic_frame_type_new_connection_id (0x18)
 * Sequence Number: 8 (0x08)
 * Retire Prior To: 3 (0x03)
 * Length: 21 (0x15)
 * Connection ID: 0xC0, ..., 0xD4 (21 bytes)
 * Stateless Reset Token: 0xE0, ..., 0xEF
 */
static uint8_t test_frame_new_cid_length_too_large[] = {
    picoquic_frame_type_new_connection_id,
    0x08, /* Sequence Number */
    0x03, /* Retire Prior To */
    0x15, /* Length (21) */
    0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, /* Connection ID (21 bytes) */
    0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, /* Stateless Reset Token */
    0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF
};

/* New NEW_TOKEN frame test cases */

/* Test Case 1: test_frame_new_token_zero_length */
/* Type: picoquic_frame_type_new_token (0x07)
 * Token Length: 0 (Varint encoded as 0x00)
 * Token: (empty)
 */
static uint8_t test_frame_new_token_zero_length[] = {
    picoquic_frame_type_new_token,
    0x00  /* Token Length: 0 */
    /* No Token data */
};

/* Test Case 2: test_frame_new_token_length_too_large */
/* Type: picoquic_frame_type_new_token (0x07)
 * Token Length: 2000 (Varint encoded as 0x47, 0xD0)
 * Token: "shortactualtoken" (16 bytes)
 */
static uint8_t test_frame_new_token_length_too_large[] = {
    picoquic_frame_type_new_token,
    0x47, 0xD0, /* Token Length: 2000 */
    's', 'h', 'o', 'r', 't', 'a', 'c', 't', 'u', 'a', 'l', 't', 'o', 'k', 'e', 'n'
};

/* Test Case 3: test_frame_new_token_length_shorter_than_data */
/* Type: picoquic_frame_type_new_token (0x07)
 * Token Length: 5 (Varint encoded as 0x05)
 * Token: "thisisalongertokenvalue" (25 bytes)
 */
static uint8_t test_frame_new_token_length_shorter_than_data[] = {
    picoquic_frame_type_new_token,
    0x05,       /* Token Length: 5 */
    't', 'h', 'i', 's', 'i', 's', 'a', 'l', 'o', 'n', 'g', 'e', 'r', 't', 'o', 'k', 'e', 'n', 'v', 'a', 'l', 'u', 'e'
};

/* Test Case 4: test_frame_new_token_length_longer_than_data */
/* Type: picoquic_frame_type_new_token (0x07)
 * Token Length: 30 (Varint encoded as 0x1E)
 * Token: "shorttoken" (10 bytes)
 */
static uint8_t test_frame_new_token_length_longer_than_data[] = {
    picoquic_frame_type_new_token,
    0x1E,       /* Token Length: 30 */
    's', 'h', 'o', 'r', 't', 't', 'o', 'k', 'e', 'n'
};

/* New CRYPTO frame test cases */

/* Test Case 1: test_frame_crypto_len_beyond_packet */
/* Type: picoquic_frame_type_crypto_hs (0x06)
 * Offset: 0 (Varint encoded as 0x00)
 * Length: 65536 (Varint encoded as 0x80, 0x01, 0x00, 0x00)
 * Crypto Data: "testcryptodata" (14 bytes)
 */
static uint8_t test_frame_crypto_len_beyond_packet[] = {
    picoquic_frame_type_crypto_hs,
    0x00,       /* Offset: 0 */
    0x80, 0x01, 0x00, 0x00, /* Length: 65536 */
    't', 'e', 's', 't', 'c', 'r', 'y', 'p', 't', 'o', 'd', 'a', 't', 'a'
};

/* Test Case 2: test_frame_crypto_zero_len_with_data */
/* Type: picoquic_frame_type_crypto_hs (0x06)
 * Offset: 0 (Varint encoded as 0x00)
 * Length: 0 (Varint encoded as 0x00)
 * Crypto Data: "actualdata" (10 bytes)
 */
static uint8_t test_frame_crypto_zero_len_with_data[] = {
    picoquic_frame_type_crypto_hs,
    0x00,       /* Offset: 0 */
    0x00,       /* Length: 0 */
    'a', 'c', 't', 'u', 'a', 'l', 'd', 'a', 't', 'a'
};

/* Test Case 3: test_frame_crypto_len_shorter_than_data */
/* Type: picoquic_frame_type_crypto_hs (0x06)
 * Offset: 0 (Varint encoded as 0x00)
 * Length: 5 (Varint encoded as 0x05)
 * Crypto Data: "muchlongercryptodata" (20 bytes)
 */
static uint8_t test_frame_crypto_len_shorter_than_data[] = {
    picoquic_frame_type_crypto_hs,
    0x00,       /* Offset: 0 */
    0x05,       /* Length: 5 */
    'm', 'u', 'c', 'h', 'l', 'o', 'n', 'g', 'e', 'r', 'c', 'r', 'y', 'p', 't', 'o', 'd', 'a', 't', 'a'
};

/* Test Case 4: test_frame_crypto_len_longer_than_data */
/* Type: picoquic_frame_type_crypto_hs (0x06)
 * Offset: 0 (Varint encoded as 0x00)
 * Length: 30 (Varint encoded as 0x1E)
 * Crypto Data: "shortcrypto" (11 bytes)
 */
static uint8_t test_frame_crypto_len_longer_than_data[] = {
    picoquic_frame_type_crypto_hs,
    0x00,       /* Offset: 0 */
    0x1E,       /* Length: 30 */
    's', 'h', 'o', 'r', 't', 'c', 'r', 'y', 'p', 't', 'o'
};

/* Test Case 5: test_frame_crypto_max_offset_max_len */
/* Type: picoquic_frame_type_crypto_hs (0x06)
 * Offset: 0x3FFFFFFFFFFFFFFF (Varint encoded as 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF)
 * Length: 0x3FFFFFFFFFFFFFFF (Varint encoded as 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF)
 * Crypto Data: "tiny" (4 bytes)
 */
static uint8_t test_frame_crypto_max_offset_max_len[] = {
    picoquic_frame_type_crypto_hs,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* Offset */
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* Length */
    't', 'i', 'n', 'y'
};

/* New fuzzy varint test cases */

/* Test Case 1: test_frame_max_data_non_minimal_varint */
/* Type: picoquic_frame_type_max_data (0x10)
 * Maximum Data: Value 48 (0x30) encoded non-minimally as a 2-byte varint (0x40, 0x30).
 * Minimal encoding would be 0x30.
 */
static uint8_t test_frame_max_data_non_minimal_varint[] = {
    picoquic_frame_type_max_data,
    0x40, 0x30  /* Non-minimal encoding of 48 */
};

/* Test Case 2: test_frame_reset_stream_invalid_9_byte_varint */
/* Type: picoquic_frame_type_reset_stream (0x04)
 * Stream ID: Invalid 9-byte varint. First byte 0xC0 suggests an 8-byte encoding,
 *            but is followed by 8 more bytes, making the varint itself 9 bytes long.
 * Application Protocol Error Code: 0 (0x00)
 * Final Size: 0 (0x00)
 */
static uint8_t test_frame_reset_stream_invalid_9_byte_varint[] = {
    picoquic_frame_type_reset_stream,
    0xC0, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, /* Stream ID (9-byte varint) */
    0x00,       /* Application Protocol Error Code: 0 */
    0x00        /* Final Size: 0 */
};

/* Test Case 3: test_frame_stop_sending_non_minimal_error_code */
/* Type: picoquic_frame_type_stop_sending (0x05)
 * Stream ID: 1 (0x01)
 * Application Protocol Error Code: Value 0 encoded non-minimally as 2-byte varint (0x40, 0x00).
 * Minimal encoding would be 0x00.
 */
static uint8_t test_frame_stop_sending_non_minimal_error_code[] = {
    picoquic_frame_type_stop_sending,
    0x01,       /* Stream ID: 1 */
    0x40, 0x00  /* Non-minimal encoding of error code 0 */
};

/* Test Case 1 (Varint): MAX_STREAMS (bidirectional) with non-minimal varint for stream count.
 * Type: MAX_STREAMS (bidirectional, 0x12)
 * Maximum Streams: Value 10 (normally 0x0A) encoded as a 2-byte varint (0x40, 0x0A).
 */
static uint8_t test_frame_max_streams_non_minimal_varint[] = {
    picoquic_frame_type_max_streams_bidir, /* 0x12 */
    0x40, 0x0A  /* Non-minimal encoding of 10 */
};

/* Test Case 2 (Varint): CRYPTO frame with a non-minimal large varint for offset.
 * Type: CRYPTO (0x06)
 * Offset: Value 1 encoded as an 8-byte varint (0xC000000000000001).
 * Length: 5
 * Crypto Data: "hello"
 */
static uint8_t test_frame_crypto_offset_non_minimal_large_varint[] = {
    picoquic_frame_type_crypto_hs, /* 0x06 */
    0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, /* Non-minimal 8-byte encoding of 1 */
    0x05,       /* Length: 5 */
    'h', 'e', 'l', 'l', 'o'
};

/* New static test cases for less common frame variations */

/* Test Case 1: test_frame_retire_cid_seq_much_higher */
/* Type: picoquic_frame_type_retire_connection_id (0x19)
 * Sequence Number: 10000 (Varint encoded as 0x67, 0x10)
 */
static uint8_t test_frame_retire_cid_seq_much_higher[] = {
    picoquic_frame_type_retire_connection_id,
    0x67, 0x10  /* Sequence Number: 10000 */
};

/* Test Case 2: test_frame_datagram_len_shorter_than_data */
/* Type: picoquic_frame_type_datagram_l (0x31)
 * Length: 5 (Varint encoded as 0x05)
 * Datagram Data: "thisislongdatagramdata" (24 bytes)
 */
static uint8_t test_frame_datagram_len_shorter_than_data[] = {
    picoquic_frame_type_datagram_l,
    0x05,       /* Length: 5 */
    't', 'h', 'i', 's', 'i', 's', 'l', 'o', 'n', 'g', 'd', 'a', 't', 'a', 'g', 'r', 'a', 'm', 'd', 'a', 't', 'a'
};

/* Test Case 3: test_frame_datagram_len_longer_than_data */
/* Type: picoquic_frame_type_datagram_l (0x31)
 * Length: 20 (Varint encoded as 0x14)
 * Datagram Data: "shortdata" (9 bytes)
 */
static uint8_t test_frame_datagram_len_longer_than_data[] = {
    picoquic_frame_type_datagram_l,
    0x14,       /* Length: 20 */
    's', 'h', 'o', 'r', 't', 'd', 'a', 't', 'a'
};

/* Test Case 4: test_frame_datagram_zero_len_with_data */
/* Type: picoquic_frame_type_datagram_l (0x31)
 * Length: 0 (Varint encoded as 0x00)
 * Datagram Data: "actualdatagramdata" (18 bytes)
 */
static uint8_t test_frame_datagram_zero_len_with_data[] = {
    picoquic_frame_type_datagram_l,
    0x00,       /* Length: 0 */
    'a', 'c', 't', 'u', 'a', 'l', 'd', 'a', 't', 'a', 'g', 'r', 'a', 'm', 'd', 'a', 't', 'a'
};

/* Non-Canonical Variable-Length Integers */
static uint8_t test_frame_stream_long_varint_stream_id_2byte[] = {
    0x08,       /* Type: STREAM */
    0x40, 0x05, /* Stream ID: 5 (2-byte varint) */
    't', 'e', 's', 't'
};

static uint8_t test_frame_stream_long_varint_stream_id_4byte[] = {
    0x08,       /* Type: STREAM */
    0x80, 0x00, 0x00, 0x05, /* Stream ID: 5 (4-byte varint) */
    't', 'e', 's', 't'
};

static uint8_t test_frame_stream_long_varint_offset_2byte[] = {
    0x0C,       /* Type: STREAM, OFF bit */
    0x01,       /* Stream ID: 1 */
    0x40, 0x0A, /* Offset: 10 (2-byte varint) */
    't', 'e', 's', 't'
};

static uint8_t test_frame_stream_long_varint_offset_4byte[] = {
    0x0C,       /* Type: STREAM, OFF bit */
    0x01,       /* Stream ID: 1 */
    0x80, 0x00, 0x00, 0x0A, /* Offset: 10 (4-byte varint) */
    't', 'e', 's', 't'
};

static uint8_t test_frame_stream_long_varint_length_2byte[] = {
    0x0A,       /* Type: STREAM, LEN bit */
    0x01,       /* Stream ID: 1 */
    0x40, 0x04, /* Length: 4 (2-byte varint) */
    't', 'e', 's', 't'
};

static uint8_t test_frame_stream_long_varint_length_4byte[] = {
    0x0A,       /* Type: STREAM, LEN bit */
    0x01,       /* Stream ID: 1 */
    0x80, 0x00, 0x00, 0x04, /* Length: 4 (4-byte varint) */
    't', 'e', 's', 't'
};

static uint8_t test_frame_max_data_long_varint_2byte[] = {
    picoquic_frame_type_max_data,
    0x44, 0x00  /* Maximum Data: 1024 (0x400) (2-byte varint) */
};

static uint8_t test_frame_max_data_long_varint_4byte[] = {
    picoquic_frame_type_max_data,
    0x80, 0x00, 0x04, 0x00  /* Maximum Data: 1024 (0x400) (4-byte varint) */
};

static uint8_t test_frame_ack_long_varint_largest_acked_2byte[] = {
    picoquic_frame_type_ack,
    0x40, 0x14, /* Largest Acknowledged: 20 (2-byte varint) */
    0x00,       /* ACK Delay: 0 */
    0x01,       /* ACK Range Count: 1 */
    0x00        /* First ACK Range: 0 */
};

static uint8_t test_frame_ack_long_varint_largest_acked_4byte[] = {
    picoquic_frame_type_ack,
    0x80, 0x00, 0x00, 0x14, /* Largest Acknowledged: 20 (4-byte varint) */
    0x00,       /* ACK Delay: 0 */
    0x01,       /* ACK Range Count: 1 */
    0x00        /* First ACK Range: 0 */
};

static uint8_t test_frame_crypto_long_varint_offset_2byte[] = {
    picoquic_frame_type_crypto_hs,
    0x40, 0x0A, /* Offset: 10 (2-byte varint) */
    0x04,       /* Length: 4 */
    't', 'e', 's', 't'
};

static uint8_t test_frame_crypto_long_varint_offset_4byte[] = {
    picoquic_frame_type_crypto_hs,
    0x80, 0x00, 0x00, 0x0A, /* Offset: 10 (4-byte varint) */
    0x04,       /* Length: 4 */
    't', 'e', 's', 't'
};

/* Aggressive Padding / PMTU Probing Mimics */
static uint8_t test_frame_ping_padded_to_1200[1200] = {0x01}; /* PING + 1199 PADDING */
static uint8_t test_frame_ping_padded_to_1500[1500] = {0x01}; /* PING + 1499 PADDING */

/* ACK Frame Stress Tests */
static uint8_t test_frame_ack_very_many_small_ranges[] = {
    0x02,       /* Type: ACK */
    0x40, 0xC8, /* Largest Acknowledged: 200 */
    0x00,       /* ACK Delay: 0 */
    0x32,       /* ACK Range Count: 50 */
    0x00,       /* First ACK Range: 0 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 10 ranges */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 20 ranges */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 30 ranges */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 40 ranges */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00        /* 49 ranges */
};

static uint8_t test_frame_ack_alternating_large_small_gaps[] = {
    0x02,       /* Type: ACK */
    0x64,       /* Largest Acknowledged: 100 */
    0x00,       /* ACK Delay: 0 */
    0x04,       /* ACK Range Count: 4 */
    0x00,       /* First ACK Range: 0 (acks 100) */
    0x30,       /* Gap: 48 */
    0x00,       /* ACK Range Length: 0 (acks 50) */
    0x00,       /* Gap: 0 */
    0x00,       /* ACK Range Length: 0 (acks 48) */
    0x14,       /* Gap: 20 */
    0x00        /* ACK Range Length: 0 (acks 26) */
};

/* Unusual but Valid Header Flags/Values (Frames) */
static uint8_t test_frame_stream_id_almost_max[] = {
    0x08,       /* Type: STREAM */
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* Stream ID: 2^62-1 */
    'm', 'a', 'x', 'S'
};

static uint8_t test_frame_stream_offset_almost_max[] = {
    0x0C,       /* Type: STREAM, OFF bit */
    0x01,       /* Stream ID: 1 */
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* Offset: 2^62-1 */
    'm', 'a', 'x', 'O'
};

/* PATH_CHALLENGE / PATH_RESPONSE Variants */
static uint8_t test_frame_path_challenge_alt_pattern[] = {
    0x1a, 0xA5,0x5A,0xA5,0x5A,0xA5,0x5A,0xA5,0x5A
};
static uint8_t test_frame_path_response_alt_pattern[] = {
    0x1b, 0x5A,0xA5,0x5A,0xA5,0x5A,0xA5,0x5A,0xA5
};

/* NEW_TOKEN Frame Variants */
static uint8_t test_frame_new_token_max_plausible_len[3 + 256] = {
    0x07, 0x41, 0x00, /* Token Length 256 */
    /* Followed by 256 bytes of 0xAA */
};
static uint8_t test_frame_new_token_min_len[] = {
    0x07, 0x01, 0xBB
};

/* CONNECTION_CLOSE Frame Variants */
static uint8_t test_frame_connection_close_max_reason_len[5 + 1000] = {
    0x1c, 0x00, 0x00, 0x43, 0xE8, /* Error Code 0, Frame Type 0, Reason Length 1000 */
    /* Followed by 1000 bytes of 'A' (0x41) */
};
static uint8_t test_frame_connection_close_app_max_reason_len[4 + 1000] = {
    0x1d, 0x00, 0x43, 0xE8, /* Error Code 0, Reason Length 1000 */
    /* Followed by 1000 bytes of 'B' (0x42) */
};

/* RETIRE_CONNECTION_ID Variants */
static uint8_t test_frame_retire_cid_high_seq[] = {
    0x19, 0x80, 0x3B, 0x9A, 0xCA, 0x00 /* Sequence Number 1,000,000,000 */
};

/* MAX_STREAMS Variants (Absolute Max) */
static uint8_t test_frame_max_streams_bidi_abs_max[] = {
    0x12, 0xC0,0x00,0x00,0x00,0x10,0x00,0x00,0x00 /* Max Streams 2^60 */
};
static uint8_t test_frame_max_streams_uni_abs_max[] = {
    0x13, 0xC0,0x00,0x00,0x00,0x10,0x00,0x00,0x00 /* Max Streams 2^60 */
};

/* Additional STREAM Frame Variants */
static uint8_t test_frame_stream_off_len_fin_empty[] = {
    0x0F,       /* Type: STREAM, OFF, LEN, FIN bits */
    0x01,       /* Stream ID: 1 */
    0x64,       /* Offset: 100 (1-byte varint) */
    0x00        /* Length: 0 */
};

static uint8_t test_frame_stream_off_no_len_fin[] = {
    0x0D,       /* Type: STREAM, OFF, FIN bits */
    0x02,       /* Stream ID: 2 */
    0x40, 0xC8, /* Offset: 200 (2-byte varint) */
    'f', 'i', 'n'
};

static uint8_t test_frame_stream_no_off_len_fin_empty[] = {
    0x0B,       /* Type: STREAM, LEN, FIN bits */
    0x03,       /* Stream ID: 3 */
    0x00        /* Length: 0 */
};

static uint8_t test_frame_stream_just_fin_at_zero[] = {
    0x09,       /* Type: STREAM, FIN bit */
    0x04        /* Stream ID: 4 */
};

/* Zero-Length Data Frames with Max Varint Encoding for Fields */
static uint8_t test_frame_data_blocked_max_varint_offset[] = {
    0x14,       /* Type: DATA_BLOCKED */
    0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00 /* Max Data: 1024 (8-byte varint) */
};

static uint8_t test_frame_stream_data_blocked_max_varint_fields[] = {
    0x15,       /* Type: STREAM_DATA_BLOCKED */
    0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, /* Stream ID: 1 (8-byte varint) */
    0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00  /* Max Stream Data: 1024 (8-byte varint) */
};

static uint8_t test_frame_streams_blocked_bidi_max_varint_limit[] = {
    0x16,       /* Type: STREAMS_BLOCKED (bidirectional) */
    0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A  /* Max Streams: 10 (8-byte varint) */
};

static uint8_t test_frame_streams_blocked_uni_max_varint_limit[] = {
    0x17,       /* Type: STREAMS_BLOCKED (unidirectional) */
    0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A  /* Max Streams: 10 (8-byte varint) */
};

/* CRYPTO Frame Edge Cases */
static uint8_t test_frame_crypto_zero_len_large_offset[] = {
    0x06,       /* Type: CRYPTO */
    0x80, 0x01, 0x00, 0x00, /* Offset: 65536 (4-byte varint) */
    0x00        /* Length: 0 */
};

/* Test Case: NEW_TOKEN frame with an empty token. */
/* Expected: Client treats as FRAME_ENCODING_ERROR (RFC 19.7). */
static uint8_t test_frame_new_token_empty_token[] = {
    picoquic_frame_type_new_token, /* Type 0x07 */
    0x00                           /* Token Length: 0 */
};

/* Test Case: STREAM frame type (0x08) encoded non-minimally as 2 bytes (0x4008). */
/* Expected: Peer MAY treat as PROTOCOL_VIOLATION (RFC 12.4). */
static uint8_t test_frame_stream_type_long_encoding[] = {
    0x40, 0x08, /* Frame Type STREAM (0x08) as 2-byte varint */
    0x01,       /* Stream ID: 1 */
    't', 'e', 's', 't'
};

/* Test Case: ACK frame type (0x02) encoded non-minimally as 2 bytes (0x4002). */
/* Expected: Peer MAY treat as PROTOCOL_VIOLATION (RFC 12.4). */
static uint8_t test_frame_ack_type_long_encoding[] = {
    0x40, 0x02, /* Frame Type ACK (0x02) as 2-byte varint */
    0x00,       /* Largest Acknowledged: 0 */
    0x00,       /* ACK Delay: 0 */
    0x01,       /* ACK Range Count: 1 */
    0x00        /* First ACK Range: 0 */
};

/* Test Case: RESET_STREAM frame type (0x04) encoded non-minimally as 2 bytes (0x4004). */
/* Expected: Peer MAY treat as PROTOCOL_VIOLATION (RFC 12.4). */
static uint8_t test_frame_reset_stream_type_long_encoding[] = {
    0x40, 0x04, /* Frame Type RESET_STREAM (0x04) as 2-byte varint */
    0x01,       /* Stream ID: 1 */
    0x00,       /* Application Error Code: 0 */
    0x00        /* Final Size: 0 */
};

/* Test Case: MAX_STREAMS (bidirectional) with Maximum Streams = 2^60 + 1 (invalid) */
/* Expected: FRAME_ENCODING_ERROR (RFC 19.11). */
static uint8_t test_frame_max_streams_bidi_just_over_limit[] = {
    picoquic_frame_type_max_streams_bidir, /* Type 0x12 */
    0xC0, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x01 /* Max Streams: (1ULL<<60) + 1 */
};

/* Test Case: MAX_STREAMS (unidirectional) with Maximum Streams = 2^60 + 1 (invalid) */
/* Expected: FRAME_ENCODING_ERROR (RFC 19.11). */
static uint8_t test_frame_max_streams_uni_just_over_limit[] = {
    picoquic_frame_type_max_streams_unidir, /* Type 0x13 */
    0xC0, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x01 /* Max Streams: (1ULL<<60) + 1 */
};

/* Test Case: Client sends STOP_SENDING for a server-initiated unidirectional stream (receive-only for client) */
/* Expected: Server treats as STREAM_STATE_ERROR (RFC 19.5 / Sec 3). */
/* To be injected when fuzzer acts as client. Stream ID 3 is server-initiated uni. */
static uint8_t test_client_sends_stop_sending_for_server_uni_stream[] = {
    picoquic_frame_type_stop_sending, /* Type 0x05 */
    0x03,                             /* Stream ID: 3 (server-initiated uni) */
    0x00                              /* Application Error Code: 0 */
};

/* Test Case: Server sends STOP_SENDING for a client-initiated unidirectional stream (receive-only for server) */
/* Expected: Client treats as STREAM_STATE_ERROR (RFC 19.5 / Sec 3). */
/* To be injected when fuzzer acts as server. Stream ID 2 is client-initiated uni. */
static uint8_t test_server_sends_stop_sending_for_client_uni_stream[] = {
    picoquic_frame_type_stop_sending, /* Type 0x05 */
    0x02,                             /* Stream ID: 2 (client-initiated uni) */
    0x00                              /* Application Error Code: 0 */
};

/* Test Case: Client sends MAX_STREAM_DATA for a client-initiated unidirectional stream (send-only for client) */
/* Expected: Server treats as STREAM_STATE_ERROR (RFC 19.10 / Sec 3). */
/* To be injected when fuzzer acts as client. Stream ID 2 is client-initiated uni. */
static uint8_t test_client_sends_max_stream_data_for_client_uni_stream[] = {
    picoquic_frame_type_max_stream_data, /* Type 0x11 */
    0x02,                                /* Stream ID: 2 */
    0x41, 0x00                           /* Max Stream Data: 256 */
};

/* Test Case: ACK frame in 1-RTT space acknowledging packet numbers typical of Initial/Handshake space. */
/* Expected: Peer should ignore these ACK ranges as they don't pertain to 1-RTT packets. */
/* (Indirect test for RFC 19.3, 12.5 PNS isolation for ACKs) */
static uint8_t test_frame_ack_cross_pns_low_pkns[] = {
    picoquic_frame_type_ack, /* Type 0x02 */
    0x02,                   /* Largest Acknowledged: 2 */
    0x00,                   /* ACK Delay: 0 */
    0x01,                   /* ACK Range Count: 1 */
    0x02                    /* First ACK Range: 2 (acks packets 0, 1, 2) */
};

/* Test Case: NEW_CONNECTION_ID frame. */
/* Context: To be sent to a peer that is configured to use/expect zero-length CIDs. */
/* Expected: Peer treats as PROTOCOL_VIOLATION (RFC 19.15). */
static uint8_t test_frame_new_cid_to_zero_len_peer[] = {
    picoquic_frame_type_new_connection_id, /* Type 0x18 */
    0x05,                                  /* Sequence Number: 5 */
    0x01,                                  /* Retire Prior To: 1 */
    0x08,                                  /* Length: 8 */
    0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,0x11, /* Connection ID */
    0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88, /* Stateless Reset Token */
    0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00
};

/* Test Case: RETIRE_CONNECTION_ID frame. */
/* Context: To be sent to a peer that has provided a zero-length source CID. */
/* Expected: Peer treats as PROTOCOL_VIOLATION (RFC 19.16). */
static uint8_t test_frame_retire_cid_to_zero_len_provider[] = {
    picoquic_frame_type_retire_connection_id, /* Type 0x19 */
    0x01                                      /* Sequence Number: 1 (to retire) */
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
    FUZI_Q_ITEM("reset_stream_app_error_specific", test_frame_reset_stream_app_error_specific), /* This is {0x04, 0x01, 0x00, 0x01} */
    FUZI_Q_ITEM("reset_stream_sid_zero", test_frame_reset_stream_sid_zero), /* New */
    FUZI_Q_ITEM("reset_stream_final_size_zero_explicit", test_frame_reset_stream_final_size_zero_explicit), /* New (StreamID=1, Err=0, FinalSize=0) */
    FUZI_Q_ITEM("reset_stream_all_large", test_frame_reset_stream_all_large), /* New */
    FUZI_Q_ITEM("connection_close", test_type_connection_close),
    FUZI_Q_ITEM("connection_close_transport_long_reason", test_frame_connection_close_transport_long_reason),
    FUZI_Q_ITEM("application_close", test_type_application_close),
    FUZI_Q_ITEM("application_close", test_type_application_close_reason),
    FUZI_Q_ITEM("application_close_long_reason", test_frame_application_close_long_reason),
    FUZI_Q_ITEM("conn_close_no_reason", test_frame_conn_close_no_reason),
    FUZI_Q_ITEM("conn_close_app_no_reason", test_frame_conn_close_app_no_reason),
    FUZI_Q_ITEM("conn_close_specific_transport_error", test_frame_conn_close_specific_transport_error),
    FUZI_Q_ITEM("max_data", test_frame_type_max_data),
    FUZI_Q_ITEM("max_data_large", test_frame_type_max_data_large),
    FUZI_Q_ITEM("max_data_zero", test_frame_max_data_zero), 
    FUZI_Q_ITEM("max_data_val_large", test_frame_max_data_val_large), /* New */
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
    FUZI_Q_ITEM("data_blocked_zero", test_frame_data_blocked_zero),
    FUZI_Q_ITEM("stream_data_blocked", test_frame_type_stream_blocked),
    FUZI_Q_ITEM("stream_data_blocked_large_limits", test_frame_type_stream_data_blocked_large_limits),
    FUZI_Q_ITEM("stream_data_blocked_zero", test_frame_stream_data_blocked_zero),
    FUZI_Q_ITEM("streams_blocked_bidir", test_frame_type_streams_blocked_bidir),
    FUZI_Q_ITEM("streams_blocked_bidi_zero", test_frame_streams_blocked_bidi_zero),
    FUZI_Q_ITEM("streams_blocked_unidir", test_frame_type_streams_blocked_unidir),
    FUZI_Q_ITEM("streams_blocked_uni_zero", test_frame_streams_blocked_uni_zero),
    FUZI_Q_ITEM("new_connection_id", test_frame_type_new_connection_id),
    FUZI_Q_ITEM("new_connection_id_alt", test_frame_type_new_connection_id_alt),
    FUZI_Q_ITEM("new_cid_retire_high", test_frame_new_cid_retire_high),
    FUZI_Q_ITEM("new_cid_short_id", test_frame_new_cid_short_id),
    FUZI_Q_ITEM("new_cid_long_id", test_frame_new_cid_long_id),
    FUZI_Q_ITEM("stop_sending", test_frame_type_stop_sending),
    FUZI_Q_ITEM("stop_sending_high_error", test_frame_type_stop_sending_high_error),
    FUZI_Q_ITEM("stop_sending_min_vals", test_frame_stop_sending_min_vals),
    FUZI_Q_ITEM("stop_sending_app_error_specific", test_frame_stop_sending_app_error_specific),
    FUZI_Q_ITEM("stop_sending_sid_err_zero", test_frame_stop_sending_sid_err_zero), /* New */
    FUZI_Q_ITEM("stop_sending_all_large", test_frame_stop_sending_all_large), /* New */
    FUZI_Q_ITEM("challenge", test_frame_type_path_challenge),
    FUZI_Q_ITEM("path_challenge_alt_data", test_frame_type_path_challenge_alt_data),
    FUZI_Q_ITEM("response", test_frame_type_path_response),
    FUZI_Q_ITEM("path_response_alt_data", test_frame_type_path_response_alt_data),
    FUZI_Q_ITEM("path_challenge_all_zeros", test_frame_path_challenge_all_zeros),
    FUZI_Q_ITEM("path_response_all_zeros", test_frame_path_response_all_zeros),
    FUZI_Q_ITEM("path_challenge_mixed_pattern", test_frame_path_challenge_mixed_pattern),
    FUZI_Q_ITEM("path_response_mixed_pattern", test_frame_path_response_mixed_pattern),
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
    FUZI_Q_ITEM("retire_cid_seq_zero", test_frame_retire_cid_seq_zero),
    FUZI_Q_ITEM("retire_cid_seq_high", test_frame_retire_cid_seq_high),
    FUZI_Q_ITEM("datagram", test_frame_type_datagram),
    FUZI_Q_ITEM("datagram_l", test_frame_type_datagram_l),
    FUZI_Q_ITEM("handshake_done", test_frame_type_handshake_done),
    FUZI_Q_ITEM("ack_frequency", test_frame_type_ack_frequency),
    FUZI_Q_ITEM("time_stamp", test_frame_type_time_stamp),
    FUZI_Q_ITEM("path_abandon_0", test_frame_type_path_abandon_0),
    FUZI_Q_ITEM("path_abandon_1", test_frame_type_path_abandon_1),
    FUZI_Q_ITEM("path_backup", test_frame_type_path_backup),
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
    FUZI_Q_ITEM("bad_bdp", test_frame_type_bdp_bad_length),
    /* New ACK frame test items */
    FUZI_Q_ITEM("ack_excessive_ack_delay", test_frame_ack_excessive_ack_delay),
    FUZI_Q_ITEM("ack_first_range_too_large", test_frame_ack_first_range_too_large),
    FUZI_Q_ITEM("ack_too_many_ranges", test_frame_ack_too_many_ranges),
    FUZI_Q_ITEM("ack_ecn_ect0_too_large", test_frame_ack_ecn_ect0_too_large),
    /* New STREAM frame test items */
    FUZI_Q_ITEM("stream_len_beyond_packet", test_frame_stream_len_beyond_packet),
    FUZI_Q_ITEM("stream_zero_len_with_data", test_frame_stream_zero_len_with_data),
    FUZI_Q_ITEM("stream_len_shorter_than_data", test_frame_stream_len_shorter_than_data),
    FUZI_Q_ITEM("stream_len_longer_than_data", test_frame_stream_len_longer_than_data),
    FUZI_Q_ITEM("stream_max_offset_max_len", test_frame_stream_max_offset_max_len),
    /* New MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS frame test items */
    FUZI_Q_ITEM("max_data_extremely_large", test_frame_max_data_extremely_large),
    FUZI_Q_ITEM("max_stream_data_extremely_large", test_frame_max_stream_data_extremely_large),
    FUZI_Q_ITEM("max_streams_bidir_extremely_large", test_frame_max_streams_bidir_extremely_large),
    FUZI_Q_ITEM("max_streams_unidir_extremely_large", test_frame_max_streams_unidir_extremely_large),
    /* New CONNECTION_CLOSE and APPLICATION_CLOSE frame test items */
    FUZI_Q_ITEM("connection_close_reason_len_too_large", test_frame_connection_close_reason_len_too_large),
    FUZI_Q_ITEM("application_close_reason_len_too_large", test_frame_application_close_reason_len_too_large),
    FUZI_Q_ITEM("connection_close_reason_len_shorter", test_frame_connection_close_reason_len_shorter),
    FUZI_Q_ITEM("application_close_reason_len_shorter", test_frame_application_close_reason_len_shorter),
    FUZI_Q_ITEM("connection_close_reason_len_longer", test_frame_connection_close_reason_len_longer),
    FUZI_Q_ITEM("application_close_reason_len_longer", test_frame_application_close_reason_len_longer),
    /* New NEW_CONNECTION_ID frame test items */
    FUZI_Q_ITEM("new_cid_retire_prior_to_greater", test_frame_new_cid_retire_prior_to_greater),
    FUZI_Q_ITEM("new_cid_zero_length", test_frame_new_cid_zero_length),
    FUZI_Q_ITEM("new_cid_length_too_large", test_frame_new_cid_length_too_large),
    /* New NEW_TOKEN frame test items */
    FUZI_Q_ITEM("new_token_zero_length", test_frame_new_token_zero_length),
    FUZI_Q_ITEM("new_token_length_too_large", test_frame_new_token_length_too_large),
    FUZI_Q_ITEM("new_token_length_shorter_than_data", test_frame_new_token_length_shorter_than_data),
    FUZI_Q_ITEM("new_token_length_longer_than_data", test_frame_new_token_length_longer_than_data),
    /* New CRYPTO frame test items */
    FUZI_Q_ITEM("crypto_len_beyond_packet", test_frame_crypto_len_beyond_packet),
    FUZI_Q_ITEM("crypto_zero_len_with_data", test_frame_crypto_zero_len_with_data),
    FUZI_Q_ITEM("crypto_len_shorter_than_data", test_frame_crypto_len_shorter_than_data),
    FUZI_Q_ITEM("crypto_len_longer_than_data", test_frame_crypto_len_longer_than_data),
    FUZI_Q_ITEM("crypto_max_offset_max_len", test_frame_crypto_max_offset_max_len),
    /* User added STREAM frame test items */
    FUZI_Q_ITEM("stream_fin_too_long", test_frame_stream_fin_too_long),
    FUZI_Q_ITEM("stream_overlapping_data_part1", test_frame_stream_overlapping_data_part1),
    FUZI_Q_ITEM("stream_overlapping_data_part2", test_frame_stream_overlapping_data_part2),
    /* New fuzzy varint test items */
    FUZI_Q_ITEM("max_data_non_minimal_varint", test_frame_max_data_non_minimal_varint),
    FUZI_Q_ITEM("reset_stream_invalid_9_byte_varint", test_frame_reset_stream_invalid_9_byte_varint),
    FUZI_Q_ITEM("stop_sending_non_minimal_error_code", test_frame_stop_sending_non_minimal_error_code),
    /* User added ACK frame test items */
    FUZI_Q_ITEM("ack_overlapping_ranges", test_frame_ack_overlapping_ranges),
    FUZI_Q_ITEM("ack_ascending_ranges_invalid_gap", test_frame_ack_ascending_ranges_invalid_gap),
    FUZI_Q_ITEM("ack_invalid_range_count", test_frame_ack_invalid_range_count),
    FUZI_Q_ITEM("ack_largest_smaller_than_range", test_frame_ack_largest_smaller_than_range),
    /* New static test cases for less common frame variations */
    FUZI_Q_ITEM("retire_cid_seq_much_higher", test_frame_retire_cid_seq_much_higher),
    FUZI_Q_ITEM("datagram_len_shorter_than_data", test_frame_datagram_len_shorter_than_data),
    FUZI_Q_ITEM("datagram_len_longer_than_data", test_frame_datagram_len_longer_than_data),
    FUZI_Q_ITEM("datagram_zero_len_with_data", test_frame_datagram_zero_len_with_data),

    /* User added test frames from current plan (steps 1-6) */
    FUZI_Q_ITEM("max_data_after_close_scenario", test_frame_max_data_after_close_scenario),
    FUZI_Q_ITEM("max_stream_data_for_reset_stream_scenario", test_frame_max_stream_data_for_reset_stream_scenario),
    FUZI_Q_ITEM("streams_blocked_not_actually_blocked", test_frame_streams_blocked_not_actually_blocked),
    FUZI_Q_ITEM("streams_blocked_limit_too_high", test_frame_streams_blocked_limit_too_high),
    FUZI_Q_ITEM("stop_sending_for_peer_reset_stream", test_frame_stop_sending_for_peer_reset_stream),
    FUZI_Q_ITEM("stop_sending_large_error_code", test_frame_stop_sending_large_error_code),
    FUZI_Q_ITEM("retire_cid_current_in_use", test_frame_retire_cid_current_in_use),
    FUZI_Q_ITEM("new_cid_exceed_limit_no_retire", test_frame_new_cid_exceed_limit_no_retire),
    FUZI_Q_ITEM("connection_close_invalid_inner_frame_type", test_frame_connection_close_invalid_inner_frame_type),
    FUZI_Q_ITEM("connection_close_reason_non_utf8", test_frame_connection_close_reason_non_utf8),
    FUZI_Q_ITEM("ping_long_encoding", test_frame_ping_long_encoding),

    /* User added NEW_CONNECTION_ID frame test items (specific names) */
    FUZI_Q_ITEM("new_cid_retire_prior_to_seq_num_mismatch", test_frame_new_cid_retire_prior_to_seq_num_mismatch),
    FUZI_Q_ITEM("new_cid_invalid_length", test_frame_new_cid_invalid_length),
    FUZI_Q_ITEM("new_cid_length_too_long_for_rfc", test_frame_new_cid_length_too_long_for_rfc),
    /* User added Varint encoding frame test items */
    FUZI_Q_ITEM("max_streams_non_minimal_varint", test_frame_max_streams_non_minimal_varint),
    FUZI_Q_ITEM("crypto_offset_non_minimal_large_varint", test_frame_crypto_offset_non_minimal_large_varint),

    /* New test frames based on RFC 9000 review */
    FUZI_Q_ITEM("stream_off_len_empty_fin", test_frame_stream_off_len_empty_fin),
    FUZI_Q_ITEM("ack_many_small_ranges", test_frame_ack_many_small_ranges),
    FUZI_Q_ITEM("new_cid_seq_much_lower", test_frame_new_cid_seq_much_lower),
    FUZI_Q_ITEM("padding_mixed_payload", test_frame_padding_mixed_payload),
    FUZI_Q_ITEM("max_streams_uni_at_limit", test_frame_max_streams_uni_at_limit),

    /* Comprehensive Fuzzing Pass 1 Test Cases */
    /* ACK frames (16 cases) */
    FUZI_Q_ITEM("test_ack_delay_zero", test_ack_delay_zero),
    FUZI_Q_ITEM("test_ack_delay_effective_max_tp_val", test_ack_delay_effective_max_tp_val),
    FUZI_Q_ITEM("test_ack_delay_max_varint_val", test_ack_delay_max_varint_val),
    FUZI_Q_ITEM("test_ack_range_count_zero", test_ack_range_count_zero),
    FUZI_Q_ITEM("test_ack_range_count_one", test_ack_range_count_one),
    FUZI_Q_ITEM("test_ack_range_count_many", test_ack_range_count_many),
    FUZI_Q_ITEM("test_ack_first_range_zero", test_ack_first_range_zero),
    FUZI_Q_ITEM("test_ack_first_range_causes_negative_smallest", test_ack_first_range_causes_negative_smallest),
    FUZI_Q_ITEM("test_ack_first_range_covers_zero", test_ack_first_range_covers_zero),
    FUZI_Q_ITEM("test_ack_gap_zero_len_zero", test_ack_gap_zero_len_zero),
    FUZI_Q_ITEM("test_ack_gap_causes_negative_next_largest", test_ack_gap_causes_negative_next_largest),
    FUZI_Q_ITEM("test_ack_range_len_large", test_ack_range_len_large),
    FUZI_Q_ITEM("test_ack_ecn_all_zero", test_ack_ecn_all_zero),
    FUZI_Q_ITEM("test_ack_ecn_one_each", test_ack_ecn_one_each),
    FUZI_Q_ITEM("test_ack_ecn_large_counts", test_ack_ecn_large_counts),
    FUZI_Q_ITEM("test_ack_ecn_sum_exceeds_largest_acked", test_ack_ecn_sum_exceeds_largest_acked),
    /* STREAM frames (17 cases) */
    FUZI_Q_ITEM("test_stream_0x08_off0_len0_fin0", test_stream_0x08_off0_len0_fin0),
    FUZI_Q_ITEM("test_stream_0x09_off0_len0_fin1", test_stream_0x09_off0_len0_fin1),
    FUZI_Q_ITEM("test_stream_0x0A_off0_len1_fin0", test_stream_0x0A_off0_len1_fin0),
    FUZI_Q_ITEM("test_stream_0x0B_off0_len1_fin1", test_stream_0x0B_off0_len1_fin1),
    FUZI_Q_ITEM("test_stream_0x0C_off1_len0_fin0", test_stream_0x0C_off1_len0_fin0),
    FUZI_Q_ITEM("test_stream_0x0D_off1_len0_fin1", test_stream_0x0D_off1_len0_fin1),
    FUZI_Q_ITEM("test_stream_0x0E_off1_len1_fin0", test_stream_0x0E_off1_len1_fin0),
    FUZI_Q_ITEM("test_stream_0x0F_off1_len1_fin1", test_stream_0x0F_off1_len1_fin1),
    FUZI_Q_ITEM("test_stream_0x0F_id_zero", test_stream_0x0F_id_zero),
    FUZI_Q_ITEM("test_stream_0x0F_id_large", test_stream_0x0F_id_large),
    FUZI_Q_ITEM("test_stream_0x0F_id_max_62bit", test_stream_0x0F_id_max_62bit),
    FUZI_Q_ITEM("test_stream_0x0F_off_zero", test_stream_0x0F_off_zero),
    FUZI_Q_ITEM("test_stream_0x0F_off_max_62bit", test_stream_0x0F_off_max_62bit),
    FUZI_Q_ITEM("test_stream_0x0F_off_plus_len_exceeds_max", test_stream_0x0F_off_plus_len_exceeds_max),
    FUZI_Q_ITEM("test_stream_0x0F_len_zero", test_stream_0x0F_len_zero),
    FUZI_Q_ITEM("test_stream_0x0F_len_one", test_stream_0x0F_len_one),
    FUZI_Q_ITEM("test_stream_0x0F_len_exceed_total_with_offset", test_stream_0x0F_len_exceed_total_with_offset),
    /* RESET_STREAM frames (11 cases) */
    FUZI_Q_ITEM("test_reset_stream_base", test_reset_stream_base),
    FUZI_Q_ITEM("test_reset_stream_id_zero", test_reset_stream_id_zero),
    FUZI_Q_ITEM("test_reset_stream_id_large", test_reset_stream_id_large),
    FUZI_Q_ITEM("test_reset_stream_id_max_62bit", test_reset_stream_id_max_62bit),
    FUZI_Q_ITEM("test_reset_stream_err_zero", test_reset_stream_err_zero),
    FUZI_Q_ITEM("test_reset_stream_err_transport_range_like", test_reset_stream_err_transport_range_like),
    FUZI_Q_ITEM("test_reset_stream_err_max_62bit", test_reset_stream_err_max_62bit),
    FUZI_Q_ITEM("test_reset_stream_final_size_zero", test_reset_stream_final_size_zero),
    FUZI_Q_ITEM("test_reset_stream_final_size_one", test_reset_stream_final_size_one),
    FUZI_Q_ITEM("test_reset_stream_final_size_scenario_small", test_reset_stream_final_size_scenario_small),
    FUZI_Q_ITEM("test_reset_stream_final_size_max_62bit", test_reset_stream_final_size_max_62bit),
    /* STOP_SENDING frames (9 cases) */
    FUZI_Q_ITEM("test_stop_sending_base", test_stop_sending_base),
    FUZI_Q_ITEM("test_stop_sending_id_zero", test_stop_sending_id_zero),
    FUZI_Q_ITEM("test_stop_sending_id_large", test_stop_sending_id_large),
    FUZI_Q_ITEM("test_stop_sending_id_max_62bit", test_stop_sending_id_max_62bit),
    FUZI_Q_ITEM("test_stop_sending_id_recv_only_scenario", test_stop_sending_id_recv_only_scenario),
    FUZI_Q_ITEM("test_stop_sending_id_uncreated_sender_scenario", test_stop_sending_id_uncreated_sender_scenario),
    FUZI_Q_ITEM("test_stop_sending_err_zero", test_stop_sending_err_zero),
    FUZI_Q_ITEM("test_stop_sending_err_transport_range_like", test_stop_sending_err_transport_range_like),
    FUZI_Q_ITEM("test_stop_sending_err_max_62bit", test_stop_sending_err_max_62bit),
    /* Non-Canonical Variable-Length Integers */
    FUZI_Q_ITEM("stream_long_varint_stream_id_2byte", test_frame_stream_long_varint_stream_id_2byte),
    FUZI_Q_ITEM("stream_long_varint_stream_id_4byte", test_frame_stream_long_varint_stream_id_4byte),
    FUZI_Q_ITEM("stream_long_varint_offset_2byte", test_frame_stream_long_varint_offset_2byte),
    FUZI_Q_ITEM("stream_long_varint_offset_4byte", test_frame_stream_long_varint_offset_4byte),
    FUZI_Q_ITEM("stream_long_varint_length_2byte", test_frame_stream_long_varint_length_2byte),
    FUZI_Q_ITEM("stream_long_varint_length_4byte", test_frame_stream_long_varint_length_4byte),
    FUZI_Q_ITEM("max_data_long_varint_2byte", test_frame_max_data_long_varint_2byte),
    FUZI_Q_ITEM("max_data_long_varint_4byte", test_frame_max_data_long_varint_4byte),
    FUZI_Q_ITEM("ack_long_varint_largest_acked_2byte", test_frame_ack_long_varint_largest_acked_2byte),
    FUZI_Q_ITEM("ack_long_varint_largest_acked_4byte", test_frame_ack_long_varint_largest_acked_4byte),
    FUZI_Q_ITEM("crypto_long_varint_offset_2byte", test_frame_crypto_long_varint_offset_2byte),
    FUZI_Q_ITEM("crypto_long_varint_offset_4byte", test_frame_crypto_long_varint_offset_4byte),
    /* Aggressive Padding / PMTU Probing Mimics */
    FUZI_Q_ITEM("ping_padded_to_1200", test_frame_ping_padded_to_1200),
    FUZI_Q_ITEM("ping_padded_to_1500", test_frame_ping_padded_to_1500),
    /* ACK Frame Stress Tests */
    FUZI_Q_ITEM("ack_very_many_small_ranges", test_frame_ack_very_many_small_ranges),
    FUZI_Q_ITEM("ack_alternating_large_small_gaps", test_frame_ack_alternating_large_small_gaps),
    /* Unusual but Valid Header Flags/Values (Frames) */
    FUZI_Q_ITEM("stream_id_almost_max", test_frame_stream_id_almost_max),
    FUZI_Q_ITEM("stream_offset_almost_max", test_frame_stream_offset_almost_max),
    /* Additional STREAM Frame Variants */
    FUZI_Q_ITEM("stream_off_len_fin_empty", test_frame_stream_off_len_fin_empty),
    FUZI_Q_ITEM("stream_off_no_len_fin", test_frame_stream_off_no_len_fin),
    FUZI_Q_ITEM("stream_no_off_len_fin_empty", test_frame_stream_no_off_len_fin_empty),
    FUZI_Q_ITEM("stream_just_fin_at_zero", test_frame_stream_just_fin_at_zero),
    /* Zero-Length Data Frames with Max Varint Encoding for Fields */
    FUZI_Q_ITEM("data_blocked_max_varint_offset", test_frame_data_blocked_max_varint_offset),
    FUZI_Q_ITEM("stream_data_blocked_max_varint_fields", test_frame_stream_data_blocked_max_varint_fields),
    FUZI_Q_ITEM("streams_blocked_bidi_max_varint_limit", test_frame_streams_blocked_bidi_max_varint_limit),
    FUZI_Q_ITEM("streams_blocked_uni_max_varint_limit", test_frame_streams_blocked_uni_max_varint_limit),
    /* CRYPTO Frame Edge Cases */
    FUZI_Q_ITEM("crypto_zero_len_large_offset", test_frame_crypto_zero_len_large_offset),
    /* PATH_CHALLENGE / PATH_RESPONSE Variants */
    FUZI_Q_ITEM("path_challenge_alt_pattern", test_frame_path_challenge_alt_pattern),
    FUZI_Q_ITEM("path_response_alt_pattern", test_frame_path_response_alt_pattern),
    /* NEW_TOKEN Frame Variants */
    FUZI_Q_ITEM("new_token_max_plausible_len", test_frame_new_token_max_plausible_len),
    FUZI_Q_ITEM("new_token_min_len", test_frame_new_token_min_len),
    /* CONNECTION_CLOSE Frame Variants */
    FUZI_Q_ITEM("connection_close_max_reason_len", test_frame_connection_close_max_reason_len),
    FUZI_Q_ITEM("connection_close_app_max_reason_len", test_frame_connection_close_app_max_reason_len),
    /* RETIRE_CONNECTION_ID Variants */
    FUZI_Q_ITEM("retire_cid_high_seq", test_frame_retire_cid_high_seq),
    /* MAX_STREAMS Variants (Absolute Max) */
    FUZI_Q_ITEM("max_streams_bidi_abs_max", test_frame_max_streams_bidi_abs_max),
    FUZI_Q_ITEM("max_streams_uni_abs_max", test_frame_max_streams_uni_abs_max),
    // Added new test cases
    FUZI_Q_ITEM("new_token_empty_token", test_frame_new_token_empty_token),
    FUZI_Q_ITEM("stream_type_long_encoding", test_frame_stream_type_long_encoding),
    FUZI_Q_ITEM("ack_type_long_encoding", test_frame_ack_type_long_encoding),
    FUZI_Q_ITEM("reset_stream_type_long_encoding", test_frame_reset_stream_type_long_encoding),
    FUZI_Q_ITEM("max_streams_bidi_just_over_limit", test_frame_max_streams_bidi_just_over_limit),
    FUZI_Q_ITEM("max_streams_uni_just_over_limit", test_frame_max_streams_uni_just_over_limit),
    FUZI_Q_ITEM("client_sends_stop_sending_for_server_uni_stream", test_client_sends_stop_sending_for_server_uni_stream),
    FUZI_Q_ITEM("server_sends_stop_sending_for_client_uni_stream", test_server_sends_stop_sending_for_client_uni_stream),
    FUZI_Q_ITEM("client_sends_max_stream_data_for_client_uni_stream", test_client_sends_max_stream_data_for_client_uni_stream),
    /* Newly added medium priority test cases */
    FUZI_Q_ITEM("ack_cross_pns_low_pkns", test_frame_ack_cross_pns_low_pkns),
    FUZI_Q_ITEM("new_cid_to_zero_len_peer", test_frame_new_cid_to_zero_len_peer),
    FUZI_Q_ITEM("retire_cid_to_zero_len_provider", test_frame_retire_cid_to_zero_len_provider)
};

size_t nb_fuzi_q_frame_list = sizeof(fuzi_q_frame_list) / sizeof(fuzi_q_frames_t);
