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

static uint8_t test_frame_type_padding_zero_byte[] = { 0x00 };

static uint8_t test_frame_type_padding_large[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 10 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 20 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 30 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 40 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 50 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 60 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 70 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 80 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 90 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 100 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 110 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 120 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 130 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 140 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 150 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 160 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 170 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 180 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 190 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  /* 200 */
};

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

static uint8_t test_frame_reset_stream_error_code_max[] = {
    picoquic_frame_type_reset_stream,
    0x01, /* Stream ID */
    0xBF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* Error Code: (1ULL << 62) - 1 */
    0x00 /* Final Size */
};

static uint8_t test_frame_reset_stream_final_size_max_new[] = {
    picoquic_frame_type_reset_stream,
    0x01, /* Stream ID */
    0x00, /* Error Code */
    0xBF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF /* Final Size: (1ULL << 62) - 1 */
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

static uint8_t test_frame_connection_close_frame_encoding_error[] = {
    picoquic_frame_type_connection_close,       /* 0x1c */
    0x07,                                       /* FRAME_ENCODING_ERROR */
    0x00,                                       /* Offending Frame Type (e.g., PADDING) */
    0x00                                        /* Reason Phrase Length 0 */
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

static uint8_t test_frame_max_data_small_value[] = {
    picoquic_frame_type_max_data, 0x44, 0x00 /* 1024 */
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

/* ACK frame with invalid Gap (10 - 20 - 2 = -12) */
static uint8_t test_frame_ack_invalid_gap_1[] = {
    picoquic_frame_type_ack, /* 0x02 */
    0x0A,       /* Largest Acknowledged: 10 */
    0x00,       /* ACK Delay: 0 */
    0x02,       /* ACK Range Count: 2 */
    0x00,       /* First ACK Range: 0 (acks packet 10) */
    0x14,       /* Gap: 20 */
    0x00        /* ACK Range Length for 2nd range: 0 */
};
static uint8_t ack_invalid_gap_1_specific[] = {
    picoquic_frame_type_ack, /* 0x02 */
    0x14,       /* Largest Acknowledged: 20 */
    0x00,       /* ACK Delay: 0 */
    0x02,       /* ACK Range Count: 2 */
    0x00,       /* First ACK Range: 0 (acks packet 20) Add commentMore actions */
    0x1E,       /* Gap: 30 */
    0x00        /* ACK Range Length for 2nd range: 0 */
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
/* Part 1: Base test cases - Cloud Native Security Attacks */
static uint8_t test_frame_serverless_cold_start[] = { 0x08, 0x2A, 'c', 'o', 'l', 'd', '_', 's', 't', 'a', 'r', 't' };
static uint8_t test_frame_serverless_injection[] = { 0x08, 0x2B, 's', 'e', 'r', 'v', 'e', 'r', 'l', 'e', 's', 's', '_', 'i', 'n', 'j' };
static uint8_t test_frame_api_gateway_bypass[] = { 0x08, 0x2C, 'a', 'p', 'i', '_', 'g', 'w', '_', 'b', 'y', 'p', 'a', 's', 's' };
static uint8_t test_frame_service_mesh_attack[] = { 0x08, 0x2D, 's', 'e', 'r', 'v', 'i', 'c', 'e', '_', 'm', 'e', 's', 'h' };

/* === ULTRA ADVANCED ATTACK VECTORS === */

/* Advanced Cryptographic Attacks */
static uint8_t test_frame_lattice_attack[] = { 0x08, 0x2E, 'l', 'a', 't', 't', 'i', 'c', 'e', '_', 'a', 't', 't', 'a', 'c', 'k' };
static uint8_t test_frame_bleichenbacher_attack[] = { 0x08, 0x2F, 'b', 'l', 'e', 'i', 'c', 'h', 'e', 'n', 'b', 'a', 'c', 'h', 'e', 'r' };
static uint8_t test_frame_invalid_curve_attack[] = { 0x08, 0x30, 'i', 'n', 'v', 'a', 'l', 'i', 'd', '_', 'c', 'u', 'r', 'v', 'e' };
static uint8_t test_frame_twist_attack[] = { 0x08, 0x31, 't', 'w', 'i', 's', 't', '_', 'a', 't', 't', 'a', 'c', 'k' };
static uint8_t test_frame_fault_injection[] = { 0x08, 0x32, 'f', 'a', 'u', 'l', 't', '_', 'i', 'n', 'j', 'e', 'c', 't', 'i', 'o', 'n' };

/* Zero-Day Exploitation Patterns */
static uint8_t test_frame_cve_2024_pattern[] = { 0x08, 0x33, 'c', 'v', 'e', '_', '2', '0', '2', '4', '_', 'p', 'a', 't', 't', 'e', 'r', 'n' };
static uint8_t test_frame_nday_exploitation[] = { 0x08, 0x34, 'n', 'd', 'a', 'y', '_', 'e', 'x', 'p', 'l', 'o', 'i', 't' };
static uint8_t test_frame_vulnerability_chaining[] = { 0x08, 0x35, 'v', 'u', 'l', 'n', '_', 'c', 'h', 'a', 'i', 'n' };
static uint8_t test_frame_exploit_mitigation_bypass[] = { 0x08, 0x36, 'm', 'i', 't', 'i', 'g', 'a', 't', 'i', 'o', 'n', '_', 'b', 'p' };

/* Advanced Network Attacks */
static uint8_t test_frame_bgp_hijacking[] = { 0x08, 0x37, 'b', 'g', 'p', '_', 'h', 'i', 'j', 'a', 'c', 'k' };
static uint8_t test_frame_dns_cache_poisoning[] = { 0x08, 0x38, 'd', 'n', 's', '_', 'p', 'o', 'i', 's', 'o', 'n' };
static uint8_t test_frame_arp_spoofing[] = { 0x08, 0x39, 'a', 'r', 'p', '_', 's', 'p', 'o', 'o', 'f' };
static uint8_t test_frame_dhcp_starvation[] = { 0x08, 0x3A, 'd', 'h', 'c', 'p', '_', 's', 't', 'a', 'r', 'v', 'e' };
static uint8_t test_frame_icmp_redirect[] = { 0x08, 0x3B, 'i', 'c', 'm', 'p', '_', 'r', 'e', 'd', 'i', 'r', 'e', 'c', 't' };

/* Database-Specific Attacks */
static uint8_t test_frame_oracle_injection[] = { 0x08, 0x3C, 'o', 'r', 'a', 'c', 'l', 'e', '_', 'i', 'n', 'j' };
static uint8_t test_frame_mssql_injection[] = { 0x08, 0x3D, 'm', 's', 's', 'q', 'l', '_', 'i', 'n', 'j' };
static uint8_t test_frame_postgresql_injection[] = { 0x08, 0x3E, 'p', 'o', 's', 't', 'g', 'r', 'e', 's', 'q', 'l' };
static uint8_t test_frame_nosql_redis_injection[] = { 0x08, 0x03, 'F', 'L', 'U', 'S', 'H', 'A', 'L', 'L', 0x0D, 0x0A };
static uint8_t test_frame_elasticsearch_injection[] = { 0x08, 0x3F, 'e', 'l', 'a', 's', 't', 'i', 'c', '_', 'i', 'n', 'j' };
static uint8_t test_frame_cassandra_injection[] = { 0x08, 0x40, 'c', 'a', 's', 's', 'a', 'n', 'd', 'r', 'a', '_', 'i', 'n', 'j' };

/* Basic SQL Injection Patterns */
static uint8_t test_frame_sql_injection_basic[] = { 0x08, 0x50, 'S', 'Q', 'L', '_', 'B', 'A', 'S', 'I', 'C' };
static uint8_t test_frame_sql_union_attack[] = { 0x08, 0x51, 'S', 'Q', 'L', '_', 'U', 'N', 'I', 'O', 'N' };
static uint8_t test_frame_sql_blind_injection[] = { 0x08, 0x52, 'S', 'Q', 'L', '_', 'B', 'L', 'I', 'N', 'D' };

/* XSS Attack Payloads */
static uint8_t test_frame_xss_script_tag[] = { 0x08, 0x53, 'X', 'S', 'S', '_', 'S', 'C', 'R', 'I', 'P', 'T' };
static uint8_t test_frame_xss_img_onerror[] = { 0x08, 0x54, 'X', 'S', 'S', '_', 'I', 'M', 'G', '_', 'E', 'R', 'R' };

/* Command Injection Patterns */
static uint8_t test_frame_cmd_injection_pipe[] = { 0x08, 0x55, 'C', 'M', 'D', '_', 'P', 'I', 'P', 'E' };
static uint8_t test_frame_cmd_injection_backtick[] = { 0x08, 0x56, 'C', 'M', 'D', '_', 'B', 'T', 'I', 'C', 'K' };

/* Path Traversal Attacks */
static uint8_t test_frame_path_traversal_basic[] = { 0x08, 0x57, 'P', 'A', 'T', 'H', '_', 'T', 'R', 'A', 'V' };
static uint8_t test_frame_path_traversal_encoded[] = { 0x08, 0x58, 'P', 'A', 'T', 'H', '_', 'E', 'N', 'C' };


/* SSRF Attacks */
static uint8_t test_frame_ssrf_localhost[] = { 0x08, 0x5A, 'h', 't', 't', 'p', ':', '/', '/', '1', '2', '7', '.', '0', '.', '0', '.', '1', ':', '2', '2' };
static uint8_t test_frame_ssrf_metadata[] = { 0x08, 0x5B, 'S', 'S', 'R', 'F', '_', 'M', 'E', 'T', 'A' };
static uint8_t test_frame_csrf_attack[] = { 0x08, 0x42, 'c', 's', 'r', 'f', '_', 'a', 't', 't', 'a', 'c', 'k' };
static uint8_t test_frame_clickjacking[] = { 0x08, 0x43, 'c', 'l', 'i', 'c', 'k', 'j', 'a', 'c', 'k', 'i', 'n', 'g' };
static uint8_t test_frame_dom_clobbering[] = { 0x08, 0x44, 'd', 'o', 'm', '_', 'c', 'l', 'o', 'b', 'b', 'e', 'r' };
static uint8_t test_frame_prototype_pollution[] = { 0x08, 0x45, 'p', 'r', 'o', 't', 'o', 't', 'y', 'p', 'e', '_', 'p', 'o', 'l', 'l' };

/* Mobile Security Attacks */
static uint8_t test_frame_android_intent_hijack[] = { 0x08, 0x46, 'a', 'n', 'd', 'r', 'o', 'i', 'd', '_', 'i', 'n', 't', 'e', 'n', 't' };
static uint8_t test_frame_ios_url_scheme[] = { 0x08, 0x47, 'i', 'o', 's', '_', 'u', 'r', 'l', '_', 's', 'c', 'h', 'e', 'm', 'e' };
static uint8_t test_frame_mobile_ssl_pinning_bypass[] = { 0x08, 0x48, 's', 's', 'l', '_', 'p', 'i', 'n', '_', 'b', 'y', 'p', 'a', 's', 's' };
static uint8_t test_frame_mobile_root_detection_bypass[] = { 0x08, 0x49, 'r', 'o', 'o', 't', '_', 'd', 'e', 't', '_', 'b', 'p' };

/* Industrial Control System Attacks */
static uint8_t test_frame_modbus_attack[] = { 0x08, 0x4A, 'm', 'o', 'd', 'b', 'u', 's', '_', 'a', 't', 't', 'a', 'c', 'k' };
static uint8_t test_frame_scada_attack[] = { 0x08, 0x4B, 's', 'c', 'a', 'd', 'a', '_', 'a', 't', 't', 'a', 'c', 'k' };
static uint8_t test_frame_dnp3_attack[] = { 0x08, 0x4C, 'd', 'n', 'p', '3', '_', 'a', 't', 't', 'a', 'c', 'k' };
static uint8_t test_frame_iec104_attack[] = { 0x08, 0x4D, 'i', 'e', 'c', '1', '0', '4', '_', 'a', 't', 't', 'a', 'c', 'k' };

/* Advanced Memory Corruption */
static uint8_t test_frame_vtable_hijacking[] = { 0x08, 0x4E, 'v', 't', 'a', 'b', 'l', 'e', '_', 'h', 'i', 'j', 'a', 'c', 'k' };
static uint8_t test_frame_coop_attack[] = { 0x08, 0x4F, 'c', 'o', 'o', 'p', '_', 'a', 't', 't', 'a', 'c', 'k' };
static uint8_t test_frame_brop_attack[] = { 0x08, 0x50, 'b', 'r', 'o', 'p', '_', 'a', 't', 't', 'a', 'c', 'k' };
static uint8_t test_frame_type_confusion[] = { 0x08, 0x51, 't', 'y', 'p', 'e', '_', 'c', 'o', 'n', 'f', 'u', 's', 'i', 'o', 'n' };

/* Advanced Persistence Techniques */
static uint8_t test_frame_dll_hijacking[] = { 0x08, 0x52, 'd', 'l', 'l', '_', 'h', 'i', 'j', 'a', 'c', 'k' };
static uint8_t test_frame_com_hijacking[] = { 0x08, 0x53, 'c', 'o', 'm', '_', 'h', 'i', 'j', 'a', 'c', 'k' };
static uint8_t test_frame_registry_persistence[] = { 0x08, 0x54, 'r', 'e', 'g', '_', 'p', 'e', 'r', 's', 'i', 's', 't' };
static uint8_t test_frame_scheduled_task_abuse[] = { 0x08, 0x55, 's', 'c', 'h', 'e', 'd', '_', 't', 'a', 's', 'k' };

/* Advanced Evasion Techniques */
static uint8_t test_frame_sandbox_evasion[] = { 0x08, 0x56, 's', 'a', 'n', 'd', 'b', 'o', 'x', '_', 'e', 'v', 'a', 's', 'i', 'o', 'n' };
static uint8_t test_frame_av_evasion[] = { 0x08, 0x57, 'a', 'v', '_', 'e', 'v', 'a', 's', 'i', 'o', 'n' };
static uint8_t test_frame_edr_evasion[] = { 0x08, 0x58, 'e', 'd', 'r', '_', 'e', 'v', 'a', 's', 'i', 'o', 'n' };
static uint8_t test_frame_behavioral_evasion[] = { 0x08, 0x59, 'b', 'e', 'h', 'a', 'v', '_', 'e', 'v', 'a', 's', 'i', 'o', 'n' };

/* Quantum Computing Attacks */
static uint8_t test_frame_shor_algorithm[] = { 0x08, 0x5A, 's', 'h', 'o', 'r', '_', 'a', 'l', 'g', 'o', 'r', 'i', 't', 'h', 'm' };
static uint8_t test_frame_grover_algorithm[] = { 0x08, 0x5B, 'g', 'r', 'o', 'v', 'e', 'r', '_', 'a', 'l', 'g', 'o' };
static uint8_t test_frame_quantum_key_recovery[] = { 0x08, 0x5C, 'q', 'u', 'a', 'n', 't', 'u', 'm', '_', 'k', 'e', 'y' };
static uint8_t test_frame_post_quantum_downgrade[] = { 0x08, 0x5D, 'p', 'q', '_', 'd', 'o', 'w', 'n', 'g', 'r', 'a', 'd', 'e' };

/* === APEX TIER ATTACK VECTORS === */

/* Nation-State APT Techniques */
static uint8_t test_frame_apt_living_off_land[] = { 0x08, 0x5E, 'a', 'p', 't', '_', 'l', 'o', 'l', '_', 'a', 't', 't', 'a', 'c', 'k' };
static uint8_t test_frame_apt_supply_chain[] = { 0x08, 0x5F, 'a', 'p', 't', '_', 's', 'u', 'p', 'p', 'l', 'y', '_', 'c', 'h', 'a', 'i', 'n' };
static uint8_t test_frame_apt_zero_click[] = { 0x08, 0x60, 'a', 'p', 't', '_', 'z', 'e', 'r', 'o', '_', 'c', 'l', 'i', 'c', 'k' };
static uint8_t test_frame_apt_watering_hole[] = { 0x08, 0x61, 'a', 'p', 't', '_', 'w', 'a', 't', 'e', 'r', 'i', 'n', 'g', '_', 'h', 'o', 'l', 'e' };

/* Advanced Ransomware Techniques */
static uint8_t test_frame_ransomware_double_extortion[] = { 0x08, 0x62, 'r', 'a', 'n', 's', 'o', 'm', '_', 'd', 'o', 'u', 'b', 'l', 'e' };
static uint8_t test_frame_ransomware_triple_extortion[] = { 0x08, 0x63, 'r', 'a', 'n', 's', 'o', 'm', '_', 't', 'r', 'i', 'p', 'l', 'e' };
static uint8_t test_frame_ransomware_as_a_service[] = { 0x08, 0x64, 'r', 'a', 'n', 's', 'o', 'm', '_', 'a', 'a', 's' };
static uint8_t test_frame_ransomware_vm_escape[] = { 0x08, 0x65, 'r', 'a', 'n', 's', 'o', 'm', '_', 'v', 'm', '_', 'e', 's', 'c' };

/* AI-Powered Cyber Attacks */
static uint8_t test_frame_ai_deepfake_voice[] = { 0x08, 0x66, 'a', 'i', '_', 'd', 'e', 'e', 'p', 'f', 'a', 'k', 'e', '_', 'v', 'o', 'i', 'c', 'e' };
static uint8_t test_frame_ai_deepfake_video[] = { 0x08, 0x67, 'a', 'i', '_', 'd', 'e', 'e', 'p', 'f', 'a', 'k', 'e', '_', 'v', 'i', 'd', 'e', 'o' };
static uint8_t test_frame_ai_automated_spearphish[] = { 0x08, 0x68, 'a', 'i', '_', 's', 'p', 'e', 'a', 'r', 'p', 'h', 'i', 's', 'h' };
static uint8_t test_frame_ai_vulnerability_discovery[] = { 0x08, 0x69, 'a', 'i', '_', 'v', 'u', 'l', 'n', '_', 'd', 'i', 's', 'c', 'o', 'v', 'e', 'r', 'y' };

/* Advanced Satellite/Space Attacks */
static uint8_t test_frame_satellite_jamming[] = { 0x08, 0x6A, 's', 'a', 't', '_', 'j', 'a', 'm', 'm', 'i', 'n', 'g' };
static uint8_t test_frame_satellite_spoofing[] = { 0x08, 0x6B, 's', 'a', 't', '_', 's', 'p', 'o', 'o', 'f', 'i', 'n', 'g' };
static uint8_t test_frame_gps_spoofing[] = { 0x08, 0x6C, 'g', 'p', 's', '_', 's', 'p', 'o', 'o', 'f', 'i', 'n', 'g' };
static uint8_t test_frame_starlink_attack[] = { 0x08, 0x6D, 's', 't', 'a', 'r', 'l', 'i', 'n', 'k', '_', 'a', 't', 't', 'a', 'c', 'k' };

/* Biometric Security Attacks */
static uint8_t test_frame_fingerprint_spoofing[] = { 0x08, 0x6E, 'f', 'i', 'n', 'g', 'e', 'r', 'p', 'r', 'i', 'n', 't', '_', 's', 'p', 'o', 'o', 'f' };
static uint8_t test_frame_face_recognition_bypass[] = { 0x08, 0x6F, 'f', 'a', 'c', 'e', '_', 'r', 'e', 'c', '_', 'b', 'y', 'p', 'a', 's', 's' };
static uint8_t test_frame_iris_scan_bypass[] = { 0x08, 0x70, 'i', 'r', 'i', 's', '_', 's', 'c', 'a', 'n', '_', 'b', 'y', 'p', 'a', 's', 's' };
static uint8_t test_frame_voice_recognition_bypass[] = { 0x08, 0x71, 'v', 'o', 'i', 'c', 'e', '_', 'r', 'e', 'c', '_', 'b', 'y', 'p', 'a', 's', 's' };

/* Advanced Social Engineering */
static uint8_t test_frame_vishing_attack[] = { 0x08, 0x72, 'v', 'i', 's', 'h', 'i', 'n', 'g', '_', 'a', 't', 't', 'a', 'c', 'k' };
static uint8_t test_frame_smishing_attack[] = { 0x08, 0x73, 's', 'm', 'i', 's', 'h', 'i', 'n', 'g', '_', 'a', 't', 't', 'a', 'c', 'k' };
static uint8_t test_frame_pretexting_attack[] = { 0x08, 0x74, 'p', 'r', 'e', 't', 'e', 'x', 't', 'i', 'n', 'g', '_', 'a', 't', 't', 'a', 'c', 'k' };
static uint8_t test_frame_business_email_compromise[] = { 0x08, 0x75, 'b', 'e', 'c', '_', 'a', 't', 't', 'a', 'c', 'k' };

/* Critical Infrastructure Attacks */
static uint8_t test_frame_power_grid_attack[] = { 0x08, 0x76, 'p', 'o', 'w', 'e', 'r', '_', 'g', 'r', 'i', 'd', '_', 'a', 't', 't', 'a', 'c', 'k' };
static uint8_t test_frame_water_system_attack[] = { 0x08, 0x77, 'w', 'a', 't', 'e', 'r', '_', 's', 'y', 's', '_', 'a', 't', 't', 'a', 'c', 'k' };
static uint8_t test_frame_transportation_attack[] = { 0x08, 0x78, 't', 'r', 'a', 'n', 's', 'p', 'o', 'r', 't', '_', 'a', 't', 't', 'a', 'c', 'k' };
static uint8_t test_frame_healthcare_attack[] = { 0x08, 0x79, 'h', 'e', 'a', 'l', 't', 'h', 'c', 'a', 'r', 'e', '_', 'a', 't', 't', 'a', 'c', 'k' };

/* Emerging Technology Attacks */
static uint8_t test_frame_metaverse_attack[] = { 0x08, 0x7A, 'm', 'e', 't', 'a', 'v', 'e', 'r', 's', 'e', '_', 'a', 't', 't', 'a', 'c', 'k' };
static uint8_t test_frame_nft_smart_contract_exploit[] = { 0x08, 0x7B, 'n', 'f', 't', '_', 's', 'c', '_', 'e', 'x', 'p', 'l', 'o', 'i', 't' };
static uint8_t test_frame_autonomous_vehicle_hack[] = { 0x08, 0x7C, 'a', 'v', '_', 'h', 'a', 'c', 'k' };
static uint8_t test_frame_drone_hijacking[] = { 0x08, 0x7D, 'd', 'r', 'o', 'n', 'e', '_', 'h', 'i', 'j', 'a', 'c', 'k' };

/* Advanced Steganography */
static uint8_t test_frame_image_steganography[] = { 0x08, 0x7E, 'i', 'm', 'a', 'g', 'e', '_', 's', 't', 'e', 'g', 'a', 'n', 'o' };
static uint8_t test_frame_audio_steganography[] = { 0x08, 0x7F, 'a', 'u', 'd', 'i', 'o', '_', 's', 't', 'e', 'g', 'a', 'n', 'o' };
static uint8_t test_frame_video_steganography[] = { 0x08, 0x80, 'v', 'i', 'd', 'e', 'o', '_', 's', 't', 'e', 'g', 'a', 'n', 'o' };
static uint8_t test_frame_network_steganography[] = { 0x08, 0x81, 'n', 'e', 't', 'w', 'o', 'r', 'k', '_', 's', 't', 'e', 'g', 'a', 'n', 'o' };

/* === MISSING ATTACK FRAME DEFINITIONS === */

/* Race Condition Triggers */
static uint8_t test_frame_race_condition_toctou[] = { 0x08, 0xE0, 'R', 'A', 'C', 'E', '_', 'T', 'O', 'C', 'T', 'O', 'U' };
static uint8_t test_frame_race_condition_double_fetch[] = { 0x08, 0xE1, 'R', 'A', 'C', 'E', '_', 'D', 'B', 'L', '_', 'F', 'E', 'T', 'C', 'H' };
static uint8_t test_frame_race_condition_atomic_violation[] = { 0x08, 0xE2, 'R', 'A', 'C', 'E', '_', 'A', 'T', 'O', 'M', 'I', 'C' };

/* Deserialization Attacks */
static uint8_t test_frame_deserial_java_commons[] = { 0x08, 0xE3, 'J', 'A', 'V', 'A', '_', 'C', 'O', 'M', 'M', 'O', 'N', 'S' };
static uint8_t test_frame_deserial_python_pickle[] = { 0x08, 0xE4, 'P', 'Y', '_', 'P', 'I', 'C', 'K', 'L', 'E' };
static uint8_t test_frame_deserial_php_unserialize[] = { 0x08, 0xE5, 'P', 'H', 'P', '_', 'U', 'N', 'S', 'E', 'R' };
static uint8_t test_frame_deserial_dotnet_binaryformatter[] = { 0x08, 0xE6, 'D', 'O', 'T', 'N', 'E', 'T', '_', 'B', 'I', 'N', 'F', 'M', 'T' };

/* Blockchain/DeFi Attacks */
static uint8_t test_frame_blockchain_reentrancy[] = { 0x08, 0xE7, 'B', 'L', 'O', 'C', 'K', '_', 'R', 'E', 'E', 'N', 'T' };
static uint8_t test_frame_blockchain_flashloan[] = { 0x08, 0xE8, 'B', 'L', 'O', 'C', 'K', '_', 'F', 'L', 'A', 'S', 'H' };
static uint8_t test_frame_blockchain_mev_sandwich[] = { 0x08, 0xE9, 'B', 'L', 'O', 'C', 'K', '_', 'M', 'E', 'V' };
static uint8_t test_frame_blockchain_oracle_manipulation[] = { 0x08, 0xEA, 'B', 'L', 'O', 'C', 'K', '_', 'O', 'R', 'A', 'C', 'L', 'E' };

/* AI/ML Model Attacks */
static uint8_t test_frame_ai_model_extraction[] = { 0x08, 0xEB, 'A', 'I', '_', 'M', 'O', 'D', 'E', 'L', '_', 'E', 'X', 'T' };
static uint8_t test_frame_ai_membership_inference[] = { 0x08, 0xEC, 'A', 'I', '_', 'M', 'E', 'M', 'B', 'E', 'R', '_', 'I', 'N', 'F' };
static uint8_t test_frame_ai_backdoor_trigger[] = { 0x08, 0xED, 'A', 'I', '_', 'B', 'A', 'C', 'K', 'D', 'O', 'O', 'R' };
static uint8_t test_frame_ai_prompt_injection[] = { 0x08, 0xEE, 'A', 'I', '_', 'P', 'R', 'O', 'M', 'P', 'T', '_', 'I', 'N', 'J' };

/* Supply Chain Attacks */
static uint8_t test_frame_supply_dependency_confusion[] = { 0x08, 0xEF, 'S', 'U', 'P', 'P', 'L', 'Y', '_', 'D', 'E', 'P', '_', 'C', 'O', 'N', 'F' };
static uint8_t test_frame_supply_typosquatting[] = { 0x08, 0xF0, 'S', 'U', 'P', 'P', 'L', 'Y', '_', 'T', 'Y', 'P', 'O' };
static uint8_t test_frame_supply_malicious_package[] = { 0x08, 0xF1, 'S', 'U', 'P', 'P', 'L', 'Y', '_', 'M', 'A', 'L', 'P', 'K', 'G' };
static uint8_t test_frame_supply_compromised_repo[] = { 0x08, 0xF2, 'S', 'U', 'P', 'P', 'L', 'Y', '_', 'C', 'O', 'M', 'P', '_', 'R', 'E', 'P', 'O' };

/* 5G/Edge Computing Attacks */
static uint8_t test_frame_5g_slice_isolation_bypass[] = { 0x08, 0xF3, '5', 'G', '_', 'S', 'L', 'I', 'C', 'E', '_', 'B', 'Y', 'P', 'A', 'S', 'S' };
static uint8_t test_frame_5g_compute_escape[] = { 0x08, 0xF4, '5', 'G', '_', 'C', 'O', 'M', 'P', 'U', 'T', 'E', '_', 'E', 'S', 'C' };
static uint8_t test_frame_5g_network_slicing_attack[] = { 0x08, 0xF5, '5', 'G', '_', 'N', 'E', 'T', '_', 'S', 'L', 'I', 'C', 'E' };
static uint8_t test_frame_edge_function_escape[] = { 0x08, 0xF6, 'E', 'D', 'G', 'E', '_', 'F', 'U', 'N', 'C', '_', 'E', 'S', 'C' };

/* Advanced Binary Exploitation */
static uint8_t test_frame_binary_rop_chain[] = { 0x08, 0xF7, 'B', 'I', 'N', '_', 'R', 'O', 'P', '_', 'C', 'H', 'A', 'I', 'N' };
static uint8_t test_frame_binary_jop_chain[] = { 0x08, 0xF8, 'B', 'I', 'N', '_', 'J', 'O', 'P', '_', 'C', 'H', 'A', 'I', 'N' };
static uint8_t test_frame_binary_stack_pivot[] = { 0x08, 0xF9, 'B', 'I', 'N', '_', 'S', 'T', 'A', 'C', 'K', '_', 'P', 'I', 'V' };
static uint8_t test_frame_binary_heap_spray[] = { 0x08, 0xFA, 'B', 'I', 'N', '_', 'H', 'E', 'A', 'P', '_', 'S', 'P', 'R', 'A', 'Y' };

/* Advanced Container/Orchestration Attacks */
static uint8_t test_frame_container_runtime_escape[] = { 0x08, 0xFB, 'C', 'O', 'N', 'T', '_', 'R', 'T', '_', 'E', 'S', 'C' };
static uint8_t test_frame_k8s_rbac_bypass[] = { 0x08, 0xFC, 'K', '8', 'S', '_', 'R', 'B', 'A', 'C', '_', 'B', 'Y', 'P' };
static uint8_t test_frame_k8s_admission_bypass[] = { 0x08, 0xFD, 'K', '8', 'S', '_', 'A', 'D', 'M', '_', 'B', 'Y', 'P' };
static uint8_t test_frame_k8s_pod_escape[] = { 0x08, 0xFE, 'K', '8', 'S', '_', 'P', 'O', 'D', '_', 'E', 'S', 'C' };

/* Advanced Firmware/Hardware Attacks */
static uint8_t test_frame_firmware_dump_attack[] = { 0x08, 0xFF, 'F', 'W', '_', 'D', 'U', 'M', 'P', '_', 'A', 'T', 'T', 'K' };
static uint8_t test_frame_uefi_bootkit[] = { 0x08, 0x80, 'U', 'E', 'F', 'I', '_', 'B', 'O', 'O', 'T', 'K', 'I', 'T' };
static uint8_t test_frame_smc_vulnerability[] = { 0x08, 0x81, 'S', 'M', 'C', '_', 'V', 'U', 'L', 'N' };
static uint8_t test_frame_tpm_bypass[] = { 0x08, 0x82, 'T', 'P', 'M', '_', 'B', 'Y', 'P', 'A', 'S', 'S' };

/* === NEXT-GENERATION ATTACK VECTORS === */

/* Additional missing definitions */
static uint8_t test_frame_xxe_attack[] = { 0x08, 0x70, 'X', 'X', 'E', '_', 'A', 'T', 'T', 'A', 'C', 'K' };

/* Advanced IoT Ecosystem Attacks */
static uint8_t test_frame_iot_mesh_takeover[] = { 0x08, 0x82, 'i', 'o', 't', '_', 'm', 'e', 's', 'h', '_', 't', 'a', 'k', 'e', 'o', 'v', 'e', 'r' };
static uint8_t test_frame_iot_swarm_botnet[] = { 0x08, 0x83, 'i', 'o', 't', '_', 's', 'w', 'a', 'r', 'm', '_', 'b', 'o', 't', 'n', 'e', 't' };
static uint8_t test_frame_iot_sensor_spoofing[] = { 0x08, 0x84, 'i', 'o', 't', '_', 's', 'e', 'n', 's', 'o', 'r', '_', 's', 'p', 'o', 'o', 'f' };
static uint8_t test_frame_iot_firmware_backdoor[] = { 0x08, 0x85, 'i', 'o', 't', '_', 'f', 'w', '_', 'b', 'a', 'c', 'k', 'd', 'o', 'o', 'r' };

/* Financial Technology Attacks */
static uint8_t test_frame_cbdc_attack[] = { 0x08, 0x8A, 'c', 'b', 'd', 'c', '_', 'a', 't', 't', 'a', 'c', 'k' };
static uint8_t test_frame_defi_liquidation[] = { 0x08, 0x8B, 'd', 'e', 'f', 'i', '_', 'l', 'i', 'q', 'u', 'i', 'd', 'a', 't', 'i', 'o', 'n' };
static uint8_t test_frame_payment_rail_hijack[] = { 0x08, 0x8C, 'p', 'a', 'y', 'm', 'e', 'n', 't', '_', 'r', 'a', 'i', 'l' };
static uint8_t test_frame_regulatory_arbitrage[] = { 0x08, 0x8D, 'r', 'e', 'g', '_', 'a', 'r', 'b', 'i', 't', 'r', 'a', 'g', 'e' };

/* Advanced Automotive Attacks */
static uint8_t test_frame_v2x_manipulation[] = { 0x08, 0x8E, 'v', '2', 'x', '_', 'm', 'a', 'n', 'i', 'p', 'u', 'l', 'a', 't', 'i', 'o', 'n' };
static uint8_t test_frame_can_bus_injection[] = { 0x08, 0x8F, 'c', 'a', 'n', '_', 'b', 'u', 's', '_', 'i', 'n', 'j', 'e', 'c', 't' };
static uint8_t test_frame_adas_sensor_attack[] = { 0x08, 0x90, 'a', 'd', 'a', 's', '_', 's', 'e', 'n', 's', 'o', 'r' };
static uint8_t test_frame_vehicle_swarm_attack[] = { 0x08, 0x91, 'v', 'e', 'h', 'i', 'c', 'l', 'e', '_', 's', 'w', 'a', 'r', 'm' };

/* Medical Device Security Attacks */
static uint8_t test_frame_pacemaker_attack[] = { 0x08, 0x92, 'p', 'a', 'c', 'e', 'm', 'a', 'k', 'e', 'r', '_', 'a', 't', 't', 'k' };
static uint8_t test_frame_insulin_pump_hijack[] = { 0x08, 0x93, 'i', 'n', 's', 'u', 'l', 'i', 'n', '_', 'p', 'u', 'm', 'p' };
static uint8_t test_frame_mri_manipulation[] = { 0x08, 0x94, 'm', 'r', 'i', '_', 'm', 'a', 'n', 'i', 'p', 'u', 'l', 'a', 't', 'i', 'o', 'n' };
static uint8_t test_frame_surgical_robot_hack[] = { 0x08, 0x95, 's', 'u', 'r', 'g', '_', 'r', 'o', 'b', 'o', 't' };

/* Gaming and Virtual World Attacks */
static uint8_t test_frame_game_engine_exploit[] = { 0x08, 0x96, 'g', 'a', 'm', 'e', '_', 'e', 'n', 'g', 'i', 'n', 'e' };
static uint8_t test_frame_virtual_economy_manipulation[] = { 0x08, 0x97, 'v', 'i', 'r', 't', '_', 'e', 'c', 'o', 'n', 'o', 'm', 'y' };
static uint8_t test_frame_esports_match_fixing[] = { 0x08, 0x98, 'e', 's', 'p', 'o', 'r', 't', 's', '_', 'f', 'i', 'x' };
static uint8_t test_frame_nft_gaming_exploit[] = { 0x08, 0x99, 'n', 'f', 't', '_', 'g', 'a', 'm', 'i', 'n', 'g' };

/* Augmented/Virtual Reality Attacks */
static uint8_t test_frame_ar_overlay_hijack[] = { 0x08, 0x9A, 'a', 'r', '_', 'o', 'v', 'e', 'r', 'l', 'a', 'y' };
static uint8_t test_frame_vr_presence_hijack[] = { 0x08, 0x9B, 'v', 'r', '_', 'p', 'r', 'e', 's', 'e', 'n', 'c', 'e' };
static uint8_t test_frame_haptic_feedback_attack[] = { 0x08, 0x9C, 'h', 'a', 'p', 't', 'i', 'c', '_', 'a', 't', 't', 'k' };
static uint8_t test_frame_mixed_reality_confusion[] = { 0x08, 0x9D, 'm', 'i', 'x', 'e', 'd', '_', 'r', 'e', 'a', 'l', 'i', 't', 'y' };

/* Advanced Quantum Technology Attacks */
static uint8_t test_frame_quantum_entanglement_break[] = { 0x08, 0x9E, 'q', 'u', 'a', 'n', 't', '_', 'e', 'n', 't', 'a', 'n', 'g', 'l', 'e' };
static uint8_t test_frame_quantum_teleportation_hijack[] = { 0x08, 0x9F, 'q', 'u', 'a', 'n', 't', '_', 't', 'e', 'l', 'e', 'p', 'o', 'r', 't' };
static uint8_t test_frame_quantum_supremacy_abuse[] = { 0x08, 0xA0, 'q', 'u', 'a', 'n', 't', '_', 's', 'u', 'p', 'r', 'e', 'm', 'a', 'c', 'y' };
static uint8_t test_frame_quantum_error_injection[] = { 0x08, 0xA1, 'q', 'u', 'a', 'n', 't', '_', 'e', 'r', 'r', 'o', 'r' };

/* Space Technology Warfare */
static uint8_t test_frame_orbital_debris_weaponization[] = { 0x08, 0xA2, 'o', 'r', 'b', 'i', 't', 'a', 'l', '_', 'd', 'e', 'b', 'r', 'i', 's' };
static uint8_t test_frame_space_elevator_sabotage[] = { 0x08, 0xA3, 's', 'p', 'a', 'c', 'e', '_', 'e', 'l', 'e', 'v', 'a', 't', 'o', 'r' };
static uint8_t test_frame_mars_colony_attack[] = { 0x08, 0xA4, 'm', 'a', 'r', 's', '_', 'c', 'o', 'l', 'o', 'n', 'y' };
static uint8_t test_frame_asteroid_mining_hijack[] = { 0x08, 0xA5, 'a', 's', 't', 'e', 'r', 'o', 'i', 'd', '_', 'm', 'i', 'n', 'e' };

/* Biotechnology Attacks */
static uint8_t test_frame_dna_sequencing_attack[] = { 0x08, 0xA6, 'd', 'n', 'a', '_', 's', 'e', 'q', 'u', 'e', 'n', 'c', 'e' };
static uint8_t test_frame_crispr_hijack[] = { 0x08, 0xA7, 'c', 'r', 'i', 's', 'p', 'r', '_', 'h', 'i', 'j', 'a', 'c', 'k' };
static uint8_t test_frame_synthetic_biology_weapon[] = { 0x08, 0xA8, 's', 'y', 'n', 't', 'h', '_', 'b', 'i', 'o', 'l', 'o', 'g', 'y' };
static uint8_t test_frame_biometric_dna_forge[] = { 0x08, 0xA9, 'b', 'i', 'o', '_', 'd', 'n', 'a', '_', 'f', 'o', 'r', 'g', 'e' };

/* Nanotechnology Attacks */
static uint8_t test_frame_nanobot_swarm_attack[] = { 0x08, 0xAA, 'n', 'a', 'n', 'o', 'b', 'o', 't', '_', 's', 'w', 'a', 'r', 'm' };
static uint8_t test_frame_molecular_assembly_hijack[] = { 0x08, 0xAB, 'm', 'o', 'l', 'e', 'c', '_', 'a', 's', 's', 'e', 'm', 'b', 'l', 'y' };
static uint8_t test_frame_nano_scale_espionage[] = { 0x08, 0xAC, 'n', 'a', 'n', 'o', '_', 'e', 's', 'p', 'i', 'o', 'n', 'a', 'g', 'e' };
static uint8_t test_frame_quantum_dot_manipulation[] = { 0x08, 0xAD, 'q', 'u', 'a', 'n', 't', 'u', 'm', '_', 'd', 'o', 't' };

/* Neurotechnology Attacks */
static uint8_t test_frame_brain_computer_hijack[] = { 0x08, 0xAE, 'b', 'r', 'a', 'i', 'n', '_', 'c', 'o', 'm', 'p', 'u', 't', 'e', 'r' };
static uint8_t test_frame_neural_implant_attack[] = { 0x08, 0xAF, 'n', 'e', 'u', 'r', 'a', 'l', '_', 'i', 'm', 'p', 'l', 'a', 'n', 't' };
static uint8_t test_frame_memory_manipulation[] = { 0x08, 0xB0, 'm', 'e', 'm', 'o', 'r', 'y', '_', 'm', 'a', 'n', 'i', 'p' };
static uint8_t test_frame_thought_pattern_hijack[] = { 0x08, 0xB1, 't', 'h', 'o', 'u', 'g', 'h', 't', '_', 'h', 'i', 'j', 'a', 'c', 'k' };

/* Advanced Robotics Attacks */
static uint8_t test_frame_robot_swarm_coordination[] = { 0x08, 0xB2, 'r', 'o', 'b', 'o', 't', '_', 's', 'w', 'a', 'r', 'm' };
static uint8_t test_frame_humanoid_impersonation[] = { 0x08, 0xB3, 'h', 'u', 'm', 'a', 'n', 'o', 'i', 'd', '_', 'i', 'm', 'p' };
static uint8_t test_frame_industrial_robot_weaponization[] = { 0x08, 0xB4, 'i', 'n', 'd', '_', 'r', 'o', 'b', 'o', 't' };
static uint8_t test_frame_ai_ethics_bypass[] = { 0x08, 0xB5, 'a', 'i', '_', 'e', 't', 'h', 'i', 'c', 's', '_', 'b', 'p' };

/* === RFC-SPECIFIC ATTACK VECTORS === */

/* RFC 8999 - Version-Independent Properties of QUIC */
static uint8_t test_frame_rfc8999_version_independent_violation[] = { 0x08, 0xC0, 'r', 'f', 'c', '8', '9', '9', '9', '_', 'v', 'i', 'o' };
static uint8_t test_frame_rfc8999_fixed_bit_clear[] = { 0x08, 0xC1, 'f', 'i', 'x', 'e', 'd', '_', 'b', 'i', 't', '_', '0' };
static uint8_t test_frame_rfc8999_connection_id_length_violation[] = { 0x08, 0xC2, 'c', 'i', 'd', '_', 'l', 'e', 'n', '_', 'v', 'i', 'o' };

/* RFC 9000 - QUIC Core Transport */
static uint8_t test_frame_rfc9000_packet_number_encoding_error[] = { 0x08, 0xC3, 'p', 'k', 't', '_', 'n', 'u', 'm', '_', 'e', 'r', 'r' };
static uint8_t test_frame_rfc9000_varint_overflow[] = { 0x08, 0xC4, 'v', 'a', 'r', 'i', 'n', 't', '_', 'o', 'v', 'f', 'l' };
static uint8_t test_frame_rfc9000_frame_type_reserved[] = { 0x08, 0xC5, 'f', 'r', 'a', 'm', 'e', '_', 'r', 'e', 's', 'v', 'd' };
static uint8_t test_frame_rfc9000_transport_param_duplicate[] = { 0x08, 0xC6, 't', 'p', '_', 'd', 'u', 'p', 'l', 'i', 'c', 'a', 't', 'e' };
static uint8_t test_frame_rfc9000_connection_migration_violation[] = { 0x08, 0xC7, 'c', 'o', 'n', 'n', '_', 'm', 'i', 'g', '_', 'v', 'i', 'o' };

/* RFC 9001 - QUIC TLS Integration */
static uint8_t test_frame_rfc9001_tls_handshake_tampering[] = { 0x08, 0xC8, 't', 'l', 's', '_', 'h', 's', '_', 't', 'a', 'm', 'p' };
static uint8_t test_frame_rfc9001_key_update_premature[] = { 0x08, 0xC9, 'k', 'e', 'y', '_', 'u', 'p', 'd', '_', 'e', 'a', 'r', 'l', 'y' };
static uint8_t test_frame_rfc9001_crypto_frame_ordering[] = { 0x08, 0xCA, 'c', 'r', 'y', 'p', 't', 'o', '_', 'o', 'r', 'd', 'e', 'r' };
static uint8_t test_frame_rfc9001_protected_packet_manipulation[] = { 0x08, 0xCB, 'p', 'r', 'o', 't', '_', 'p', 'k', 't', '_', 'm', 'a', 'n' };

/* RFC 9002 - Loss Detection and Congestion Control */
static uint8_t test_frame_rfc9002_ack_delay_manipulation[] = { 0x08, 0xCC, 'a', 'c', 'k', '_', 'd', 'e', 'l', 'a', 'y', '_', 'm' };
static uint8_t test_frame_rfc9002_rtt_manipulation[] = { 0x08, 0xCD, 'r', 't', 't', '_', 'm', 'a', 'n', 'i', 'p', 'u', 'l', 'a', 't', 'e' };
static uint8_t test_frame_rfc9002_congestion_window_attack[] = { 0x08, 0xCE, 'c', 'w', 'n', 'd', '_', 'a', 't', 't', 'a', 'c', 'k' };
static uint8_t test_frame_rfc9002_loss_detection_bypass[] = { 0x08, 0xCF, 'l', 'o', 's', 's', '_', 'd', 'e', 't', '_', 'b', 'p' };

/* RFC 9221 - Unreliable Datagram Extension */
static uint8_t test_frame_rfc9221_datagram_length_violation[] = { 0x30, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 'd', 'a', 't', 'a' };
static uint8_t test_frame_rfc9221_datagram_in_0rtt[] = { 0x30, 0x05, 'z', 'e', 'r', 'o', '_', 'r', 't', 't' };
static uint8_t test_frame_rfc9221_datagram_fragmentation[] = { 0x31, 0x08, 'f', 'r', 'a', 'g', 'm', 'e', 'n', 't' };

/* RFC 9287 - Greasing the QUIC Bit */
static uint8_t test_frame_rfc9287_grease_bit_violation[] = { 0x08, 0xD0, 'g', 'r', 'e', 'a', 's', 'e', '_', 'b', 'i', 't' };
static uint8_t test_frame_rfc9287_reserved_bit_dependency[] = { 0x08, 0xD1, 'r', 'e', 's', 'v', '_', 'b', 'i', 't', '_', 'd', 'e', 'p' };

/* RFC 9368 - Compatible Version Negotiation */
static uint8_t test_frame_rfc9368_version_negotiation_downgrade[] = { 0x08, 0xD2, 'v', 'e', 'r', '_', 'n', 'e', 'g', '_', 'd', 'g', 'd' };
static uint8_t test_frame_rfc9368_compatible_version_confusion[] = { 0x08, 0xD3, 'c', 'o', 'm', 'p', '_', 'v', 'e', 'r', '_', 'c', 'f' };

/* RFC 9369 - QUIC Version 2 */
static uint8_t test_frame_rfc9369_v2_frame_type_confusion[] = { 0x08, 0xD4, 'v', '2', '_', 'f', 'r', 'a', 'm', 'e', '_', 'c', 'f' };
static uint8_t test_frame_rfc9369_v2_packet_protection_bypass[] = { 0x08, 0xD5, 'v', '2', '_', 'p', 'r', 'o', 't', '_', 'b', 'p' };

/* RFC 9114 - HTTP/3 */
static uint8_t test_frame_rfc9114_h3_frame_length_overflow[] = { 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x04, 0x00, 0x00, 0x00, 0x00 };
static uint8_t test_frame_rfc9114_h3_settings_duplicate[] = { 0x04, 0x08, 0x01, 0x40, 0x64, 0x01, 0x40, 0x64 };
static uint8_t test_frame_rfc9114_h3_push_promise_violation[] = { 0x05, 0x05, 0x00, 0x01, 0x02, 0x03, 0x04 };
static uint8_t test_frame_rfc9114_h3_goaway_invalid_stream[] = { 0x07, 0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
static uint8_t test_frame_rfc9114_h3_max_push_id_regression[] = { 0x0D, 0x04, 0x00, 0x00, 0x00, 0x32 };

/* RFC 9204 - QPACK Field Compression */
static uint8_t test_frame_rfc9204_qpack_encoder_stream_corruption[] = { 0x08, 0x02, 0xFF, 0xFF, 0xFF, 0xFF };
static uint8_t test_frame_rfc9204_qpack_decoder_stream_overflow[] = { 0x08, 0x03, 0x80, 0xFF, 0xFF, 0xFF, 0xFF };
static uint8_t test_frame_rfc9204_qpack_dynamic_table_corruption[] = { 0x3F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
static uint8_t test_frame_rfc9204_qpack_header_block_dependency[] = { 0xC0, 0xFF, 0xFF, 0xFF, 0xFF };

/* RFC 9220 - Bootstrapping WebSockets with HTTP/3 */
static uint8_t test_frame_rfc9220_websocket_upgrade_injection[] = { 0x08, 0x00, 'U', 'p', 'g', 'r', 'a', 'd', 'e', ':', ' ', 'w', 'e', 'b', 's', 'o', 'c', 'k', 'e', 't' };
static uint8_t test_frame_rfc9220_websocket_key_manipulation[] = { 0x08, 0x01, 'S', 'e', 'c', '-', 'W', 'e', 'b', 'S', 'o', 'c', 'k', 'e', 't', '-', 'K', 'e', 'y' };
static uint8_t test_frame_rfc9220_websocket_protocol_confusion[] = { 0x08, 0x02, 'w', 's', ':', '/', '/', 'e', 'x', 'a', 'm', 'p', 'l', 'e' };

/* RFC 9412 - ORIGIN Extension in HTTP/3 */
static uint8_t test_frame_rfc9412_origin_frame_spoofing[] = { 0x0C, 0x10, 'h', 't', 't', 'p', 's', ':', '/', '/', 'e', 'v', 'i', 'l', '.', 'c', 'o', 'm' };
static uint8_t test_frame_rfc9412_origin_authority_bypass[] = { 0x0C, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

/* RFC 9250 - DNS over QUIC (DoQ) */
static uint8_t test_frame_rfc9250_doq_malformed_query[] = { 0x08, 0x00, 0xFF, 0xFF, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
static uint8_t test_frame_rfc9250_doq_response_amplification[] = { 0x08, 0x01, 0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x01 };
static uint8_t test_frame_rfc9250_doq_cache_poisoning[] = { 0x08, 0x02, 0xBA, 0xDC, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 };
static uint8_t test_frame_rfc9250_doq_stream_reuse_violation[] = { 0x08, 0x00, 0x56, 0x78, 0x01, 0x00, 0x00, 0x01 };

/* RFC 8484 - DNS over HTTPS (DoH) */
static uint8_t test_frame_rfc8484_doh_get_parameter_injection[] = { 0x08, 0x00, 'G', 'E', 'T', ' ', '/', 'd', 'n', 's', '-', 'q', 'u', 'e', 'r', 'y', '?', 'd', 'n', 's', '=', 'e', 'v', 'i', 'l' };
static uint8_t test_frame_rfc8484_doh_post_content_type_bypass[] = { 0x08, 0x01, 'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'T', 'y', 'p', 'e', ':', ' ', 't', 'e', 'x', 't', '/', 'p', 'l', 'a', 'i', 'n' };

/* RFC 8446 - TLS 1.3 Integration Issues */
static uint8_t test_frame_rfc8446_tls13_early_data_replay[] = { 0x06, 0x00, 0x10, 0x16, 0x03, 0x03, 0x00, 0x0C, 0x08, 0x00, 0x00, 0x08, 'r', 'e', 'p', 'l', 'a', 'y', 'e', 'd' };
static uint8_t test_frame_rfc8446_tls13_certificate_transparency_bypass[] = { 0x06, 0x00, 0x08, 0x0B, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00 };

/* RFC 9110/9111/9112/9113 - HTTP Semantics Violations */
static uint8_t test_frame_rfc9110_http_method_smuggling[] = { 0x08, 0x00, 'P', 'O', 'S', 'T', ' ', '/', 'x', ' ', 'H', 'T', 'T', 'P', '/', '3' };
static uint8_t test_frame_rfc9111_cache_poisoning_via_vary[] = { 0x08, 0x01, 'V', 'a', 'r', 'y', ':', ' ', 'X', '-', 'E', 'v', 'i', 'l' };
static uint8_t test_frame_rfc9113_h2_frame_injection[] = { 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01 };

/* RFC 7541 - HPACK vs QPACK Confusion */
static uint8_t test_frame_rfc7541_hpack_in_qpack_context[] = { 0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff };
static uint8_t test_frame_rfc7541_hpack_huffman_bomb[] = { 0x88, 0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f, 0x89, 0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f };

/* RFC 7838 - HTTP Alternative Services Abuse */
static uint8_t test_frame_rfc7838_alt_svc_redirection_attack[] = { 0x08, 0x00, 'A', 'l', 't', '-', 'S', 'v', 'c', ':', ' ', 'h', '3', '=', ':', '4', '4', '3' };
static uint8_t test_frame_rfc7838_alt_svc_downgrade_attack[] = { 0x08, 0x01, 'A', 'l', 't', '-', 'S', 'v', 'c', ':', ' ', 'c', 'l', 'e', 'a', 'r' };

/* RFC 9218 - Extensible Prioritization Scheme */
static uint8_t test_frame_rfc9218_priority_update_overflow[] = { 0x10, 0x04, 0xFF, 0xFF, 0xFF, 0xFF, 'u', '=', '7', ',', 'i' };
static uint8_t test_frame_rfc9218_priority_dependency_loop[] = { 0x10, 0x08, 0x00, 0x00, 0x00, 0x01, 'u', '=', '1', ',', 'p', '=', '1' };

/* RFC 9297 - HTTP Datagrams Integration Issues */
static uint8_t test_frame_rfc9297_http_datagram_context_confusion[] = { 0x30, 0x10, 0x00, 0x00, 0x00, 0x01, 'h', 't', 't', 'p', '_', 'd', 'a', 't', 'a', 'g', 'r', 'a', 'm' };
static uint8_t test_frame_rfc9297_datagram_flow_id_collision[] = { 0x31, 0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x01, 0x02, 0x03 };

/* === EXTENDED RFC-SPECIFIC ATTACK VECTORS === */

/* RFC 2119/8174 - Requirement Level Violations */
static uint8_t test_frame_rfc2119_must_violation[] = { 0x08, 0x00, 'M', 'U', 'S', 'T', '_', 'V', 'I', 'O', 'L', 'A', 'T', 'E' };
static uint8_t test_frame_rfc8174_should_not_ignore[] = { 0x08, 0x01, 'S', 'H', 'O', 'U', 'L', 'D', '_', 'N', 'O', 'T' };
static uint8_t test_frame_rfc2119_may_abuse[] = { 0x08, 0x02, 'M', 'A', 'Y', '_', 'A', 'B', 'U', 'S', 'E' };

/* RFC 768 - UDP Integration Issues */
static uint8_t test_frame_rfc768_udp_length_mismatch[] = { 0x08, 0x00, 0xFF, 0xFF, 0x00, 0x08, 'u', 'd', 'p', '_', 'l', 'e', 'n' };
static uint8_t test_frame_rfc768_udp_checksum_zero[] = { 0x08, 0x01, 0x00, 0x00, 'z', 'e', 'r', 'o', '_', 'c', 's', 'u', 'm' };
static uint8_t test_frame_rfc768_udp_port_zero[] = { 0x08, 0x02, 0x00, 0x00, 0x00, 0x00, 'p', 'o', 'r', 't', '_', '0' };

/* RFC 6455 - WebSocket Protocol Deeper Violations */
static uint8_t test_frame_rfc6455_ws_upgrade_downgrade[] = { 0x08, 0x00, 'U', 'p', 'g', 'r', 'a', 'd', 'e', ':', ' ', 'h', 't', 't', 'p' };
static uint8_t test_frame_rfc6455_ws_sec_key_collision[] = { 0x08, 0x01, 'S', 'e', 'c', '-', 'W', 'e', 'b', 'S', 'o', 'c', 'k', 'e', 't', '-', 'K', 'e', 'y', ':', ' ', 'A', 'A', 'A', 'A' };
static uint8_t test_frame_rfc6455_ws_version_mismatch[] = { 0x08, 0x02, 'S', 'e', 'c', '-', 'W', 'e', 'b', 'S', 'o', 'c', 'k', 'e', 't', '-', 'V', 'e', 'r', 's', 'i', 'o', 'n', ':', ' ', '1', '2' };
static uint8_t test_frame_rfc6455_ws_extension_hijack[] = { 0x08, 0x03, 'S', 'e', 'c', '-', 'W', 'e', 'b', 'S', 'o', 'c', 'k', 'e', 't', '-', 'E', 'x', 't', 'e', 'n', 's', 'i', 'o', 'n', 's' };

/* RFC 8441 - HTTP/2 over QUIC Violations */
static uint8_t test_frame_rfc8441_h2_over_quic_settings[] = { 0x04, 0x06, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01 };
static uint8_t test_frame_rfc8441_h2_quic_stream_mapping[] = { 0x08, 0x00, 'h', '2', '_', 'q', 'u', 'i', 'c', '_', 'm', 'a', 'p' };
static uint8_t test_frame_rfc8441_extended_connect_abuse[] = { 0x08, 0x01, 'C', 'O', 'N', 'N', 'E', 'C', 'T', ' ', '/', ' ', 'H', 'T', 'T', 'P', '/', '2' };

/* Advanced RFC 9000 Core Protocol Edge Cases */
static uint8_t test_frame_rfc9000_initial_packet_corruption[] = { 0x08, 0x00, 'i', 'n', 'i', 't', '_', 'c', 'o', 'r', 'r', 'u', 'p', 't' };
static uint8_t test_frame_rfc9000_handshake_packet_replay[] = { 0x08, 0x01, 'h', 's', '_', 'r', 'e', 'p', 'l', 'a', 'y' };
static uint8_t test_frame_rfc9000_application_data_leak[] = { 0x08, 0x02, 'a', 'p', 'p', '_', 'd', 'a', 't', 'a', '_', 'l', 'e', 'a', 'k' };
static uint8_t test_frame_rfc9000_stateless_reset_forge[] = { 0x08, 0x03, 's', 't', 'a', 't', 'e', 'l', 'e', 's', 's', '_', 'f', 'o', 'r', 'g', 'e' };
static uint8_t test_frame_rfc9000_retry_token_reuse[] = { 0x08, 0x04, 'r', 'e', 't', 'r', 'y', '_', 't', 'o', 'k', 'e', 'n', '_', 'r', 'e', 'u', 's', 'e' };

/* Advanced RFC 9001 TLS Integration Attacks */
static uint8_t test_frame_rfc9001_tls_alert_injection[] = { 0x06, 0x00, 0x04, 0x15, 0x03, 0x01, 0x02 };
static uint8_t test_frame_rfc9001_early_data_confusion[] = { 0x06, 0x00, 0x08, 0x16, 0x03, 0x03, 0x00, 0x04, 0x0E, 0x00, 0x00, 0x00 };
static uint8_t test_frame_rfc9001_certificate_verify_bypass[] = { 0x06, 0x00, 0x10, 0x16, 0x03, 0x03, 0x00, 0x0C, 0x0F, 0x00, 0x00, 0x08, 0x04, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
static uint8_t test_frame_rfc9001_finished_message_forge[] = { 0x06, 0x00, 0x14, 0x16, 0x03, 0x03, 0x00, 0x10, 0x14, 0x00, 0x00, 0x0C, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

/* Advanced RFC 9002 Loss Detection Exploits */
static uint8_t test_frame_rfc9002_probe_timeout_manipulation[] = { 0x02, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00 };
static uint8_t test_frame_rfc9002_persistent_congestion_force[] = { 0x02, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00 };
static uint8_t test_frame_rfc9002_bandwidth_estimation_poison[] = { 0x02, 0x64, 0x00, 0x00, 0x01, 0x00 };
static uint8_t test_frame_rfc9002_loss_detection_evasion[] = { 0x01 }; // PING with specific timing

/* Advanced RFC 9114 HTTP/3 Frame Attacks */
static uint8_t test_frame_rfc9114_h3_cancel_push_invalid[] = { 0x03, 0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
static uint8_t test_frame_rfc9114_h3_headers_after_trailers[] = { 0x01, 0x04, 0x00, 0x00, 0x82, 0x84 };
static uint8_t test_frame_rfc9114_h3_data_after_fin[] = { 0x00, 0x04, 'd', 'a', 't', 'a' };
static uint8_t test_frame_rfc9114_h3_unknown_frame_critical[] = { 0xFF, 0x04, 'c', 'r', 'i', 't' };
static uint8_t test_frame_rfc9114_h3_settings_after_request[] = { 0x04, 0x04, 0x01, 0x40, 0x64, 0x00 };

/* Advanced RFC 9204 QPACK Compression Attacks */
static uint8_t test_frame_rfc9204_qpack_table_update_race[] = { 0x3A, 0xFF, 0xFF, 0xFF, 0xFF };
static uint8_t test_frame_rfc9204_qpack_name_reference_oob[] = { 0x50, 0xFF, 0xFF, 0xFF, 0xFF, 0x04, 't', 'e', 's', 't' };
static uint8_t test_frame_rfc9204_qpack_huffman_bomb_extended[] = { 0x88, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
static uint8_t test_frame_rfc9204_qpack_post_base_index[] = { 0x10, 0xFF, 0xFF, 0xFF, 0xFF };

/* Advanced RFC 9221 Datagram Extension Exploits */
static uint8_t test_frame_rfc9221_datagram_id_reuse[] = { 0x30, 0x08, 0x12, 0x34, 0x56, 0x78, 'd', 'u', 'p', 'e' };
static uint8_t test_frame_rfc9221_datagram_ordering_violation[] = { 0x31, 0x10, 0x00, 0x00, 0x00, 0x02, 'o', 'u', 't', '_', 'o', 'f', '_', 'o', 'r', 'd', 'e', 'r' };
static uint8_t test_frame_rfc9221_datagram_ack_elicitation[] = { 0x30, 0x04, 'a', 'c', 'k', '?' };

/* Advanced RFC 9250 DoQ Protocol Violations */
static uint8_t test_frame_rfc9250_doq_transaction_id_reuse[] = { 0x08, 0x00, 0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
static uint8_t test_frame_rfc9250_doq_stream_multiplexing_abuse[] = { 0x08, 0x04, 0x56, 0x78, 0x01, 0x00, 0x00, 0x01 };
static uint8_t test_frame_rfc9250_doq_early_close_attack[] = { 0x1C, 0x00, 0x00, 0x04, 'd', 'o', 'q', '_', 'c', 'l', 'o', 's', 'e' };
static uint8_t test_frame_rfc9250_doq_padding_analysis[] = { 0x08, 0x00, 0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01 };

/* Cross-RFC Integration Attacks */
static uint8_t test_frame_cross_rfc_h3_quic_version_confusion[] = { 0x08, 0x00, 'h', '3', '_', 'v', '1', '_', 'o', 'n', '_', 'v', '2' };
static uint8_t test_frame_cross_rfc_tls_quic_key_mismatch[] = { 0x06, 0x00, 0x08, 't', 'l', 's', '_', 'k', 'e', 'y', '_', 'm', 'i', 's', 'm', 'a', 't', 'c', 'h' };
static uint8_t test_frame_cross_rfc_http_quic_stream_leak[] = { 0x08, 0x00, 'h', 't', 't', 'p', '_', 's', 't', 'r', 'e', 'a', 'm', '_', 'l', 'e', 'a', 'k' };
static uint8_t test_frame_cross_rfc_qpack_hpack_confusion[] = { 0x82, 0x84, 0x86, 0x41, 0x8A, 0x0E, 0x03, '2', '0', '0' };

/* === ULTIMATE RFC COVERAGE EXPANSION === */

/* RFC 1035 - DNS Protocol Violations */
static uint8_t test_frame_rfc1035_dns_compression_bomb[] = { 0x08, 0x00, 0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x0C, 0xC0, 0x0C, 0xC0, 0x0C };
static uint8_t test_frame_rfc1035_dns_label_overflow[] = { 0x08, 0x01, 0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 'A', 'A', 'A', 'A' };
static uint8_t test_frame_rfc1035_dns_type_confusion[] = { 0x08, 0x02, 0xEF, 0x12, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00, 0xFF, 0xFF, 0xFF, 0xFF };

/* RFC 1123 - Host Requirements Violations */
static uint8_t test_frame_rfc1123_invalid_hostname[] = { 0x08, 0x00, 'H', 'o', 's', 't', ':', ' ', '-', 'i', 'n', 'v', 'a', 'l', 'i', 'd', '-', '.', 'c', 'o', 'm' };
static uint8_t test_frame_rfc1123_hostname_length_overflow[] = { 0x08, 0x01, 'H', 'o', 's', 't', ':', ' ', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A' };
static uint8_t test_frame_rfc1123_numeric_only_hostname[] = { 0x08, 0x02, 'H', 'o', 's', 't', ':', ' ', '1', '2', '3', '4', '5', '6', '7', '8' };

/* RFC 2131 - DHCP Protocol Violations */
static uint8_t test_frame_rfc2131_dhcp_option_overflow[] = { 0x08, 0x00, 0x01, 0x01, 0x06, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
static uint8_t test_frame_rfc2131_dhcp_malformed_packet[] = { 0x08, 0x01, 0x02, 0x01, 0x06, 0x00, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x80, 0x00 };
static uint8_t test_frame_rfc2131_dhcp_invalid_message_type[] = { 0x08, 0x02, 0x01, 0xFF, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00 };

/* RFC 2818 - HTTP Over TLS Violations */
static uint8_t test_frame_rfc2818_https_redirect_attack[] = { 0x08, 0x00, 'L', 'o', 'c', 'a', 't', 'i', 'o', 'n', ':', ' ', 'h', 't', 't', 'p', ':', '/', '/', 'e', 'v', 'i', 'l' };
static uint8_t test_frame_rfc2818_mixed_content_attack[] = { 0x08, 0x01, '<', 'i', 'm', 'g', ' ', 's', 'r', 'c', '=', '"', 'h', 't', 't', 'p', ':', '/', '/', 'a', 't', 't', 'a', 'c', 'k', 'e', 'r' };
static uint8_t test_frame_rfc2818_certificate_pinning_bypass[] = { 0x06, 0x00, 0x10, 0x16, 0x03, 0x03, 0x00, 0x0C, 0x0B, 0x00, 0x08, 0x00, 0x00, 0x05, 'f', 'a', 'k', 'e', 'c' };

/* RFC 3280 - Certificate and CRL Profile Violations */
static uint8_t test_frame_rfc3280_certificate_chain_attack[] = { 0x06, 0x00, 0x20, 0x16, 0x03, 0x03, 0x00, 0x1C, 0x0B, 0x00, 0x18, 0x00, 0x00, 0x15, 'f', 'a', 'k', 'e', '_', 'c', 'e', 'r', 't', '_', 'c', 'h', 'a', 'i', 'n', '_', 'a', 't', 't', 'a', 'c', 'k' };
static uint8_t test_frame_rfc3280_crl_poisoning[] = { 0x06, 0x00, 0x18, 0x16, 0x03, 0x03, 0x00, 0x14, 'c', 'r', 'l', '_', 'p', 'o', 'i', 's', 'o', 'n', 'i', 'n', 'g', '_', 'a', 't', 't', 'a', 'c', 'k' };
static uint8_t test_frame_rfc3280_invalid_extension[] = { 0x06, 0x00, 0x0C, 0x16, 0x03, 0x03, 0x00, 0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

/* RFC 3492 - Punycode Implementation Attacks */
static uint8_t test_frame_rfc3492_punycode_overflow[] = { 0x08, 0x00, 'H', 'o', 's', 't', ':', ' ', 'x', 'n', '-', '-', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A' };
static uint8_t test_frame_rfc3492_punycode_homograph[] = { 0x08, 0x01, 'H', 'o', 's', 't', ':', ' ', 'x', 'n', '-', '-', 'a', 'p', 'p', 'l', 'e', '-', '9', 'q', 'a' };
static uint8_t test_frame_rfc3492_punycode_mixed_script[] = { 0x08, 0x02, 'x', 'n', '-', '-', 'c', 'y', 'r', 'i', 'l', 'l', 'i', 'c', '-', 'l', 'a', 't', 'i', 'n' };

/* RFC 4291 - IPv6 Addressing Architecture Violations */
static uint8_t test_frame_rfc4291_ipv6_header_manipulation[] = { 0x08, 0x00, 0x60, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x3A, 0xFF, 0x20, 0x01, 0x0D, 0xB8 };
static uint8_t test_frame_rfc4291_ipv6_extension_header_bomb[] = { 0x08, 0x01, 0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x06, 0xFF, 0xFF, 0xFF, 0xFF };
static uint8_t test_frame_rfc4291_ipv6_address_spoofing[] = { 0x08, 0x02, 0xFE, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

/* RFC 5321 - SMTP Enhanced Violations */
static uint8_t test_frame_rfc5321_smtp_pipeline_injection[] = { 0x08, 0x00, 'R', 'C', 'P', 'T', ' ', 'T', 'O', ':', '<', 'u', 's', 'e', 'r', '>', '\r', '\n', 'D', 'A', 'T', 'A' };
static uint8_t test_frame_rfc5321_smtp_header_injection[] = { 0x08, 0x01, 'S', 'u', 'b', 'j', 'e', 'c', 't', ':', ' ', 't', 'e', 's', 't', '\r', '\n', 'B', 'c', 'c', ':' };
static uint8_t test_frame_rfc5321_smtp_size_limit_bypass[] = { 0x08, 0x02, 'M', 'A', 'I', 'L', ' ', 'F', 'R', 'O', 'M', ':', '<', 't', 'e', 's', 't', '>', ' ', 'S', 'I', 'Z', 'E', '=', '-', '1' };

/* RFC 3261 - SIP Integration Issues */
static uint8_t test_frame_rfc3261_sip_uri_overflow[] = { 0x08, 0x00, 'S', 'I', 'P', '/', '2', '.', '0', ' ', '/', ' ', 'u', 'r', 'i', '_', 'o', 'v', 'f' };
static uint8_t test_frame_rfc3261_sip_header_injection[] = { 0x08, 0x01, 'V', 'i', 'a', ':', ' ', 'S', 'I', 'P', '/', '2', '.', '0', '/', 'U', 'D', 'P' };
static uint8_t test_frame_rfc3261_sip_message_smuggling[] = { 0x08, 0x02, 'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'L', 'e', 'n', 'g', 't', 'h', ':', ' ', '-', '1' };

/* RFC 5321 - SMTP Integration Violations */
static uint8_t test_frame_rfc5321_smtp_command_injection[] = { 0x08, 0x00, 'M', 'A', 'I', 'L', ' ', 'F', 'R', 'O', 'M', ':', '<', 'e', 'v', 'i', 'l', '>' };
static uint8_t test_frame_rfc5321_smtp_data_smuggling[] = { 0x08, 0x01, 'D', 'A', 'T', 'A', '\r', '\n', '.', '\r', '\n', 'M', 'A', 'I', 'L' };
static uint8_t test_frame_rfc5321_smtp_relay_attack[] = { 0x08, 0x02, 'R', 'C', 'P', 'T', ' ', 'T', 'O', ':', '<', 'a', 'd', 'm', 'i', 'n' };

/* RFC 1939 - POP3 Protocol Violations */
static uint8_t test_frame_rfc1939_pop3_buffer_overflow[] = { 0x08, 0x00, 'U', 'S', 'E', 'R', ' ', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A' };
static uint8_t test_frame_rfc1939_pop3_command_injection[] = { 0x08, 0x01, 'P', 'A', 'S', 'S', ' ', 0x00, '0', '0', 0x00, '0', 'A' };

/* RFC 3501 - IMAP4 Protocol Violations */
static uint8_t test_frame_rfc3501_imap_literal_attack[] = { 0x08, 0x00, 'A', '0', '0', '1', ' ', 'L', 'O', 'G', 'I', 'N', ' ', '{', '9', '9', '9', '}' };
static uint8_t test_frame_rfc3501_imap_command_continuation[] = { 0x08, 0x01, 'A', '0', '0', '2', ' ', 'S', 'E', 'A', 'R', 'C', 'H', ' ', 'A', 'L', 'L' };

/* RFC 959 - FTP Protocol Violations */
static uint8_t test_frame_rfc959_ftp_port_command_hijack[] = { 0x08, 0x00, 'P', 'O', 'R', 'T', ' ', '1', '2', '7', ',', '0', ',', '0', ',', '1' };
static uint8_t test_frame_rfc959_ftp_pasv_response_spoof[] = { 0x08, 0x01, '2', '2', '7', ' ', 'P', 'A', 'S', 'V', ' ', '(', '1', '2', '7', ',' };

/* RFC 854 - Telnet Protocol Violations */
static uint8_t test_frame_rfc854_telnet_option_negotiation[] = { 0x08, 0x00, 0xFF, 0xFB, 0x01, 'I', 'A', 'C', ' ', 'W', 'I', 'L', 'L' };
static uint8_t test_frame_rfc854_telnet_command_injection[] = { 0x08, 0x01, 0xFF, 0xF4, 0xFF, 0xFD, 0x06 };

/* RFC 2616 - HTTP/1.1 Legacy Violations */
static uint8_t test_frame_rfc2616_http11_request_smuggling[] = { 0x08, 0x00, 'P', 'O', 'S', 'T', ' ', '/', ' ', 'H', 'T', 'T', 'P', '/', '1', '.', '1' };
static uint8_t test_frame_rfc2616_http11_response_splitting[] = { 0x08, 0x01, 'H', 'T', 'T', 'P', '/', '1', '.', '1', ' ', '2', '0', '0', '\r', '\n' };

/* Advanced Transport Layer Attacks */
static uint8_t test_frame_rfc793_tcp_sequence_prediction[] = { 0x08, 0x00, 'T', 'C', 'P', '_', 'S', 'E', 'Q', '_', 'P', 'R', 'E', 'D' };
static uint8_t test_frame_rfc793_tcp_connection_hijack[] = { 0x08, 0x01, 'T', 'C', 'P', '_', 'H', 'I', 'J', 'A', 'C', 'K' };

/* RFC 4880 - OpenPGP Integration Issues */
static uint8_t test_frame_rfc4880_pgp_key_substitution[] = { 0x08, 0x00, 'P', 'G', 'P', '_', 'K', 'E', 'Y', '_', 'S', 'U', 'B', 'S', 'T' };
static uint8_t test_frame_rfc4880_pgp_signature_forge[] = { 0x08, 0x01, 'P', 'G', 'P', '_', 'S', 'I', 'G', '_', 'F', 'O', 'R', 'G', 'E' };

/* RFC 3986 - URI Manipulation Attacks */
static uint8_t test_frame_rfc3986_uri_scheme_confusion[] = { 0x08, 0x00, 'h', 't', 't', 'p', 's', ':', '/', '/', 'e', 'v', 'i', 'l', '.', 'c', 'o', 'm' };
static uint8_t test_frame_rfc3986_uri_authority_bypass[] = { 0x08, 0x01, 'h', 't', 't', 'p', ':', '/', '/', '@', 'e', 'v', 'i', 'l', '.', 'c', 'o', 'm' };

/* RFC 2045 - MIME Content Type Violations */
static uint8_t test_frame_rfc2045_mime_boundary_attack[] = { 0x08, 0x00, 'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'T', 'y', 'p', 'e', ':', ' ', 'm', 'u', 'l', 't', 'i' };
static uint8_t test_frame_rfc2045_mime_header_injection[] = { 0x08, 0x01, 'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'D', 'i', 's', 'p', 'o', 's', 'i', 't', 'i', 'o', 'n' };

/* RFC 3339 - Date/Time Format Attacks */
static uint8_t test_frame_rfc3339_datetime_overflow[] = { 0x08, 0x00, '9', '9', '9', '9', '-', '1', '3', '-', '3', '2', 'T', '2', '5', ':', '6', '1' };
static uint8_t test_frame_rfc3339_timezone_confusion[] = { 0x08, 0x01, '2', '0', '2', '4', '-', '0', '1', '-', '0', '1', 'T', '0', '0', ':', '0', '0', '+', '2', '5' };

/* RFC 5246 - TLS 1.2 Legacy Protocol Violations */
static uint8_t test_frame_rfc5246_tls12_downgrade_attack[] = { 0x06, 0x00, 0x08, 0x16, 0x03, 0x02, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00 };
static uint8_t test_frame_rfc5246_tls12_cipher_suite_confusion[] = { 0x06, 0x00, 0x0C, 0x16, 0x03, 0x02, 0x00, 0x08, 0x02, 0x00, 0x04, 0x03, 0x02, 0x00, 0x35, 0x00 };
static uint8_t test_frame_rfc5246_tls12_renegotiation_attack[] = { 0x06, 0x00, 0x10, 0x16, 0x03, 0x02, 0x00, 0x0C, 0x01, 0x00, 0x08, 0x03, 0x02, 0xFF, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00 };

/* RFC 6066 - TLS Extensions Abuse */
static uint8_t test_frame_rfc6066_sni_spoofing[] = { 0x06, 0x00, 0x18, 0x16, 0x03, 0x03, 0x00, 0x14, 0x00, 0x00, 0x00, 0x10, 0x00, 0x0E, 0x00, 0x00, 0x0B, 'e', 'v', 'i', 'l', '.', 'c', 'o', 'm', '.', 'c', 'o', 'm' };
static uint8_t test_frame_rfc6066_max_fragment_length_attack[] = { 0x06, 0x00, 0x0C, 0x16, 0x03, 0x03, 0x00, 0x08, 0x00, 0x01, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00 };
static uint8_t test_frame_rfc6066_server_name_overflow[] = { 0x06, 0x00, 0x20, 0x16, 0x03, 0x03, 0x00, 0x1C, 0x00, 0x00, 0x00, 0x18, 0x00, 0x16, 0x00, 0x00, 0x13, 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A' };

/* RFC 6520 - TLS/DTLS Heartbeat Extension Attacks */
static uint8_t test_frame_rfc6520_heartbleed_attack[] = { 0x06, 0x00, 0x08, 0x18, 0x03, 0x03, 0x00, 0x04, 0x01, 0xFF, 0xFF, 0x00 };
static uint8_t test_frame_rfc6520_heartbeat_overflow[] = { 0x06, 0x00, 0x10, 0x18, 0x03, 0x03, 0x00, 0x0C, 0x01, 0xFF, 0xFF, 'p', 'a', 'y', 'l', 'o', 'a', 'd', '_', 'a', 't', 't', 'k' };
static uint8_t test_frame_rfc6520_heartbeat_response_spoofing[] = { 0x06, 0x00, 0x0C, 0x18, 0x03, 0x03, 0x00, 0x08, 0x02, 0x00, 0x04, 'f', 'a', 'k', 'e', '_', 'r', 'e', 's', 'p' };

/* RFC 7301 - ALPN Extension Violations */
static uint8_t test_frame_rfc7301_alpn_protocol_confusion[] = { 0x06, 0x00, 0x14, 0x16, 0x03, 0x03, 0x00, 0x10, 0x00, 0x10, 0x00, 0x0C, 0x00, 0x0A, 0x08, 'h', 't', 't', 'p', '/', '9', '.', '9' };
static uint8_t test_frame_rfc7301_alpn_downgrade_attack[] = { 0x06, 0x00, 0x10, 0x16, 0x03, 0x03, 0x00, 0x0C, 0x00, 0x10, 0x00, 0x08, 0x00, 0x06, 0x04, 'h', 't', 't', 'p', '/', '1', '.', '1' };
static uint8_t test_frame_rfc7301_alpn_protocol_injection[] = { 0x06, 0x00, 0x18, 0x16, 0x03, 0x03, 0x00, 0x14, 0x00, 0x10, 0x00, 0x10, 0x00, 0x0E, 0x0C, 'i', 'n', 'j', 'e', 'c', 't', 'e', 'd', '/', 'e', 'v', 'i', 'l' };

/* RFC 7633 - X.509v3 TLS Feature Extension Attacks */
static uint8_t test_frame_rfc7633_tls_feature_bypass[] = { 0x06, 0x00, 0x10, 0x16, 0x03, 0x03, 0x00, 0x0C, 0x00, 0x18, 0x00, 0x08, 0x00, 0x06, 0x30, 0x04, 0x02, 0x02, 0x00, 0x05 };
static uint8_t test_frame_rfc7633_must_staple_violation[] = { 0x06, 0x00, 0x0C, 0x16, 0x03, 0x03, 0x00, 0x08, 0x00, 0x18, 0x00, 0x04, 0x30, 0x02, 0x02, 0x00 };

/* RFC 8446 - TLS 1.3 Advanced Violations */
static uint8_t test_frame_rfc8446_tls13_psk_binder_confusion[] = { 0x06, 0x00, 0x20, 0x16, 0x03, 0x03, 0x00, 0x1C, 0x01, 0x00, 0x18, 0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x29, 0x00, 0x04, 0x00, 0x02, 0xFF, 0xFF };
static uint8_t test_frame_rfc8446_tls13_hello_retry_confusion[] = { 0x06, 0x00, 0x24, 0x16, 0x03, 0x03, 0x00, 0x20, 0x02, 0x00, 0x1C, 0x03, 0x03, 0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91, 0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C };
static uint8_t test_frame_rfc8446_tls13_key_share_manipulation[] = { 0x06, 0x00, 0x18, 0x16, 0x03, 0x03, 0x00, 0x14, 0x00, 0x33, 0x00, 0x10, 0x00, 0x0E, 0x00, 0x1D, 0x00, 0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

/* RFC 8879 - TLS Certificate Compression Attacks */
static uint8_t test_frame_rfc8879_cert_compression_bomb[] = { 0x06, 0x00, 0x10, 0x16, 0x03, 0x03, 0x00, 0x0C, 0x00, 0x1B, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF };
static uint8_t test_frame_rfc8879_cert_decompression_attack[] = { 0x06, 0x00, 0x14, 0x16, 0x03, 0x03, 0x00, 0x10, 0x00, 0x1B, 0x00, 0x0C, 0x00, 0x01, 0x00, 0x08, 0x78, 0x9C, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

/* RFC 8998 - ShangMi Cipher Suites Attacks */
static uint8_t test_frame_rfc8998_shangmi_downgrade[] = { 0x06, 0x00, 0x10, 0x16, 0x03, 0x03, 0x00, 0x0C, 0x02, 0x00, 0x08, 0x03, 0x03, 0x00, 0x00, 0x00, 0xE0, 0x11, 0x00, 0x00 };
static uint8_t test_frame_rfc8998_shangmi_key_confusion[] = { 0x06, 0x00, 0x20, 0x16, 0x03, 0x03, 0x00, 0x1C, 0x00, 0x33, 0x00, 0x18, 0x00, 0x16, 0x00, 0x1C, 0x00, 0x10, 'S', 'M', '2', '_', 'k', 'e', 'y', '_', 'c', 'o', 'n', 'f', 'u', 's', 'i', 'o', 'n' };

/* RFC 9001 - Enhanced QUIC TLS Integration Attacks */
static uint8_t test_frame_rfc9001_transport_param_encryption_bypass[] = { 0x06, 0x00, 0x10, 0x16, 0x03, 0x03, 0x00, 0x0C, 0x08, 0x00, 0x08, 't', 'p', '_', 'b', 'y', 'p', 'a', 's', 's' };
static uint8_t test_frame_rfc9001_quic_tls_version_mismatch[] = { 0x06, 0x00, 0x08, 0x16, 0x03, 0x01, 0x00, 0x04, 'q', 'u', 'i', 'c' };
static uint8_t test_frame_rfc9001_connection_id_confusion[] = { 0x06, 0x00, 0x0C, 0x16, 0x03, 0x03, 0x00, 0x08, 'c', 'i', 'd', '_', 'c', 'o', 'n', 'f', 'u', 's', 'e' };

/* RFC 791 - Internet Protocol (IPv4) Violations */
static uint8_t test_frame_rfc791_ipv4_fragment_overlap[] = { 0x08, 0x00, 0x45, 0x00, 0x00, 0x1C, 0x12, 0x34, 0x20, 0x01, 0x40, 0x01, 0x00, 0x00, 0xC0, 0xA8, 0x01, 0x01 };
static uint8_t test_frame_rfc791_ipv4_option_overflow[] = { 0x08, 0x01, 0x4F, 0x00, 0x00, 0x40, 0x56, 0x78, 0x00, 0x00, 0x01, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
static uint8_t test_frame_rfc791_ipv4_ttl_manipulation[] = { 0x08, 0x02, 0x45, 0x00, 0x00, 0x14, 0xAB, 0xCD, 0x40, 0x00, 0x00, 0x06, 0x00, 0x00, 0x7F, 0x00, 0x00, 0x01 };

/* RFC 793 - Transmission Control Protocol (TCP) Violations */
static uint8_t test_frame_rfc793_tcp_sequence_wraparound[] = { 0x08, 0x00, 0x00, 0x50, 0x00, 0x80, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x50, 0x02, 0x20, 0x00 };
static uint8_t test_frame_rfc793_tcp_window_scale_attack[] = { 0x08, 0x01, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x50, 0x18, 0xFF, 0xFF };
static uint8_t test_frame_rfc793_tcp_urgent_pointer_abuse[] = { 0x08, 0x02, 0x00, 0x50, 0x00, 0x80, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x50, 0x20, 0x20, 0x00, 0xFF, 0xFF };

/* RFC 826 - Address Resolution Protocol (ARP) Violations */
static uint8_t test_frame_rfc826_arp_spoofing_attack[] = { 0x08, 0x00, 0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x02, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0xC0, 0xA8, 0x01, 0x01 };
static uint8_t test_frame_rfc826_arp_cache_poisoning[] = { 0x08, 0x01, 0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00 };
static uint8_t test_frame_rfc826_arp_gratuitous_flood[] = { 0x08, 0x02, 0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

/* RFC 1058 - Routing Information Protocol (RIP) Violations */
static uint8_t test_frame_rfc1058_rip_metric_infinity_attack[] = { 0x08, 0x00, 0x02, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10 };
static uint8_t test_frame_rfc1058_rip_route_poisoning[] = { 0x08, 0x01, 0x01, 0x01, 0x00, 0x00, 0xC0, 0xA8, 0x01, 0x00, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x01 };
static uint8_t test_frame_rfc1058_rip_authentication_bypass[] = { 0x08, 0x02, 0x02, 0x02, 0xFF, 0xFF, 0x00, 0x02, 'f', 'a', 'k', 'e', '_', 'a', 'u', 't', 'h' };

/* RFC 1112 - Internet Group Management Protocol (IGMP) Violations */
static uint8_t test_frame_rfc1112_igmp_membership_flood[] = { 0x08, 0x00, 0x11, 0x00, 0x00, 0x00, 0xE0, 0x00, 0x00, 0x01 };
static uint8_t test_frame_rfc1112_igmp_leave_group_spoof[] = { 0x08, 0x01, 0x17, 0x00, 0x00, 0x00, 0xE0, 0x00, 0x00, 0x02 };
static uint8_t test_frame_rfc1112_igmp_query_amplification[] = { 0x08, 0x02, 0x11, 0x01, 0x00, 0x00, 0xE0, 0x00, 0x00, 0x00 };

/* RFC 1321 - MD5 Message-Digest Algorithm Attacks */
static uint8_t test_frame_rfc1321_md5_collision_attack[] = { 0x08, 0x00, 0x4D, 0x44, 0x35, 0x00, 0xD1, 0x31, 0xDD, 0x02, 0xC5, 0xE6, 0xEE, 0xC4, 0x69, 0x3D, 0x9A, 0x06, 0x98, 0xAF };
static uint8_t test_frame_rfc1321_md5_length_extension[] = { 0x08, 0x01, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xC0 };
static uint8_t test_frame_rfc1321_md5_preimage_attack[] = { 0x08, 0x02, 'p', 'r', 'e', 'i', 'm', 'a', 'g', 'e', '_', 'a', 't', 't', 'a', 'c', 'k', '_', 'm', 'd', '5' };

/* RFC 1519 - Classless Inter-Domain Routing (CIDR) Violations */
static uint8_t test_frame_rfc1519_cidr_route_aggregation_attack[] = { 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0x00 };
static uint8_t test_frame_rfc1519_cidr_supernet_hijack[] = { 0x08, 0x01, 0x08, 0x08, 0x08, 0x00, 0xFF, 0x00, 0x00, 0x00 };
static uint8_t test_frame_rfc1519_cidr_prefix_length_manipulation[] = { 0x08, 0x02, 0xC0, 0xA8, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00 };

/* RFC 1631 - Network Address Translation (NAT) Violations */
static uint8_t test_frame_rfc1631_nat_port_exhaustion[] = { 0x08, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00 };
static uint8_t test_frame_rfc1631_nat_hairpinning_attack[] = { 0x08, 0x01, 0xC0, 0xA8, 0x01, 0x01, 0xC0, 0xA8, 0x01, 0x02 };
static uint8_t test_frame_rfc1631_nat_translation_bypass[] = { 0x08, 0x02, 0x0A, 0x00, 0x00, 0x01, 0x08, 0x08, 0x08, 0x08 };

/* RFC 1918 - Private Internet Address Space Violations */
static uint8_t test_frame_rfc1918_private_ip_leak[] = { 0x08, 0x00, 0xC0, 0xA8, 0x01, 0x01, 0x08, 0x08, 0x08, 0x08 };
static uint8_t test_frame_rfc1918_private_routing_attack[] = { 0x08, 0x01, 0x0A, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00 };
static uint8_t test_frame_rfc1918_reserved_address_abuse[] = { 0x08, 0x02, 0xAC, 0x10, 0x00, 0x00, 0xFF, 0xF0, 0x00, 0x00 };

/* RFC 2104 - HMAC Keyed-Hashing Violations */
static uint8_t test_frame_rfc2104_hmac_key_recovery[] = { 0x08, 0x00, 'H', 'M', 'A', 'C', '_', 'k', 'e', 'y', '_', 'l', 'e', 'a', 'k' };
static uint8_t test_frame_rfc2104_hmac_timing_attack[] = { 0x08, 0x01, 0x36, 0x36, 0x36, 0x36, 0x5C, 0x5C, 0x5C, 0x5C };
static uint8_t test_frame_rfc2104_hmac_length_extension[] = { 0x08, 0x02, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00 };

/* RFC 2205 - Resource Reservation Protocol (RSVP) Violations */
static uint8_t test_frame_rfc2205_rsvp_path_message_spoof[] = { 0x08, 0x00, 0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
static uint8_t test_frame_rfc2205_rsvp_reservation_hijack[] = { 0x08, 0x01, 0x10, 0x02, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00 };
static uint8_t test_frame_rfc2205_rsvp_teardown_attack[] = { 0x08, 0x02, 0x10, 0x05, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF };

/* RFC 2284 - PPP Extensible Authentication Protocol (EAP) Violations */
static uint8_t test_frame_rfc2284_eap_identity_spoofing[] = { 0x08, 0x00, 0x02, 0x01, 0x00, 0x05, 0x01, 'f', 'a', 'k', 'e' };
static uint8_t test_frame_rfc2284_eap_method_downgrade[] = { 0x08, 0x01, 0x02, 0x02, 0x00, 0x06, 0x04, 0x10, 0x00, 0x00 };
static uint8_t test_frame_rfc2284_eap_success_injection[] = { 0x08, 0x02, 0x02, 0x03, 0x00, 0x04 };

/* RFC 2328 - Open Shortest Path First (OSPF) Violations */
static uint8_t test_frame_rfc2328_ospf_hello_flood[] = { 0x08, 0x00, 0x02, 0x01, 0x00, 0x2C, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00 };
static uint8_t test_frame_rfc2328_ospf_lsa_poisoning[] = { 0x08, 0x01, 0x02, 0x04, 0x00, 0x24, 0x02, 0x02, 0x02, 0x02, 0xFF, 0xFF, 0xFF, 0xFF };
static uint8_t test_frame_rfc2328_ospf_area_hijack[] = { 0x08, 0x02, 0x02, 0x01, 0x00, 0x2C, 0x03, 0x03, 0x03, 0x03, 0x00, 0x00, 0x00, 0x01 };

/* RFC 2401 - Security Architecture for IP (IPsec) Violations */
static uint8_t test_frame_rfc2401_ipsec_esp_replay[] = { 0x08, 0x00, 0x32, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01 };
static uint8_t test_frame_rfc2401_ipsec_ah_truncation[] = { 0x08, 0x01, 0x33, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x12, 0x34 };
static uint8_t test_frame_rfc2401_ipsec_sa_confusion[] = { 0x08, 0x02, 0x32, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00 };

/* RFC 2616 - HTTP/1.1 Protocol Violations */
static uint8_t test_frame_rfc2616_http11_header_injection[] = { 0x08, 0x01, 'G', 'E', 'T', ' ', '/', ' ', 'H', 'T', 'T', 'P', '/', '1', '.', '1', '\r', '\n', 'H', 'o', 's', 't', ':', ' ', 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', '\r', '\n', 'X', '-', 'I', 'n', 'j', 'e', 'c', 't', 'e', 'd', ':', ' ', 'e', 'v', 'i', 'l' };

/* RFC 2865 - Remote Authentication Dial In User Service (RADIUS) Violations */
static uint8_t test_frame_rfc2865_radius_shared_secret_attack[] = { 0x08, 0x00, 0x01, 0x01, 0x00, 0x14, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
static uint8_t test_frame_rfc2865_radius_attribute_overflow[] = { 0x08, 0x01, 0x01, 0x02, 0xFF, 0xFF, 0x01, 0xFF, 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A' };
static uint8_t test_frame_rfc2865_radius_message_authenticator_bypass[] = { 0x08, 0x02, 0x01, 0x03, 0x00, 0x16, 0x50, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

/* RFC 3164 - Syslog Protocol Violations */
static uint8_t test_frame_rfc3164_syslog_format_injection[] = { 0x08, 0x00, '<', '1', '3', '4', '>', 'O', 'c', 't', ' ', '1', '1', ' ', '2', '2', ':', '1', '4', ':', '1', '5', ' ', 'm', 'y', 'h', 'o', 's', 't', ' ', 's', 'u', ':', ' ', 'r', 'o', 'o', 't', '\n', '<', '1', '>', 'i', 'n', 'j', 'e', 'c', 't', 'e', 'd' };
static uint8_t test_frame_rfc3164_syslog_priority_manipulation[] = { 0x08, 0x01, '<', '9', '9', '9', '>', 'f', 'a', 'k', 'e', '_', 'e', 'm', 'e', 'r', 'g', 'e', 'n', 'c', 'y' };
static uint8_t test_frame_rfc3164_syslog_timestamp_confusion[] = { 0x08, 0x02, '<', '1', '6', '>', 'F', 'e', 'b', ' ', '3', '0', ' ', '2', '5', ':', '6', '1', ':', '6', '1', ' ', 'h', 'o', 's', 't', ' ', 'm', 's', 'g' };

/* RFC 3411 - SNMP Architecture Violations */
static uint8_t test_frame_rfc3411_snmp_community_brute_force[] = { 0x08, 0x00, 0x30, 0x19, 0x02, 0x01, 0x00, 0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c', 0xA0, 0x0C, 0x02, 0x04, 0x12, 0x34, 0x56, 0x78, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x00 };
static uint8_t test_frame_rfc3411_snmp_version_downgrade[] = { 0x08, 0x01, 0x30, 0x15, 0x02, 0x01, 0xFF, 0x04, 0x06, 'p', 'r', 'i', 'v', 'a', 't', 0xA1, 0x08, 0x02, 0x01, 0x01, 0x04, 0x00, 0x04, 0x00 };
static uint8_t test_frame_rfc3411_snmp_oid_traversal[] = { 0x08, 0x02, 0x30, 0x20, 0x02, 0x01, 0x01, 0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c', 0xA0, 0x13, 0x02, 0x04, 0x00, 0x00, 0x00, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x05, 0x30, 0x03, 0x06, 0x01, 0x00 };

/* RFC 3550 - Real-time Transport Protocol (RTP) Violations */
static uint8_t test_frame_rfc3550_rtp_sequence_prediction[] = { 0x08, 0x00, 0x80, 0x08, 0x00, 0x01, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC };
static uint8_t test_frame_rfc3550_rtp_timestamp_manipulation[] = { 0x08, 0x01, 0x80, 0x60, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00 };
static uint8_t test_frame_rfc3550_rtp_ssrc_collision[] = { 0x08, 0x02, 0x80, 0x08, 0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78 };

/* RFC 3748 - Extensible Authentication Protocol (EAP) Enhanced Violations */
static uint8_t test_frame_rfc3748_eap_tls_fragment_bomb[] = { 0x08, 0x00, 0x02, 0x01, 0x00, 0xFF, 0x0D, 0xC0, 0xFF, 0xFF, 0xFF, 0xFF };
static uint8_t test_frame_rfc3748_eap_method_chaining_attack[] = { 0x08, 0x01, 0x02, 0x02, 0x00, 0x08, 0x04, 0x10, 0x00, 0x06, 0x19, 0x00 };
static uint8_t test_frame_rfc3748_eap_identity_disclosure[] = { 0x08, 0x02, 0x02, 0x01, 0x00, 0x10, 0x01, 'a', 'd', 'm', 'i', 'n', '@', 's', 'e', 'c', 'r', 'e', 't', '.', 'c', 'o', 'm' };

/* RFC 4271 - Border Gateway Protocol (BGP-4) Violations */
static uint8_t test_frame_rfc4271_bgp_route_hijack[] = { 0x08, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x13, 0x02 };
static uint8_t test_frame_rfc4271_bgp_path_attribute_manipulation[] = { 0x08, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x17, 0x02, 0x00, 0x00, 0x00, 0x00 };
static uint8_t test_frame_rfc4271_bgp_as_path_prepending_attack[] = { 0x08, 0x02, 0x40, 0x01, 0x01, 0x00, 0x40, 0x02, 0xFF, 0x02, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

/* RFC 4347 - Datagram Transport Layer Security (DTLS) Violations */
static uint8_t test_frame_rfc4347_dtls_replay_attack[] = { 0x08, 0x00, 0x16, 0xFE, 0xFD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
static uint8_t test_frame_rfc4347_dtls_fragmentation_attack[] = { 0x08, 0x01, 0x16, 0xFE, 0xFD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01 };
static uint8_t test_frame_rfc4347_dtls_cookie_manipulation[] = { 0x08, 0x02, 0x16, 0xFE, 0xFD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0C, 0xFF, 'f', 'a', 'k', 'e', '_', 'c', 'o', 'o', 'k', 'i', 'e' };

/* RFC 4456 - BGP Route Reflection Violations */
static uint8_t test_frame_rfc4456_bgp_route_reflection_loop[] = { 0x08, 0x00, 0x80, 0x04, 0x04, 0x00, 0x00, 0x00, 0x64, 0x80, 0x0A, 0x04, 0x01, 0x01, 0x01, 0x01 };
static uint8_t test_frame_rfc4456_bgp_cluster_id_spoof[] = { 0x08, 0x01, 0x80, 0x0A, 0x04, 0xFF, 0xFF, 0xFF, 0xFF };
static uint8_t test_frame_rfc4456_bgp_originator_id_manipulation[] = { 0x08, 0x02, 0x80, 0x09, 0x04, 0x00, 0x00, 0x00, 0x00 };

/* RFC 5321 - Enhanced SMTP Protocol Violations */
static uint8_t test_frame_rfc5321_smtp_command_injection_enhanced[] = { 0x08, 0x00, 'M', 'A', 'I', 'L', ' ', 'F', 'R', 'O', 'M', ':', '<', 'u', 's', 'e', 'r', '>', '\r', '\n', 'R', 'C', 'P', 'T', ' ', 'T', 'O', ':', '<', 'v', 'i', 'c', 't', 'i', 'm', '>' };
static uint8_t test_frame_rfc5321_smtp_auth_bypass[] = { 0x08, 0x02, 'A', 'U', 'T', 'H', ' ', 'P', 'L', 'A', 'I', 'N', ' ', 'A', 'G', 'F', 'k', 'b', 'W', 'l', 'u', 'A', 'G', 'F', 'k', 'b', 'W', 'l', 'u' };

/* RFC 5389 - Session Traversal Utilities for NAT (STUN) Violations */
static uint8_t test_frame_rfc5389_stun_message_integrity_bypass[] = { 0x08, 0x00, 0x00, 0x01, 0x00, 0x08, 0x21, 0x12, 0xA4, 0x42, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x00, 0x08, 0x00, 0x14 };
static uint8_t test_frame_rfc5389_stun_attribute_overflow[] = { 0x08, 0x01, 0x01, 0x01, 0xFF, 0xFF, 0x21, 0x12, 0xA4, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
static uint8_t test_frame_rfc5389_stun_xor_mapped_address_confusion[] = { 0x08, 0x02, 0x00, 0x01, 0x00, 0x0C, 0x21, 0x12, 0xA4, 0x42, 0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0xA1, 0x47, 0x01, 0x13 };

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

/* DATAGRAM frame with LEN bit set, Length is 0, and no data. */
static uint8_t test_frame_datagram_with_len_empty[] = {
    0x31, /* Type: DATAGRAM, LEN=1 */
    0x00  /* Length: 0 */
};

/* DATAGRAM frame with LEN bit set, Length is 4 encoded non-canonically as 2 bytes. */
static uint8_t test_frame_datagram_len_non_canon[] = {
    0x31,       /* Type: DATAGRAM, LEN=1 */
    0x40, 0x04, /* Length: 4 (2-byte varint) */
    0x64, 0x61, 0x74, 0x61 /* Data: "data" */
};

/* DATAGRAM frame with LEN bit set, moderately large length, and sample data. */
static uint8_t test_frame_datagram_very_large[] = {
    0x31,       /* Type: DATAGRAM, LEN=1 */
    0x40, 0xFA, /* Length: 250 (varint) */
    'l', 'a', 'r', 'g', 'e', '_', 'd', 'a', 't', 'a', 'g', 'r', 'a', 'm', '_', 't', 'e', 's', 't', '_', 'd', 'a', 't', 'a'
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

/* STREAM SID: Non-Canonical Varints */
static uint8_t test_stream_sid_0_nc2[] = {0x08, 0x40, 0x00, 'S','I','D','n','c'};
static uint8_t test_stream_sid_0_nc4[] = {0x08, 0x80, 0x00, 0x00, 0x00, 'S','I','D','n','c'};
static uint8_t test_stream_sid_0_nc8[] = {0x08, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 'S','I','D','n','c'};
static uint8_t test_stream_sid_1_nc2[] = {0x08, 0x40, 0x01, 'S','I','D','n','c'};
static uint8_t test_stream_sid_1_nc4[] = {0x08, 0x80, 0x00, 0x00, 0x01, 'S','I','D','n','c'};
static uint8_t test_stream_sid_1_nc8[] = {0x08, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 'S','I','D','n','c'};
static uint8_t test_stream_sid_5_nc2[] = {0x08, 0x40, 0x05, 'S','I','D','n','c'};
static uint8_t test_stream_sid_5_nc4[] = {0x08, 0x80, 0x00, 0x00, 0x05, 'S','I','D','n','c'};
static uint8_t test_stream_sid_5_nc8[] = {0x08, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 'S','I','D','n','c'};

/* STREAM Offset: Non-Canonical Varints */
static uint8_t test_stream_off_0_nc2[] = {0x0C, 0x01, 0x40, 0x00, 'O','F','F','n','c'};
static uint8_t test_stream_off_0_nc4[] = {0x0C, 0x01, 0x80, 0x00, 0x00, 0x00, 'O','F','F','n','c'};
static uint8_t test_stream_off_0_nc8[] = {0x0C, 0x01, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 'O','F','F','n','c'};
static uint8_t test_stream_off_1_nc2[] = {0x0C, 0x01, 0x40, 0x01, 'O','F','F','n','c'};
static uint8_t test_stream_off_1_nc4[] = {0x0C, 0x01, 0x80, 0x00, 0x00, 0x01, 'O','F','F','n','c'};
static uint8_t test_stream_off_1_nc8[] = {0x0C, 0x01, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 'O','F','F','n','c'};
static uint8_t test_stream_off_5_nc2[] = {0x0C, 0x01, 0x40, 0x05, 'O','F','F','n','c'};
static uint8_t test_stream_off_5_nc4[] = {0x0C, 0x01, 0x80, 0x00, 0x00, 0x05, 'O','F','F','n','c'};
static uint8_t test_stream_off_5_nc8[] = {0x0C, 0x01, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 'O','F','F','n','c'};

/* STREAM Length: Non-Canonical Varints */
static uint8_t test_stream_len_0_nc2[] = {0x0A, 0x01, 0x40, 0x00};
static uint8_t test_stream_len_0_nc4[] = {0x0A, 0x01, 0x80, 0x00, 0x00, 0x00};
static uint8_t test_stream_len_0_nc8[] = {0x0A, 0x01, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static uint8_t test_stream_len_1_nc2[] = {0x0A, 0x01, 0x40, 0x01, 'L'};
static uint8_t test_stream_len_1_nc4[] = {0x0A, 0x01, 0x80, 0x00, 0x00, 0x01, 'L'};
static uint8_t test_stream_len_1_nc8[] = {0x0A, 0x01, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 'L'};
static uint8_t test_stream_len_4_nc2[] = {0x0A, 0x01, 0x40, 0x04, 'L','E','N','n'};
static uint8_t test_stream_len_4_nc4[] = {0x0A, 0x01, 0x80, 0x00, 0x00, 0x04, 'L','E','N','n'};
static uint8_t test_stream_len_4_nc8[] = {0x0A, 0x01, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 'L','E','N','n'};

/* ACK Largest Acknowledged: Non-Canonical Varints */
static uint8_t test_ack_largest_ack_0_nc2[] = {0x02, 0x40, 0x00, 0x00, 0x01, 0x00};
static uint8_t test_ack_largest_ack_0_nc4[] = {0x02, 0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00};
static uint8_t test_ack_largest_ack_0_nc8[] = {0x02, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00};
static uint8_t test_ack_largest_ack_1_nc2[] = {0x02, 0x40, 0x01, 0x00, 0x01, 0x00};
static uint8_t test_ack_largest_ack_1_nc4[] = {0x02, 0x80, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00};
static uint8_t test_ack_largest_ack_1_nc8[] = {0x02, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00};
static uint8_t test_ack_largest_ack_5_nc2[] = {0x02, 0x40, 0x05, 0x00, 0x01, 0x00};
static uint8_t test_ack_largest_ack_5_nc4[] = {0x02, 0x80, 0x00, 0x00, 0x05, 0x00, 0x01, 0x00};
static uint8_t test_ack_largest_ack_5_nc8[] = {0x02, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x01, 0x00};

/* ACK Delay: Non-Canonical Varints */
static uint8_t test_ack_delay_0_nc2[] = {0x02, 0x0A, 0x40, 0x00, 0x01, 0x00};
static uint8_t test_ack_delay_0_nc4[] = {0x02, 0x0A, 0x80, 0x00, 0x00, 0x00, 0x01, 0x00};
static uint8_t test_ack_delay_0_nc8[] = {0x02, 0x0A, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00};
static uint8_t test_ack_delay_1_nc2[] = {0x02, 0x0A, 0x40, 0x01, 0x01, 0x00};
static uint8_t test_ack_delay_1_nc4[] = {0x02, 0x0A, 0x80, 0x00, 0x00, 0x01, 0x01, 0x00};
static uint8_t test_ack_delay_1_nc8[] = {0x02, 0x0A, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00};
static uint8_t test_ack_delay_5_nc2[] = {0x02, 0x0A, 0x40, 0x05, 0x01, 0x00};
static uint8_t test_ack_delay_5_nc4[] = {0x02, 0x0A, 0x80, 0x00, 0x00, 0x05, 0x01, 0x00};
static uint8_t test_ack_delay_5_nc8[] = {0x02, 0x0A, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x01, 0x00};

/* ACK Range Count: Non-Canonical Varints */
static uint8_t test_ack_range_count_1_nc2[] = {0x02, 0x0A, 0x00, 0x40, 0x01, 0x00};
static uint8_t test_ack_range_count_1_nc4[] = {0x02, 0x0A, 0x00, 0x80, 0x00, 0x00, 0x01, 0x00};
static uint8_t test_ack_range_count_1_nc8[] = {0x02, 0x0A, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00};
static uint8_t test_ack_range_count_2_nc2[] = {0x02, 0x0A, 0x00, 0x40, 0x02, 0x00, 0x00, 0x00};
static uint8_t test_ack_range_count_2_nc4[] = {0x02, 0x0A, 0x00, 0x80, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00};
static uint8_t test_ack_range_count_2_nc8[] = {0x02, 0x0A, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00};

/* ACK First ACK Range: Non-Canonical Varints */
static uint8_t test_ack_first_range_0_nc2[] = {0x02, 0x0A, 0x00, 0x01, 0x40, 0x00};
static uint8_t test_ack_first_range_0_nc4[] = {0x02, 0x0A, 0x00, 0x01, 0x80, 0x00, 0x00, 0x00};
static uint8_t test_ack_first_range_0_nc8[] = {0x02, 0x0A, 0x00, 0x01, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static uint8_t test_ack_first_range_1_nc2[] = {0x02, 0x0A, 0x00, 0x01, 0x40, 0x01};
static uint8_t test_ack_first_range_1_nc4[] = {0x02, 0x0A, 0x00, 0x01, 0x80, 0x00, 0x00, 0x01};
static uint8_t test_ack_first_range_1_nc8[] = {0x02, 0x0A, 0x00, 0x01, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
static uint8_t test_ack_first_range_5_nc2[] = {0x02, 0x0A, 0x00, 0x01, 0x40, 0x05};
static uint8_t test_ack_first_range_5_nc4[] = {0x02, 0x0A, 0x00, 0x01, 0x80, 0x00, 0x00, 0x05};
static uint8_t test_ack_first_range_5_nc8[] = {0x02, 0x0A, 0x00, 0x01, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05};

/* ACK Gap: Non-Canonical Varints */
static uint8_t test_ack_gap_0_nc2[] = {0x02, 0x14, 0x00, 0x02, 0x01, 0x40, 0x00, 0x00};
static uint8_t test_ack_gap_0_nc4[] = {0x02, 0x14, 0x00, 0x02, 0x01, 0x80, 0x00, 0x00, 0x00, 0x00};
static uint8_t test_ack_gap_0_nc8[] = {0x02, 0x14, 0x00, 0x02, 0x01, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static uint8_t test_ack_gap_1_nc2[] = {0x02, 0x14, 0x00, 0x02, 0x01, 0x40, 0x01, 0x00};
static uint8_t test_ack_gap_1_nc4[] = {0x02, 0x14, 0x00, 0x02, 0x01, 0x80, 0x00, 0x00, 0x01, 0x00};
static uint8_t test_ack_gap_1_nc8[] = {0x02, 0x14, 0x00, 0x02, 0x01, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00};
static uint8_t test_ack_gap_2_nc2[] = {0x02, 0x14, 0x00, 0x02, 0x01, 0x40, 0x02, 0x00};
static uint8_t test_ack_gap_2_nc4[] = {0x02, 0x14, 0x00, 0x02, 0x01, 0x80, 0x00, 0x00, 0x02, 0x00};
static uint8_t test_ack_gap_2_nc8[] = {0x02, 0x14, 0x00, 0x02, 0x01, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00};

/* ACK Range Length: Non-Canonical Varints */
static uint8_t test_ack_range_len_0_nc2[] = {0x02, 0x14, 0x00, 0x02, 0x01, 0x01, 0x40, 0x00};
static uint8_t test_ack_range_len_0_nc4[] = {0x02, 0x14, 0x00, 0x02, 0x01, 0x01, 0x80, 0x00, 0x00, 0x00};
static uint8_t test_ack_range_len_0_nc8[] = {0x02, 0x14, 0x00, 0x02, 0x01, 0x01, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static uint8_t test_ack_range_len_1_nc2[] = {0x02, 0x14, 0x00, 0x02, 0x01, 0x01, 0x40, 0x01};
static uint8_t test_ack_range_len_1_nc4[] = {0x02, 0x14, 0x00, 0x02, 0x01, 0x01, 0x80, 0x00, 0x00, 0x01};
static uint8_t test_ack_range_len_1_nc8[] = {0x02, 0x14, 0x00, 0x02, 0x01, 0x01, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
static uint8_t test_ack_range_len_5_nc2[] = {0x02, 0x14, 0x00, 0x02, 0x01, 0x01, 0x40, 0x05};
static uint8_t test_ack_range_len_5_nc4[] = {0x02, 0x14, 0x00, 0x02, 0x01, 0x01, 0x80, 0x00, 0x00, 0x05};
static uint8_t test_ack_range_len_5_nc8[] = {0x02, 0x14, 0x00, 0x02, 0x01, 0x01, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05};

/* RESET_STREAM Stream ID: Non-Canonical Varints */
static uint8_t test_reset_stream_sid_0_nc2[] = {0x04, 0x40, 0x00, 0x00, 0x00};
static uint8_t test_reset_stream_sid_0_nc4[] = {0x04, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00};
static uint8_t test_reset_stream_sid_0_nc8[] = {0x04, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static uint8_t test_reset_stream_sid_1_nc2[] = {0x04, 0x40, 0x01, 0x00, 0x00};
static uint8_t test_reset_stream_sid_1_nc4[] = {0x04, 0x80, 0x00, 0x00, 0x01, 0x00, 0x00};
static uint8_t test_reset_stream_sid_1_nc8[] = {0x04, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00};
static uint8_t test_reset_stream_sid_5_nc2[] = {0x04, 0x40, 0x05, 0x00, 0x00};
static uint8_t test_reset_stream_sid_5_nc4[] = {0x04, 0x80, 0x00, 0x00, 0x05, 0x00, 0x00};
static uint8_t test_reset_stream_sid_5_nc8[] = {0x04, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00};

/* RESET_STREAM App Error Code: Non-Canonical Varints */
static uint8_t test_reset_stream_err_0_nc2[] = {0x04, 0x01, 0x40, 0x00, 0x00};
static uint8_t test_reset_stream_err_0_nc4[] = {0x04, 0x01, 0x80, 0x00, 0x00, 0x00, 0x00};
static uint8_t test_reset_stream_err_0_nc8[] = {0x04, 0x01, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static uint8_t test_reset_stream_err_1_nc2[] = {0x04, 0x01, 0x40, 0x01, 0x00};
static uint8_t test_reset_stream_err_1_nc4[] = {0x04, 0x01, 0x80, 0x00, 0x00, 0x01, 0x00};
static uint8_t test_reset_stream_err_1_nc8[] = {0x04, 0x01, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00};
static uint8_t test_reset_stream_err_5_nc2[] = {0x04, 0x01, 0x40, 0x05, 0x00};
static uint8_t test_reset_stream_err_5_nc4[] = {0x04, 0x01, 0x80, 0x00, 0x00, 0x05, 0x00};
static uint8_t test_reset_stream_err_5_nc8[] = {0x04, 0x01, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00};

/* RESET_STREAM Final Size: Non-Canonical Varints */
static uint8_t test_reset_stream_final_0_nc2[] = {0x04, 0x01, 0x00, 0x40, 0x00};
static uint8_t test_reset_stream_final_0_nc4[] = {0x04, 0x01, 0x00, 0x80, 0x00, 0x00, 0x00};
static uint8_t test_reset_stream_final_0_nc8[] = {0x04, 0x01, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static uint8_t test_reset_stream_final_1_nc2[] = {0x04, 0x01, 0x00, 0x40, 0x01};
static uint8_t test_reset_stream_final_1_nc4[] = {0x04, 0x01, 0x00, 0x80, 0x00, 0x00, 0x01};
static uint8_t test_reset_stream_final_1_nc8[] = {0x04, 0x01, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
static uint8_t test_reset_stream_final_5_nc2[] = {0x04, 0x01, 0x00, 0x40, 0x05};
static uint8_t test_reset_stream_final_5_nc4[] = {0x04, 0x01, 0x00, 0x80, 0x00, 0x00, 0x05};
static uint8_t test_reset_stream_final_5_nc8[] = {0x04, 0x01, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05};

/* STOP_SENDING Stream ID: Non-Canonical Varints */
static uint8_t test_stop_sending_sid_0_nc2[] = {0x05, 0x40, 0x00, 0x00};
static uint8_t test_stop_sending_sid_0_nc4[] = {0x05, 0x80, 0x00, 0x00, 0x00, 0x00};
static uint8_t test_stop_sending_sid_0_nc8[] = {0x05, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static uint8_t test_stop_sending_sid_1_nc2[] = {0x05, 0x40, 0x01, 0x00};
static uint8_t test_stop_sending_sid_1_nc4[] = {0x05, 0x80, 0x00, 0x00, 0x01, 0x00};
static uint8_t test_stop_sending_sid_1_nc8[] = {0x05, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00};
static uint8_t test_stop_sending_sid_5_nc2[] = {0x05, 0x40, 0x05, 0x00};
static uint8_t test_stop_sending_sid_5_nc4[] = {0x05, 0x80, 0x00, 0x00, 0x05, 0x00};
static uint8_t test_stop_sending_sid_5_nc8[] = {0x05, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00};

/* STOP_SENDING App Error Code: Non-Canonical Varints */
static uint8_t test_stop_sending_err_0_nc2[] = {0x05, 0x01, 0x40, 0x00};
static uint8_t test_stop_sending_err_0_nc4[] = {0x05, 0x01, 0x80, 0x00, 0x00, 0x00};
static uint8_t test_stop_sending_err_0_nc8[] = {0x05, 0x01, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static uint8_t test_stop_sending_err_1_nc2[] = {0x05, 0x01, 0x40, 0x01};
static uint8_t test_stop_sending_err_1_nc4[] = {0x05, 0x01, 0x80, 0x00, 0x00, 0x01};
static uint8_t test_stop_sending_err_1_nc8[] = {0x05, 0x01, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
static uint8_t test_stop_sending_err_5_nc2[] = {0x05, 0x01, 0x40, 0x05};
static uint8_t test_stop_sending_err_5_nc4[] = {0x05, 0x01, 0x80, 0x00, 0x00, 0x05};
static uint8_t test_stop_sending_err_5_nc8[] = {0x05, 0x01, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05};

/* MAX_DATA Maximum Data: Non-Canonical Varints */
static uint8_t test_max_data_0_nc2[] = {0x10, 0x40, 0x00};
static uint8_t test_max_data_0_nc4[] = {0x10, 0x80, 0x00, 0x00, 0x00};
static uint8_t test_max_data_0_nc8[] = {0x10, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static uint8_t test_max_data_1_nc2[] = {0x10, 0x40, 0x01};
static uint8_t test_max_data_1_nc4[] = {0x10, 0x80, 0x00, 0x00, 0x01};
static uint8_t test_max_data_1_nc8[] = {0x10, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
static uint8_t test_max_data_10_nc2[] = {0x10, 0x40, 0x0A};
static uint8_t test_max_data_10_nc4[] = {0x10, 0x80, 0x00, 0x00, 0x0A};
static uint8_t test_max_data_10_nc8[] = {0x10, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A};

/* MAX_STREAM_DATA Stream ID: Non-Canonical Varints */
static uint8_t test_max_sdata_sid_0_nc2[] = {0x11, 0x40, 0x00, 0x64};
static uint8_t test_max_sdata_sid_0_nc4[] = {0x11, 0x80, 0x00, 0x00, 0x00, 0x64};
static uint8_t test_max_sdata_sid_0_nc8[] = {0x11, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64};
static uint8_t test_max_sdata_sid_1_nc2[] = {0x11, 0x40, 0x01, 0x64};
static uint8_t test_max_sdata_sid_1_nc4[] = {0x11, 0x80, 0x00, 0x00, 0x01, 0x64};
static uint8_t test_max_sdata_sid_1_nc8[] = {0x11, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x64};
static uint8_t test_max_sdata_sid_5_nc2[] = {0x11, 0x40, 0x05, 0x64};
static uint8_t test_max_sdata_sid_5_nc4[] = {0x11, 0x80, 0x00, 0x00, 0x05, 0x64};
static uint8_t test_max_sdata_sid_5_nc8[] = {0x11, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x64};

/* MAX_STREAM_DATA Max Value: Non-Canonical Varints */
static uint8_t test_max_sdata_val_0_nc2[] = {0x11, 0x01, 0x40, 0x00};
static uint8_t test_max_sdata_val_0_nc4[] = {0x11, 0x01, 0x80, 0x00, 0x00, 0x00};
static uint8_t test_max_sdata_val_0_nc8[] = {0x11, 0x01, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static uint8_t test_max_sdata_val_1_nc2[] = {0x11, 0x01, 0x40, 0x01};
static uint8_t test_max_sdata_val_1_nc4[] = {0x11, 0x01, 0x80, 0x00, 0x00, 0x01};
static uint8_t test_max_sdata_val_1_nc8[] = {0x11, 0x01, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
static uint8_t test_max_sdata_val_10_nc2[] = {0x11, 0x01, 0x40, 0x0A};
static uint8_t test_max_sdata_val_10_nc4[] = {0x11, 0x01, 0x80, 0x00, 0x00, 0x0A};
static uint8_t test_max_sdata_val_10_nc8[] = {0x11, 0x01, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A};

/* MAX_STREAMS (Bidi): Non-Canonical Varints */
static uint8_t test_max_streams_bidi_0_nc2[] = {0x12, 0x40, 0x00};
static uint8_t test_max_streams_bidi_0_nc4[] = {0x12, 0x80, 0x00, 0x00, 0x00};
static uint8_t test_max_streams_bidi_0_nc8[] = {0x12, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static uint8_t test_max_streams_bidi_1_nc2[] = {0x12, 0x40, 0x01};
static uint8_t test_max_streams_bidi_1_nc4[] = {0x12, 0x80, 0x00, 0x00, 0x01};
static uint8_t test_max_streams_bidi_1_nc8[] = {0x12, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
static uint8_t test_max_streams_bidi_5_nc2[] = {0x12, 0x40, 0x05};
static uint8_t test_max_streams_bidi_5_nc4[] = {0x12, 0x80, 0x00, 0x00, 0x05};
static uint8_t test_max_streams_bidi_5_nc8[] = {0x12, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05};

/* MAX_STREAMS (Uni): Non-Canonical Varints */
static uint8_t test_max_streams_uni_0_nc2[] = {0x13, 0x40, 0x00};
static uint8_t test_max_streams_uni_0_nc4[] = {0x13, 0x80, 0x00, 0x00, 0x00};
static uint8_t test_max_streams_uni_0_nc8[] = {0x13, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static uint8_t test_max_streams_uni_1_nc2[] = {0x13, 0x40, 0x01};
static uint8_t test_max_streams_uni_1_nc4[] = {0x13, 0x80, 0x00, 0x00, 0x01};
static uint8_t test_max_streams_uni_1_nc8[] = {0x13, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
static uint8_t test_max_streams_uni_5_nc2[] = {0x13, 0x40, 0x05};
static uint8_t test_max_streams_uni_5_nc4[] = {0x13, 0x80, 0x00, 0x00, 0x05};
static uint8_t test_max_streams_uni_5_nc8[] = {0x13, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05};


/* DATA_BLOCKED Maximum Data: Non-Canonical Varints */
static uint8_t test_data_blocked_0_nc2[] = {0x14, 0x40, 0x00};
static uint8_t test_data_blocked_0_nc4[] = {0x14, 0x80, 0x00, 0x00, 0x00};
static uint8_t test_data_blocked_0_nc8[] = {0x14, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static uint8_t test_data_blocked_1_nc2[] = {0x14, 0x40, 0x01};
static uint8_t test_data_blocked_1_nc4[] = {0x14, 0x80, 0x00, 0x00, 0x01};
static uint8_t test_data_blocked_1_nc8[] = {0x14, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
static uint8_t test_data_blocked_10_nc2[] = {0x14, 0x40, 0x0A};
static uint8_t test_data_blocked_10_nc4[] = {0x14, 0x80, 0x00, 0x00, 0x0A};
static uint8_t test_data_blocked_10_nc8[] = {0x14, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A};

/* STREAM_DATA_BLOCKED Stream ID: Non-Canonical Varints */
static uint8_t test_sdata_blocked_sid_0_nc2[] = {0x15, 0x40, 0x00, 0x64};
static uint8_t test_sdata_blocked_sid_0_nc4[] = {0x15, 0x80, 0x00, 0x00, 0x00, 0x64};
static uint8_t test_sdata_blocked_sid_0_nc8[] = {0x15, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64};
static uint8_t test_sdata_blocked_sid_1_nc2[] = {0x15, 0x40, 0x01, 0x64};
static uint8_t test_sdata_blocked_sid_1_nc4[] = {0x15, 0x80, 0x00, 0x00, 0x01, 0x64};
static uint8_t test_sdata_blocked_sid_1_nc8[] = {0x15, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x64};
static uint8_t test_sdata_blocked_sid_5_nc2[] = {0x15, 0x40, 0x05, 0x64};
static uint8_t test_sdata_blocked_sid_5_nc4[] = {0x15, 0x80, 0x00, 0x00, 0x05, 0x64};
static uint8_t test_sdata_blocked_sid_5_nc8[] = {0x15, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x64};

/* STREAM_DATA_BLOCKED Stream Data Limit: Non-Canonical Varints */
static uint8_t test_sdata_blocked_limit_0_nc2[] = {0x15, 0x01, 0x40, 0x00};
static uint8_t test_sdata_blocked_limit_0_nc4[] = {0x15, 0x01, 0x80, 0x00, 0x00, 0x00};
static uint8_t test_sdata_blocked_limit_0_nc8[] = {0x15, 0x01, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static uint8_t test_sdata_blocked_limit_1_nc2[] = {0x15, 0x01, 0x40, 0x01};
static uint8_t test_sdata_blocked_limit_1_nc4[] = {0x15, 0x01, 0x80, 0x00, 0x00, 0x01};
static uint8_t test_sdata_blocked_limit_1_nc8[] = {0x15, 0x01, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
static uint8_t test_sdata_blocked_limit_10_nc2[] = {0x15, 0x01, 0x40, 0x0A};
static uint8_t test_sdata_blocked_limit_10_nc4[] = {0x15, 0x01, 0x80, 0x00, 0x00, 0x0A};
static uint8_t test_sdata_blocked_limit_10_nc8[] = {0x15, 0x01, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A};

/* STREAMS_BLOCKED (Bidi) Maximum Streams: Non-Canonical Varints */
static uint8_t test_streams_blocked_bidi_0_nc2[] = {0x16, 0x40, 0x00};
static uint8_t test_streams_blocked_bidi_0_nc4[] = {0x16, 0x80, 0x00, 0x00, 0x00};
static uint8_t test_streams_blocked_bidi_0_nc8[] = {0x16, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static uint8_t test_streams_blocked_bidi_1_nc2[] = {0x16, 0x40, 0x01};
static uint8_t test_streams_blocked_bidi_1_nc4[] = {0x16, 0x80, 0x00, 0x00, 0x01};
static uint8_t test_streams_blocked_bidi_1_nc8[] = {0x16, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
static uint8_t test_streams_blocked_bidi_5_nc2[] = {0x16, 0x40, 0x05};
static uint8_t test_streams_blocked_bidi_5_nc4[] = {0x16, 0x80, 0x00, 0x00, 0x05};
static uint8_t test_streams_blocked_bidi_5_nc8[] = {0x16, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05};

/* STREAMS_BLOCKED (Uni) Maximum Streams: Non-Canonical Varints */
static uint8_t test_streams_blocked_uni_0_nc2[] = {0x17, 0x40, 0x00};
static uint8_t test_streams_blocked_uni_0_nc4[] = {0x17, 0x80, 0x00, 0x00, 0x00};
static uint8_t test_streams_blocked_uni_0_nc8[] = {0x17, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static uint8_t test_streams_blocked_uni_1_nc2[] = {0x17, 0x40, 0x01};
static uint8_t test_streams_blocked_uni_1_nc4[] = {0x17, 0x80, 0x00, 0x00, 0x01};
static uint8_t test_streams_blocked_uni_1_nc8[] = {0x17, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
static uint8_t test_streams_blocked_uni_5_nc2[] = {0x17, 0x40, 0x05};
static uint8_t test_streams_blocked_uni_5_nc4[] = {0x17, 0x80, 0x00, 0x00, 0x05};
static uint8_t test_streams_blocked_uni_5_nc8[] = {0x17, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05};

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

/* Non-Canonical Field Encodings (RFC 9000) */
/* DATA_BLOCKED Frame Variations (Type 0x14): */
static uint8_t test_frame_data_blocked_val_non_canon_2byte[] = {picoquic_frame_type_data_blocked, 0x40, 0x64};
/* STREAM_DATA_BLOCKED Frame Variations (Type 0x15): */
static uint8_t test_frame_sdb_sid_non_canon_4byte[] = {picoquic_frame_type_stream_data_blocked, 0x80, 0x00, 0x00, 0x01, 0x41, 0x00};
static uint8_t test_frame_sdb_val_non_canon_8byte[] = {picoquic_frame_type_stream_data_blocked, 0x01, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64};
/* STREAMS_BLOCKED Frame Variations (Bidirectional - Type 0x16): */
static uint8_t test_frame_streams_blocked_bidi_non_canon_8byte[] = {picoquic_frame_type_streams_blocked_bidir, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A};
/* STREAMS_BLOCKED Frame Variations (Unidirectional - Type 0x17): */
static uint8_t test_frame_streams_blocked_uni_non_canon_2byte[] = {picoquic_frame_type_streams_blocked_unidir, 0x40, 0x64};
/* NEW_CONNECTION_ID Frame Variations (Type 0x18): */
static uint8_t test_frame_ncid_seq_non_canon_2byte[] = {picoquic_frame_type_new_connection_id, 0x40, 0x01, 0x00, 0x08, 0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA, 0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB};
static uint8_t test_frame_ncid_ret_non_canon_4byte[] = {picoquic_frame_type_new_connection_id, 0x01, 0x80, 0x00, 0x00, 0x00, 0x08, 0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA, 0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB};
/* RETIRE_CONNECTION_ID Frame Variations (Type 0x19): */
static uint8_t test_frame_retire_cid_seq_non_canon_4byte[] = {picoquic_frame_type_retire_connection_id, 0x80, 0x00, 0x00, 0x01};
/* CONNECTION_CLOSE Frame Variations (Transport Error - Type 0x1c): */
static uint8_t test_frame_conn_close_ec_non_canon[] = {picoquic_frame_type_connection_close, 0x40, 0x01, 0x00, 0x00};
/* test_frame_conn_close_ft_non_canon is already defined as {0x1c, 0x00, 0x40, 0x08, 0x00} */
static uint8_t test_frame_conn_close_rlen_non_canon[] = {picoquic_frame_type_connection_close, 0x00, 0x00, 0x40, 0x04, 't', 'e', 's', 't'};
/* CONNECTION_CLOSE Frame Variations (Application Error - Type 0x1d): */
static uint8_t test_frame_conn_close_app_ec_non_canon[] = {picoquic_frame_type_application_close, 0x80, 0x00, 0x01, 0x01, 0x00};
static uint8_t test_frame_conn_close_app_rlen_non_canon_2byte[] = {picoquic_frame_type_application_close, 0x00, 0x40, 0x05, 't', 'e', 's', 't', '!'};

/* CRYPTO Frame Variations (Type 0x06) */
static uint8_t test_frame_crypto_offset_non_canon_4byte[] = {picoquic_frame_type_crypto_hs, 0x80, 0x00, 0x00, 0x0A, 0x04, 't', 'e', 's', 't'};
static uint8_t test_frame_crypto_len_non_canon_4byte[] = {picoquic_frame_type_crypto_hs, 0x0A, 0x80, 0x00, 0x00, 0x04, 't', 'e', 's', 't'};
/* NEW_TOKEN Frame Variations (Type 0x07) */
static uint8_t test_frame_new_token_len_non_canon_4byte[] = {picoquic_frame_type_new_token, 0x80, 0x00, 0x00, 0x08, '1', '2', '3', '4', '5', '6', '7', '8'};
/* MAX_DATA Frame Variations (Type 0x10) */
static uint8_t test_frame_max_data_non_canon_8byte[] = {picoquic_frame_type_max_data, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00};
/* MAX_STREAM_DATA Frame Variations (Type 0x11) */
static uint8_t test_frame_max_stream_data_sid_non_canon_2byte[] = {picoquic_frame_type_max_stream_data, 0x40, 0x01, 0x44, 0x00};
static uint8_t test_frame_max_stream_data_val_non_canon_4byte[] = {picoquic_frame_type_max_stream_data, 0x01, 0x80, 0x00, 0x01, 0x00};
/* MAX_STREAMS Frame Variations (Bidirectional - Type 0x12) */
static uint8_t test_frame_max_streams_bidi_non_canon_2byte[] = {picoquic_frame_type_max_streams_bidir, 0x40, 0x0A};
static uint8_t test_frame_max_streams_bidi_non_canon_8byte[] = {picoquic_frame_type_max_streams_bidir, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05};
/* MAX_STREAMS Frame Variations (Unidirectional - Type 0x13) */
static uint8_t test_frame_max_streams_uni_non_canon_4byte[] = {picoquic_frame_type_max_streams_unidir, 0x80, 0x00, 0x00, 0x64};

/* ACK, RESET_STREAM, STOP_SENDING Frame Variations (RFC 9000) */
/* ACK Frame Variations (Type 0x03 for ECN) */
static uint8_t test_frame_ack_ecn_ect0_large[] = {0x03, 0x0A, 0x00, 0x01, 0x00, 0x3F, 0x00, 0x00};
static uint8_t test_frame_ack_ecn_ect1_large[] = {0x03, 0x0A, 0x00, 0x01, 0x00, 0x00, 0x7F, 0xFF, 0x00};
static uint8_t test_frame_ack_ecn_ce_large[] = {0x03, 0x0A, 0x00, 0x01, 0x00, 0x00, 0x00, 0xBF, 0xFF, 0xFF, 0xFF};
static uint8_t test_frame_ack_ecn_all_large[] = {0x03, 0x0A, 0x00, 0x01, 0x00, 0x3F, 0x3F, 0x3F};
static uint8_t test_frame_ack_delay_non_canon[] = {picoquic_frame_type_ack, 0x05, 0x40, 0x0A, 0x01, 0x00};
static uint8_t test_frame_ack_range_count_non_canon[] = {picoquic_frame_type_ack, 0x05, 0x00, 0x40, 0x01, 0x00};
static uint8_t test_frame_ack_first_ack_range_non_canon[] = {picoquic_frame_type_ack, 0x05, 0x00, 0x01, 0x40, 0x00};
static uint8_t test_frame_ack_gap_non_canon[] = {picoquic_frame_type_ack, 0x14, 0x00, 0x02, 0x01, 0x40, 0x01, 0x01};

/* RESET_STREAM Frame Variations (Type 0x04) */
static uint8_t test_frame_reset_stream_app_err_non_canon[] = {picoquic_frame_type_reset_stream, 0x01, 0x80, 0x00, 0x01, 0x01, 0x64};
static uint8_t test_frame_reset_stream_final_size_non_canon_8byte[] = {picoquic_frame_type_reset_stream, 0x01, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xE8};

/* STOP_SENDING Frame Variations (Type 0x05) */
static uint8_t test_frame_stop_sending_app_err_non_canon[] = {picoquic_frame_type_stop_sending, 0x01, 0x80, 0x00, 0x01, 0x01};

/* STREAM Frame Variations (RFC 9000, Section 19.8) */
/* Type 0x08 (OFF=0, LEN=0, FIN=0) */
static uint8_t test_stream_0x08_minimal[] = {0x08, 0x01};
static uint8_t test_stream_0x08_sid_non_canon[] = {0x08, 0x40, 0x01, 'h', 'i'};
static uint8_t test_stream_0x08_data_long[] = {0x08, 0x02, 'l', 'o', 'n', 'g', 's', 't', 'r', 'e', 'a', 'm', 'd', 'a', 't', 'a'};
/* Type 0x09 (OFF=0, LEN=0, FIN=1) */
static uint8_t test_stream_0x09_minimal[] = {0x09, 0x01};
static uint8_t test_stream_0x09_sid_non_canon[] = {0x09, 0x40, 0x01, 'f', 'i', 'n'};
/* Type 0x0A (OFF=0, LEN=1, FIN=0) */
static uint8_t test_stream_0x0A_len_zero_no_data[] = {0x0A, 0x01, 0x00};
static uint8_t test_stream_0x0A_len_zero_with_data[] = {0x0A, 0x02, 0x00, 'e', 'x', 't', 'r', 'a'};
static uint8_t test_stream_0x0A_len_small[] = {0x0A, 0x03, 0x01, 'd'};
static uint8_t test_stream_0x0A_len_large[] = {0x0A, 0x04, 0x40, 0xC8, 's', 'o', 'm', 'e', 'd', 'a', 't', 'a'};
static uint8_t test_stream_0x0A_sid_non_canon[] = {0x0A, 0x40, 0x01, 0x04, 't', 'e', 's', 't'};
static uint8_t test_stream_0x0A_len_non_canon[] = {0x0A, 0x02, 0x40, 0x04, 't', 'e', 's', 't'};
/* Type 0x0B (OFF=0, LEN=1, FIN=1) */
static uint8_t test_stream_0x0B_len_zero_no_data_fin[] = {0x0B, 0x01, 0x00};
static uint8_t test_stream_0x0B_len_non_canon_fin[] = {0x0B, 0x02, 0x40, 0x03, 'e', 'n', 'd'};
/* Type 0x0C (OFF=1, LEN=0, FIN=0) */
static uint8_t test_stream_0x0C_offset_zero[] = {0x0C, 0x01, 0x00, 'd', 'a', 't', 'a'};
static uint8_t test_stream_0x0C_offset_large[] = {0x0C, 0x02, 0x40, 0xC8, 'd', 'a', 't', 'a'};
static uint8_t test_stream_0x0C_sid_non_canon[] = {0x0C, 0x40, 0x01, 0x0A, 'o', 'f', 'f'};
static uint8_t test_stream_0x0C_offset_non_canon[] = {0x0C, 0x02, 0x40, 0x0A, 'o', 'f', 'f'};
/* Type 0x0D (OFF=1, LEN=0, FIN=1) */
static uint8_t test_stream_0x0D_offset_zero_fin[] = {0x0D, 0x01, 0x00, 'l', 'a', 's', 't'};
static uint8_t test_stream_0x0D_offset_non_canon_fin[] = {0x0D, 0x02, 0x40, 0x05, 'f', 'i', 'n', 'a', 'l'};
/* Type 0x0E (OFF=1, LEN=1, FIN=0) */
static uint8_t test_stream_0x0E_all_fields_present[] = {0x0E, 0x01, 0x0A, 0x04, 'd', 'a', 't', 'a'};
static uint8_t test_stream_0x0E_all_non_canon[] = {0x0E, 0x40, 0x01, 0x40, 0x0A, 0x40, 0x04, 't', 'e', 's', 't'};
/* Type 0x0F (OFF=1, LEN=1, FIN=1) */
static uint8_t test_stream_0x0F_all_fields_fin[] = {0x0F, 0x01, 0x0A, 0x07, 't', 'h', 'e', ' ', 'e', 'n', 'd'};
static uint8_t test_stream_0x0F_all_non_canon_fin[] = {0x0F, 0x40, 0x01, 0x40, 0x0A, 0x40, 0x04, 'd', 'o', 'n', 'e'};

/* Application Protocol Payloads (HTTP/3, DoQ) */
/* HTTP/3 Frame Payloads */
static uint8_t test_h3_frame_data_payload[] = {0x00, 0x04, 0x74, 0x65, 0x73, 0x74}; /* Type 0x00 (DATA), Length 4, "test" */
static uint8_t test_h3_frame_headers_payload_simple[] = {0x01, 0x01, 0x99}; /* Type 0x01 (HEADERS), Length 1, QPACK :method: GET */
static uint8_t test_h3_frame_settings_payload_empty[] = {0x04, 0x00}; /* Type 0x04 (SETTINGS), Length 0 */
static uint8_t test_h3_frame_settings_payload_one_setting[] = {0x04, 0x03, 0x06, 0x44, 0x00}; /* Type 0x04 (SETTINGS), Len 3, ID 0x06, Val 1024 (varint 0x4400) */
static uint8_t test_h3_frame_goaway_payload[] = {0x07, 0x01, 0x00}; /* Type 0x07 (GOAWAY), Length 1, ID 0 */
static uint8_t test_h3_frame_max_push_id_payload[] = {0x0D, 0x01, 0x0A}; /* Type 0x0D (MAX_PUSH_ID), Length 1, ID 10 */
static uint8_t test_h3_frame_cancel_push_payload[] = {0x03, 0x01, 0x03}; /* Type 0x03 (CANCEL_PUSH), Length 1, ID 3 */
static uint8_t test_h3_frame_push_promise_payload_simple[] = {0x05, 0x02, 0x01, 0x99}; /* Type 0x05 (PUSH_PROMISE), Len 2, PushID 1, QPACK :method: GET */

/* HTTP/3 ORIGIN frame draft-ietf-httpbis-origin-frame-00 */
static uint8_t test_frame_h3_origin_val_0x0c[] = { 0x0c };

/* HTTP/3 PRIORITY_UPDATE frame RFC9218 */
static uint8_t test_frame_h3_priority_update_val_0xf0700[] = { 0x80, 0x0F, 0x07, 0x00 };

/* HTTP/3 ORIGIN Frame Payload */
static uint8_t test_h3_frame_origin_payload[] = {
    0x0c, 0x14, 0x00, 0x12, 'h', 't', 't', 'p', ':', '/', '/', 'o', 'r', 'i', 'g', 'i', 'n', '.', 't', 'e', 's', 't'
};

/* HTTP/3 PRIORITY_UPDATE Frame Payloads */
static uint8_t test_h3_frame_priority_update_request_payload[] = {
    0x80, 0x0F, 0x07, 0x00, 0x06, 0x04, 0x75, 0x3d, 0x33, 0x2c, 0x69
};

static uint8_t test_h3_frame_priority_update_placeholder_payload[] = {
    0x80, 0x0F, 0x07, 0x01, 0x04, 0x02, 0x75, 0x3d, 0x35
};
/* H3_DATA Frame Variations */
static uint8_t test_h3_frame_data_empty[] = {0x00, 0x00};
static uint8_t test_h3_frame_data_len_non_canon[] = {0x00, 0x40, 0x04, 't', 'e', 's', 't'};
/* H3_SETTINGS Frame Variations */
static uint8_t test_h3_settings_max_field_section_size_zero[] = {0x04, 0x02, 0x06, 0x00};
static uint8_t test_h3_settings_max_field_section_size_large[] = {0x04, 0x03, 0x06, 0x7F, 0xFF};
static uint8_t test_h3_settings_multiple[] = {0x04, 0x06, 0x06, 0x44, 0x00, 0x21, 0x41, 0x00};
static uint8_t test_h3_settings_id_non_canon[] = {0x04, 0x03, 0x40, 0x06, 0x00};
static uint8_t test_h3_settings_val_non_canon[] = {0x04, 0x03, 0x06, 0x40, 0x0A};
/* H3_GOAWAY Frame Variations */
static uint8_t test_h3_goaway_max_id[] = {0x07, 0x01, 0x3F};
static uint8_t test_h3_goaway_id_non_canon[] = {0x07, 0x02, 0x40, 0x00};
/* H3_MAX_PUSH_ID Frame Variations */
static uint8_t test_h3_max_push_id_zero[] = {0x0D, 0x01, 0x00};
static uint8_t test_h3_max_push_id_non_canon[] = {0x0D, 0x02, 0x40, 0x0A};
/* H3_CANCEL_PUSH Frame Variations */
static uint8_t test_h3_cancel_push_max_id[] = {0x03, 0x02, 0x7F, 0xFF};
static uint8_t test_h3_cancel_push_id_non_canon[] = {0x03, 0x02, 0x40, 0x03};

/* DoQ Message Payload */
static uint8_t test_doq_dns_query_payload[] = {
    0x00, 0x1d, /* Length prefix for DNS message (29 bytes) */
    /* Start of DNS query */
    0x00, 0x00, /* Transaction ID */
    0x01, 0x00, /* Flags: Standard query, Recursion Desired */
    0x00, 0x01, /* Questions: 1 */
    0x00, 0x00, /* Answer RRs: 0 */
    0x00, 0x00, /* Authority RRs: 0 */
    0x00, 0x00, /* Additional RRs: 0 */
    /* Query: example.com A IN */
    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', /* example */
    0x03, 'c', 'o', 'm',                   /* com */
    0x00,                                  /*   (root) */
    0x00, 0x01,                            /* Type: A */
    0x00, 0x01                             /* Class: IN */
};

/* RFC 9113 (HTTP/2) Frame Types */
static uint8_t test_frame_h2_data_val_0x0[] = { 0x00 };
static uint8_t test_frame_h2_headers_val_0x1[] = { 0x01 };
static uint8_t test_frame_h2_priority_val_0x2[] = { 0x02 };
static uint8_t test_frame_h2_rst_stream_val_0x3[] = { 0x03 };
static uint8_t test_frame_h2_settings_val_0x4[] = { 0x04 };
static uint8_t test_frame_h2_push_promise_val_0x5[] = { 0x05 };
static uint8_t test_frame_h2_ping_val_0x6[] = { 0x06 };
static uint8_t test_frame_h2_goaway_val_0x7[] = { 0x07 };
static uint8_t test_frame_h2_window_update_val_0x8[] = { 0x08 };
static uint8_t test_frame_h2_continuation_val_0x9[] = { 0x09 };
static uint8_t test_frame_h2_altsvc_val_0xa[] = { 0x0a };

/* RFC 6455 (WebSocket) Frame Types */
static uint8_t test_frame_ws_continuation_val_0x0[] = { 0x00, 0x00 }; /* FIN=0, RSV1=0, RSV2=0, RSV3=0, Opcode=0x0 (Continuation), Mask=0, Payload length=0 */
static uint8_t test_frame_ws_text_val_0x1[] = { 0x81, 0x00 };         /* FIN=1, RSV1=0, RSV2=0, RSV3=0, Opcode=0x1 (Text), Mask=0, Payload length=0 */
static uint8_t test_frame_ws_binary_val_0x2[] = { 0x82, 0x00 };        /* FIN=1, RSV1=0, RSV2=0, RSV3=0, Opcode=0x2 (Binary), Mask=0, Payload length=0 */
static uint8_t test_frame_ws_connection_close_val_0x8[] = { 0x88, 0x00 }; /* FIN=1, RSV1=0, RSV2=0, RSV3=0, Opcode=0x8 (Connection Close), Mask=0, Payload length=0 */
static uint8_t test_frame_ws_ping_val_0x9[] = { 0x89, 0x00 };          /* FIN=1, RSV1=0, RSV2=0, RSV3=0, Opcode=0x9 (Ping), Mask=0, Payload length=0 */
static uint8_t test_frame_ws_pong_val_0xa[] = { 0x8A, 0x00 };          /* FIN=1, RSV1=0, RSV2=0, RSV3=0, Opcode=0xA (Pong), Mask=0, Payload length=0 */

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

/* Test Case: RESET_STREAM with Stream ID encoded non-canonically (value 1 as 2 bytes). */
/* Expected: Peer should process normally. (RFC 16) */
static uint8_t test_frame_reset_stream_sid_non_canon[] = {
    picoquic_frame_type_reset_stream, /* Type 0x04 */
    0x40, 0x01,                       /* Stream ID: 1 (2-byte varint) */
    0x00,                             /* Application Protocol Error Code: 0 */
    0x00                              /* Final Size: 0 */
};

/* Test Case: RESET_STREAM with App Error Code encoded non-canonically (value 1 as 2 bytes). */
/* Expected: Peer should process normally. (RFC 16) */
static uint8_t test_frame_reset_stream_err_non_canon[] = {
    picoquic_frame_type_reset_stream, /* Type 0x04 */
    0x01,                             /* Stream ID: 1 */
    0x40, 0x01,                       /* Application Protocol Error Code: 1 (2-byte varint) */
    0x00                              /* Final Size: 0 */
};

/* Test Case: RESET_STREAM with Final Size encoded non-canonically (value 1 as 2 bytes). */
/* Expected: Peer should process normally. (RFC 16) */
static uint8_t test_frame_reset_stream_final_non_canon[] = {
    picoquic_frame_type_reset_stream, /* Type 0x04 */
    0x01,                             /* Stream ID: 1 */
    0x00,                             /* Application Protocol Error Code: 0 */
    0x40, 0x01                        /* Final Size: 1 (2-byte varint) */
};

/* Test Case: STOP_SENDING with Stream ID encoded non-canonically (value 1 as 2 bytes). */
/* Expected: Peer should process normally. (RFC 16) */
static uint8_t test_frame_stop_sending_sid_non_canon[] = {
    picoquic_frame_type_stop_sending, /* Type 0x05 */
    0x40, 0x01,                       /* Stream ID: 1 (2-byte varint) */
    0x00                              /* Application Protocol Error Code: 0 */
};

/* Test Case: STOP_SENDING with App Error Code encoded non-canonically (value 1 as 2 bytes). */
/* Expected: Peer should process normally. (RFC 16) */
static uint8_t test_frame_stop_sending_err_non_canon[] = {
    picoquic_frame_type_stop_sending, /* Type 0x05 */
    0x01,                             /* Stream ID: 1 */
    0x40, 0x01                        /* Application Protocol Error Code: 1 (2-byte varint) */
};

/* Test Case: CRYPTO frame with Offset encoded non-canonically (value 10 as 2 bytes). */
/* Expected: Peer should process normally. (RFC 16) */
static uint8_t test_frame_crypto_offset_small_non_canon[] = {
    picoquic_frame_type_crypto_hs, /* Type 0x06 */
    0x40, 0x0A,                    /* Offset: 10 (2-byte varint) */
    0x04,                          /* Length: 4 */
    'd','a','t','a'
};

/* Test Case: CRYPTO frame with Length encoded non-canonically (value 4 as 2 bytes). */
/* Expected: Peer should process normally. (RFC 16) */
static uint8_t test_frame_crypto_len_small_non_canon[] = {
    picoquic_frame_type_crypto_hs, /* Type 0x06 */
    0x0A,                          /* Offset: 10 */
    0x40, 0x04,                    /* Length: 4 (2-byte varint) */
    'd','a','t','a'
};

/* Test Case: NEW_TOKEN frame with Token Length encoded non-canonically (value 16 as 2 bytes). */
/* Expected: Peer should process normally. (RFC 16) */
static uint8_t test_frame_new_token_len_non_canon[] = {
    picoquic_frame_type_new_token, /* Type 0x07 */
    0x40, 0x10,                    /* Token Length: 16 (2-byte varint) */
    '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f' /* Token data */
};

/* Test Case: PADDING frame (single byte). */
/* Expected: Peer should process normally. (RFC 19.1) */
static uint8_t test_frame_padding_single[] = {
    picoquic_frame_type_padding /* Type 0x00 */
};

/* Test Case: ACK frame with Range Count = 0 and a non-zero First ACK Range. */
/* Expected: Peer should process normally. (RFC 19.3) */
static uint8_t test_frame_ack_range_count_zero_first_range_set[] = {
    picoquic_frame_type_ack, /* Type 0x02 */
    0x0A,                    /* Largest Acknowledged: 10 */
    0x00,                    /* ACK Delay: 0 */
    0x00,                    /* ACK Range Count: 0 */
    0x05                     /* First ACK Range: 5 (acks packets 6-10) */
};

/* Test Case: ACK frame with an ACK Delay that might cause overflow if not handled carefully with ack_delay_exponent. */
/* Assuming default ack_delay_exponent = 3. Max ACK Delay field val is (2^62-1).
   A large val like 2^24 (0x01000000) for ACK Delay field, when multiplied by 2^3, is 2^27 microseconds.
   If ack_delay_exponent was, e.g., 20, then 2^24 * 2^20 = 2^44, still okay for u64 RTT.
   Let's use a value that is itself large, but not max varint.
   0x80, 0x01, 0x00, 0x00 -> 65536. Shifted by 3 = 524288 us = ~0.5 sec.
   Shifted by 20 = 65536 * 2^20 = 2^16 * 2^20 = 2^36 us = ~19 hours. This is large. */
/* Expected: Peer calculates RTT correctly or clamps delay. (RFC 19.3) */
static uint8_t test_frame_ack_delay_potentially_large_calc[] = {
    picoquic_frame_type_ack,       /* Type 0x02 */
    0x0A,                          /* Largest Acknowledged: 10 */
    0x80, 0x01, 0x00, 0x00,        /* ACK Delay: 65536 (raw value) */
    0x01,                          /* ACK Range Count: 1 */
    0x00                           /* First ACK Range: 0 */
};

/* Test Case: ACK frame acknowledging packet 0, with First ACK Range = 0. */
/* Expected: Peer should process normally. (RFC 19.3) */
static uint8_t test_frame_ack_largest_zero_first_zero[] = {
    picoquic_frame_type_ack, /* Type 0x02 */
    0x00,                    /* Largest Acknowledged: 0 */
    0x00,                    /* ACK Delay: 0 */
    0x01,                    /* ACK Range Count: 1 */
    0x00                     /* First ACK Range: 0 (acks packet 0) */
};

/* Test Case: ACK frame with ECN ECT0 count encoded non-minimally. */
/* Expected: Peer should process normally. (RFC 16) */
static uint8_t test_frame_ack_ecn_non_minimal_ect0[] = {
    picoquic_frame_type_ack_ecn, /* Type 0x03 */
    0x0A,                        /* Largest Acknowledged: 10 */
    0x00,                        /* ACK Delay: 0 */
    0x01,                        /* ACK Range Count: 1 */
    0x00,                        /* First ACK Range: 0 */
    0x40, 0x01,                  /* ECT0 Count: 1 (2-byte varint) */
    0x00,                        /* ECT1 Count: 0 */
    0x00                         /* ECN-CE Count: 0 */
};

/* Test Case: STREAM from Client on a server-initiated bidirectional Stream ID (e.g., 1). */
/* Expected: Server treats as STREAM_STATE_ERROR. (RFC 3.2, 19.8) */
static uint8_t test_stream_client_sends_server_bidi_stream[] = {
    0x0F,       /* Type: All bits (OFF,LEN,FIN) set for generic data */
    0x01,       /* Stream ID: 1 (Server-initiated bidi) */
    0x00,       /* Offset: 0 */
    0x04,       /* Length: 4 */
    't','e','s','t'
};

/* Test Case: STREAM from Client on a server-initiated unidirectional Stream ID (e.g., 3). */
/* Expected: Server treats as STREAM_STATE_ERROR. (RFC 3.2, 19.8) */
static uint8_t test_stream_client_sends_server_uni_stream[] = {
    0x0F,       /* Type: All bits set */
    0x03,       /* Stream ID: 3 (Server-initiated uni) */
    0x00,       /* Offset: 0 */
    0x04,       /* Length: 4 */
    't','e','s','t'
};

/* Test Case: STREAM from Server on a client-initiated bidirectional Stream ID (e.g., 0). */
/* Expected: Client treats as STREAM_STATE_ERROR. (RFC 3.2, 19.8) */
static uint8_t test_stream_server_sends_client_bidi_stream[] = {
    0x0F,       /* Type: All bits set */
    0x00,       /* Stream ID: 0 (Client-initiated bidi) */
    0x00,       /* Offset: 0 */
    0x04,       /* Length: 4 */
    't','e','s','t'
};

/* Test Case: STREAM from Server on a client-initiated unidirectional Stream ID (e.g., 2). */
/* Expected: Client treats as STREAM_STATE_ERROR. (RFC 3.2, 19.8) */
static uint8_t test_stream_server_sends_client_uni_stream[] = {
    0x0F,       /* Type: All bits set */
    0x02,       /* Stream ID: 2 (Client-initiated uni) */
    0x00,       /* Offset: 0 */
    0x04,       /* Length: 4 */
    't','e','s','t'
};

/* Test Case: STREAM with LEN=1, Length field = 0, but data is present. */
/* Expected: Parser should take Length field; trailing data might be another frame or error. (RFC 19.8) */
static uint8_t test_stream_explicit_len_zero_with_data[] = {
    0x0A,       /* Type: OFF=0, LEN=1, FIN=0 */
    0x01,       /* Stream ID: 1 */
    0x00,       /* Length: 0 */
    'd','a','t','a' /* This data should ideally be parsed as a separate frame or cause error */
};

/* Test Case: STREAM with only FIN bit set (Type 0x09), no data, implicit length, zero offset. */
/* Expected: Valid empty stream with FIN. (RFC 19.8) */
static uint8_t test_stream_fin_only_implicit_len_zero_offset[] = {
    0x09,       /* Type: OFF=0, LEN=0, FIN=1 */
    0x04        /* Stream ID: 4 */
    /* Data implicitly to end of packet, which is 0 here if this is the only frame. */
};

/* Test Case: STREAM with FIN=1, LEN=1, Length field = 0, but trailing data present. */
/* Expected: Stream ends at offset + 0. Trailing data is next frame or error. (RFC 19.8) */
static uint8_t test_stream_fin_len_zero_with_trailing_data[] = {
    0x0B,        /* Type: OFF=0, LEN=1, FIN=1 */
    0x01,        /* Stream ID: 1 */
    0x00,        /* Length: 0 */
    0x01         /* A PING frame as trailing data, for example */
};

/* Test Case: MAX_DATA with value 10 encoded non-canonically as 8-byte varint. */
/* Expected: Peer should process normally. (RFC 16) */
static uint8_t test_frame_max_data_long_varint_8byte_small[] = {
    picoquic_frame_type_max_data, /* Type 0x10 */
    0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A /* Maximum Data: 10 (8-byte varint) */
};

/* MAX_STREAM_DATA Variations */
/* Test Case: MAX_STREAM_DATA with Stream ID 0 and a non-zero Max Data value. */
/* Expected: Peer should process normally (Stream 0 is a valid bidi stream). (RFC 19.10) */
static uint8_t test_frame_max_stream_data_id_zero_val_set[] = {
    picoquic_frame_type_max_stream_data, /* Type 0x11 */
    0x00,                                /* Stream ID: 0 */
    0x41, 0x00                           /* Maximum Stream Data: 256 */
};

/* Test Case: MAX_STREAM_DATA with Stream ID encoded non-canonically (value 1 as 2 bytes). */
/* Expected: Peer should process normally. (RFC 16) */
static uint8_t test_frame_max_stream_data_sid_non_canon[] = {
    picoquic_frame_type_max_stream_data, /* Type 0x11 */
    0x40, 0x01,                          /* Stream ID: 1 (2-byte varint) */
    0x41, 0x00                           /* Maximum Stream Data: 256 */
};

/* Test Case: MAX_STREAM_DATA with Max Stream Data encoded non-canonically (value 10 as 2 bytes). */
/* Expected: Peer should process normally. (RFC 16) */
static uint8_t test_frame_max_stream_data_val_non_canon[] = {
    picoquic_frame_type_max_stream_data, /* Type 0x11 */
    0x01,                                /* Stream ID: 1 */
    0x40, 0x0A                           /* Maximum Stream Data: 10 (2-byte varint) */
};


/* MAX_STREAMS Variations */
/* Test Case: MAX_STREAMS (bidirectional) with Maximum Streams = 2^50 (large valid value). */
/* Expected: Peer should process normally. (RFC 19.11) */
static uint8_t test_frame_max_streams_bidi_val_2_pow_50[] = {
    picoquic_frame_type_max_streams_bidir, /* Type 0x12 */
    0xC0, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00 /* Max Streams: 2^50 */
};

/* Test Case: MAX_STREAMS (bidirectional) with small value 5 encoded non-canonically as 8-byte varint. */
/* Expected: Peer should process normally. (RFC 16) */
static uint8_t test_frame_max_streams_bidi_small_non_canon8[] = {
    picoquic_frame_type_max_streams_bidir, /* Type 0x12 */
    0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05 /* Maximum Streams: 5 (8-byte varint) */
};

/* DATA_BLOCKED Variations */
/* Test Case: DATA_BLOCKED with Maximum Data encoded non-canonically (value 10 as 2 bytes). */
/* Expected: Peer should process normally. (RFC 16) */
static uint8_t test_frame_data_blocked_non_canon2[] = {
    picoquic_frame_type_data_blocked, /* Type 0x14 */
    0x40, 0x0A                        /* Maximum Data: 10 (2-byte varint) */
};

/* Test Case: DATA_BLOCKED with Maximum Data encoded non-canonically (value 10 as 4 bytes). */
/* Expected: Peer should process normally. (RFC 16) */
static uint8_t test_frame_data_blocked_non_canon4[] = {
    picoquic_frame_type_data_blocked, /* Type 0x14 */
    0x80, 0x00, 0x00, 0x0A            /* Maximum Data: 10 (4-byte varint) */
};

/* Test Case: STREAM_DATA_BLOCKED with Stream ID non-canonically encoded (value 1 as 2 bytes). */
/* Expected: Peer should process normally. (RFC 16) */
static uint8_t test_frame_sdb_sid_non_canon[] = {
    picoquic_frame_type_stream_data_blocked, /* Type 0x15 */
    0x40, 0x01,                              /* Stream ID: 1 (2-byte varint) */
    0x41, 0x00                               /* Maximum Stream Data: 256 */
};

/* Test Case: STREAM_DATA_BLOCKED with Maximum Stream Data non-canonically encoded (value 10 as 2 bytes). */
/* Expected: Peer should process normally. (RFC 16) */
static uint8_t test_frame_sdb_val_non_canon[] = {
    picoquic_frame_type_stream_data_blocked, /* Type 0x15 */
    0x01,                                    /* Stream ID: 1 */
    0x40, 0x0A                               /* Maximum Stream Data: 10 (2-byte varint) */
};

/* Test Case: STREAM_DATA_BLOCKED with Stream ID 0. */
/* Expected: Peer should process normally for bidirectional stream 0. (RFC 19.13) */
static uint8_t test_frame_sdb_sid_zero[] = {
    picoquic_frame_type_stream_data_blocked, /* Type 0x15 */
    0x00,                                    /* Stream ID: 0 */
    0x41, 0x00                               /* Maximum Stream Data: 256 */
};

/* Test Case: STREAMS_BLOCKED (Bidirectional) with Maximum Streams = 2^60 (valid max). */
/* Expected: Peer should process normally. (RFC 19.14) */
static uint8_t test_frame_streams_blocked_bidi_at_limit[] = {
    picoquic_frame_type_streams_blocked_bidir, /* Type 0x16 */
    0xC0, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00 /* Max Streams: 2^60 */
};

/* Test Case: STREAMS_BLOCKED (Unidirectional) with Maximum Streams = 2^60 (valid max). */
/* Expected: Peer should process normally. (RFC 19.14) */
static uint8_t test_frame_streams_blocked_uni_at_limit[] = {
    picoquic_frame_type_streams_blocked_unidir, /* Type 0x17 */
    0xC0, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00 /* Max Streams: 2^60 */
};

/* Test Case: STREAMS_BLOCKED (Bidirectional) with Max Streams non-canonically encoded (value 10 as 2 bytes). */
/* Expected: Peer should process normally. (RFC 16) */
static uint8_t test_frame_streams_blocked_bidi_non_canon2[] = {
    picoquic_frame_type_streams_blocked_bidir, /* Type 0x16 */
    0x40, 0x0A                                 /* Maximum Streams: 10 (2-byte varint) */
};

/* Test Case: STREAMS_BLOCKED (Unidirectional) with Max Streams non-canonically encoded (value 10 as 4 bytes). */
/* Expected: Peer should process normally. (RFC 16) */
static uint8_t test_frame_streams_blocked_uni_non_canon4[] = {
    picoquic_frame_type_streams_blocked_unidir, /* Type 0x17 */
    0x80, 0x00, 0x00, 0x0A                     /* Maximum Streams: 10 (4-byte varint) */
};

/* Test Case: NEW_CONNECTION_ID with Sequence Number non-canonically encoded (value 1 as 2 bytes). */
/* Expected: Peer should process normally. (RFC 16) */
static uint8_t test_frame_ncid_seq_non_canon[] = {
    picoquic_frame_type_new_connection_id, /* Type 0x18 */
    0x40, 0x01,                            /* Sequence Number: 1 (2-byte varint) */
    0x00,                                  /* Retire Prior To: 0 */
    0x08,                                  /* Length: 8 */
    0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08, /* Connection ID */
    0xA0,0xA1,0xA2,0xA3,0xA4,0xA5,0xA6,0xA7, /* Stateless Reset Token */
    0xA8,0xA9,0xAA,0xAB,0xAC,0xAD,0xAE,0xAF
};

/* Test Case: NEW_CONNECTION_ID with Retire Prior To non-canonically encoded (value 0 as 2 bytes). */
/* Expected: Peer should process normally. (RFC 16) */
static uint8_t test_frame_ncid_ret_non_canon[] = {
    picoquic_frame_type_new_connection_id, /* Type 0x18 */
    0x01,                                  /* Sequence Number: 1 */
    0x40, 0x00,                            /* Retire Prior To: 0 (2-byte varint) */
    0x08,                                  /* Length: 8 */
    0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08, /* Connection ID */
    0xA0,0xA1,0xA2,0xA3,0xA4,0xA5,0xA6,0xA7, /* Stateless Reset Token */
    0xA8,0xA9,0xAA,0xAB,0xAC,0xAD,0xAE,0xAF
};
/* Specific ACK frame with an invalid gap of 1 */
/* Largest Ack: 5, Delay:0, RangeCount:1, FirstRangeLen:0 (acks 5), Gap:1 (skips 4), NextRangeLen:0 (acks 3) */
static uint8_t test_frame_ack_invalid_gap_1_specific_val[] = {0x02, 0x05, 0x00, 0x01, 0x00, 0x01, 0x00};

/* Frame Sequences for test_frame_sequence */
static uint8_t sequence_stream_ping_padding_val[] = {
    0x0A, 0x01, 0x05, 'h', 'e', 'l', 'l', 'o', /* STREAM ID 1, len 5, "hello" */
    0x01,                                     /* PING */
    0x00, 0x00, 0x00                          /* PADDING x3 */
};
static uint8_t sequence_max_data_max_stream_data_val[] = {
    0x10, 0x44, 0x00,                         /* MAX_DATA 1024 Add commentMore actions */
    0x11, 0x01, 0x42, 0x00                    /* MAX_STREAM_DATA Stream 1, 512 */
};

/* Error condition test frames */
static uint8_t error_stream_client_on_server_uni_val[] = { /* Client sends on server-initiated uni stream (ID 3) */
    0x09, 0x03, 'd', 'a', 't', 'a'         /* STREAM ID 3, FIN, "data" */
};
static uint8_t error_stream_len_shorter_val[] = { /* STREAM frame, LEN bit, Length=2, Data="test" (4 bytes) */
    0x0A, 0x04, 0x02, 't', 'e', 's', 't'
};
/* Test Case: NEW_CONNECTION_ID with minimum Connection ID Length (1). */
/* Expected: Peer should process normally. (RFC 19.15) */
static uint8_t test_frame_ncid_cid_len_min[] = {
    picoquic_frame_type_new_connection_id, /* Type 0x18 */
    0x02,                                  /* Sequence Number: 2 */
    0x00,                                  /* Retire Prior To: 0 */
    0x01,                                  /* Length: 1 */
    0xBB,                                  /* Connection ID (1 byte) */
    0xA0,0xA1,0xA2,0xA3,0xA4,0xA5,0xA6,0xA7, /* Stateless Reset Token */
    0xA8,0xA9,0xAA,0xAB,0xAC,0xAD,0xAE,0xAF
};

#define FUZI_Q_ITEM(n, x) \
    {                        \
        n, x, sizeof(x),     \
    }

/* Test Case: RETIRE_CONNECTION_ID with Sequence Number encoded non-canonically (value 1 as 2 bytes). */
/* Expected: Peer should process normally. (RFC 16) */
static uint8_t test_frame_retire_cid_seq_non_canon[] = {
    0x19,       /* Type: RETIRE_CONNECTION_ID */
    0x40, 0x01  /* Sequence Number: 1 (2-byte varint) */
};

/* Test Case: CONNECTION_CLOSE (transport error) with a reserved error code. */
/* Error Code 0x100 (QUIC_TLS_HANDSHAKE_FAILED) -> varint 0x4100. Frame Type PADDING (0x00). Empty reason. */
static uint8_t test_frame_conn_close_reserved_err[] = {
    picoquic_frame_type_connection_close, /* Type 0x1c */
    0x41, 0x00, /* Error Code: 0x100 (varint) */
    0x00,       /* Frame Type: PADDING */
    0x00        /* Reason Phrase Length: 0 */
};

/* Test Case: CONNECTION_CLOSE (transport error) with Frame Type encoded non-canonically. */
/* Error Code 0. Frame Type STREAM (0x08) as 2-byte varint (0x40, 0x08). Empty reason. */
static uint8_t test_frame_conn_close_ft_non_canon[] = {
    picoquic_frame_type_connection_close, /* Type 0x1c */
    0x00,       /* Error Code: 0 */
    0x40, 0x08, /* Frame Type: STREAM (0x08) as 2-byte varint */
    0x00        /* Reason Phrase Length: 0 */
};

static uint8_t sequence_stream_ping_padding[] = {
    0x0A, 0x01, 0x04, 't', 'e', 's', 't', /* STREAM frame */
    0x01,                               /* PING frame */
    0x00, 0x00, 0x00                    /* PADDING frame (3 bytes) */
};

static uint8_t sequence_max_data_max_stream_data[] = {
    0x10, 0x44, 0x00, /* MAX_DATA frame (Type 0x10, Value 1024) */
    0x11, 0x01, 0x44, 0x00 /* MAX_STREAM_DATA frame (Type 0x11, Stream 1, Value 1024) */
};

/* Test Case: CONNECTION_CLOSE (application error) with Reason Phrase Length non-canonically encoded. */
/* Error Code 0. Reason Phrase Length 5 as 2-byte varint (0x40, 0x05). Reason "test!". */
static uint8_t test_frame_conn_close_app_rlen_non_canon[] = {
    picoquic_frame_type_application_close, /* Type 0x1d */
    0x00,       /* Error Code: 0 */
    0x40, 0x05, /* Reason Phrase Length: 5 (2-byte varint) */
    't', 'e', 's', 't', '!'
};

/* Test Case: HANDSHAKE_DONE with Frame Type encoded non-canonically. */
/* Frame Type HANDSHAKE_DONE (0x1e) as 2-byte varint (0x40, 0x1e). */
static uint8_t test_frame_hsd_type_non_canon[] = {
    0x40, 0x1e  /* Frame Type: HANDSHAKE_DONE (0x1e) as 2-byte varint */
};

/* Proposed New STREAM Variants - RFC 9000, Section 19.8, 4.5 */

/* Test STREAM frame with LEN=1, FIN=1, OFF=0, explicit non-zero Length, but NO actual Stream Data.
 * Type 0x0B (OFF=0, LEN=1, FIN=1), Stream ID 1, Length 5. Packet ends.
 * Final size should be 5.
 */
static uint8_t test_stream_len_set_explicit_length_no_data_fin[] = {
    0x0B,       /* Type: OFF=0, LEN=1, FIN=1 */
    0x01,       /* Stream ID: 1 */
    0x05        /* Length: 5 */
    /* Packet is truncated here; no stream data provided. */
};

/* Test STREAM frame with OFF=1, LEN=1, FIN=1, where offset + length is very close to 2^62-1.
 * Type 0x0F, Stream ID 2, Offset ((1ULL<<62)-10), Length 5, Data "hello".
 * Final size should be (2^62)-10 + 5 = (2^62)-5.
 */
static uint8_t test_stream_off_len_fin_offset_plus_length_almost_max[] = {
    0x0F,        /* Type: OFF=1, LEN=1, FIN=1 */
    0x02,        /* Stream ID: 2 */
    /* Offset: (1ULL<<62)-10. Encoded as 8-byte varint.
       (2^62)-10 = 0x3FFFFFFFFFFFFFF6
       Prefix 0b11 -> 8 bytes.
       Value: 0x3F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF6
    */
    0xBF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF6,
    0x05,        /* Length: 5 */
    'h', 'e', 'l', 'l', 'o' /* Stream Data */
};

/* Proposed New ACK Variant - RFC 9000, Section 19.3, 19.3.1, 19.3.2 */

/* Test ACK frame with ECN (Type 0x03), ACK Range Count = 0, but First ACK Range is set.
 * Largest Ack: 0x10, Delay: 0, Range Count: 0, First ACK Range: 0x05.
 * ECN Counts: ECT0=1, ECT1=1, CE=1.
 */
static uint8_t test_ack_ecn_range_count_zero_first_range_set_with_counts[] = {
    0x03,       /* Type: ACK with ECN */
    0x10,       /* Largest Acknowledged: 16 */
    0x00,       /* ACK Delay: 0 */
    0x00,       /* ACK Range Count: 0 */
    0x05,       /* First ACK Range: 5 (acks packets 11-16) */
    0x01,       /* ECT0 Count: 1 */
    0x01,       /* ECT1 Count: 1 */
    0x01        /* ECN-CE Count: 1 */
};

/* Proposed New CONNECTION_CLOSE Variant - RFC 9000, Section 19.19 */

/* Test CONNECTION_CLOSE (transport) with minimal fields.
 * Type 0x1c, Error Code INTERNAL_ERROR (0x01), Frame Type PADDING (0x00), Reason Phrase Length 0.
 */
static uint8_t test_connection_close_transport_min_fields[] = {
    0x1c,       /* Type: CONNECTION_CLOSE (transport) */
    0x01,       /* Error Code: INTERNAL_ERROR (0x01) */
    0x00,       /* Frame Type: PADDING (0x00) */
    0x00        /* Reason Phrase Length: 0 */
};

/* Proposed New MAX_STREAM_DATA Variant - RFC 9000, Section 19.10 */

/* Test MAX_STREAM_DATA with Stream ID and Max Stream Data at max varint values.
 * Type 0x11, Stream ID (2^62)-1, Max Stream Data (2^62)-1.
 */
static uint8_t test_max_stream_data_id_max_val_max[] = {
    0x11,       /* Type: MAX_STREAM_DATA */
    /* Stream ID: (1ULL<<62)-1 = 0x3FFFFFFFFFFFFFFF. Encoded as 8-byte varint. */
    0xBF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    /* Maximum Stream Data: (1ULL<<62)-1 = 0x3FFFFFFFFFFFFFFF. Encoded as 8-byte varint. */
    0xBF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

/* --- Batch 1 of New Edge Case Test Variants --- */

/* RFC 9000, Sec 19.8, 4.5 - STREAM (Type 0x0D: OFF=1,LEN=0,FIN=1) with max offset and 1 byte of data.
 * Offset is (2^62-1), implicit length is 1. Final size = offset + 1, which exceeds 2^62-1.
 * Expected: FINAL_SIZE_ERROR by receiver.
 */
static uint8_t test_stream_implicit_len_max_offset_with_data[] = {
    0x0D,       /* Type: OFF=1, LEN=0, FIN=1 */
    0x01,       /* Stream ID: 1 */
    /* Offset: (1ULL<<62)-1 = 0x3FFFFFFFFFFFFFFF. Encoded as 8-byte varint. */
    0xBF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    'X'         /* Stream Data: 1 byte */
};

/* RFC 9000, Sec 19.3 - ACK frame Type 0x02 (no ECN) but with trailing ECN-like data.
 * Parser should correctly identify end of ACK frame based on its fields and either
 * ignore trailing data or flag an error if it tries to parse beyond necessary.
 */
static uint8_t test_ack_type02_with_trailing_ecn_like_data[] = {
    0x02,       /* Type: ACK (no ECN bit) */
    0x10,       /* Largest Acknowledged: 16 */
    0x01,       /* ACK Delay: 1 (raw value) */
    0x01,       /* ACK Range Count: 1 */
    0x02,       /* First ACK Range: 2 (acks packets 14-16) */
    0x03,       /* Gap: 3 (unacked 10-12) */
    0x04,       /* ACK Range Length: 4 (acks packets 6-9) */
    /* Trailing ECN-like data, should be ignored or cause error if parsed as part of ACK */
    0x40, 0x01, /* ECT0 Count: 1 (varint) */
    0x40, 0x01, /* ECT1 Count: 1 (varint) */
    0x40, 0x01  /* ECN-CE Count: 1 (varint) */
};

/* RFC 9000, Sec 19.15 - NEW_CONNECTION_ID frame with CID truncated.
 * Length field for CID is 8, but only 4 bytes of CID data provided before packet ends.
 * Expected: FRAME_ENCODING_ERROR by receiver.
 */
static uint8_t test_new_connection_id_truncated_cid[] = {
    0x18,       /* Type: NEW_CONNECTION_ID */
    0x01,       /* Sequence Number: 1 */
    0x00,       /* Retire Prior To: 0 */
    0x08,       /* Length of Connection ID: 8 */
    0xAA, 0xBB, 0xCC, 0xDD /* Connection ID data (only 4 bytes) */
    /* Packet ends here, Stateless Reset Token is missing */
};

/* RFC 9000, Sec 19.15 - NEW_CONNECTION_ID frame with Stateless Reset Token truncated.
 * CID is fully provided (8 bytes), but token is only partially provided (8 of 16 bytes).
 * Expected: FRAME_ENCODING_ERROR by receiver.
 */
static uint8_t test_new_connection_id_truncated_token[] = {
    0x18,       /* Type: NEW_CONNECTION_ID */
    0x02,       /* Sequence Number: 2 */
    0x01,       /* Retire Prior To: 1 */
    0x08,       /* Length of Connection ID: 8 */
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, /* Connection ID data */
    /* Stateless Reset Token (partially provided) */
    0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7
    /* Packet ends here, 8 bytes of token missing */
};

/* RFC 9000, Sec 19.15 - NEW_CONNECTION_ID frame with CID data longer than Length field.
 * Length field for CID is 4, but 6 bytes of CID data provided.
 * Parser should use Length field to find start of token.
 */
static uint8_t test_new_connection_id_cid_overrun_length_field[] = {
    0x18,       /* Type: NEW_CONNECTION_ID */
    0x03,       /* Sequence Number: 3 */
    0x00,       /* Retire Prior To: 0 */
    0x04,       /* Length of Connection ID: 4 */
    /* Actual Connection ID data (6 bytes) */
    0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    /* Stateless Reset Token (16 bytes) */
    0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7,
    0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF
};

/* --- Batch 2 of New Edge Case Test Variants (Flow Control) --- */

/* RFC 9000, Sec 19.12 - DATA_BLOCKED frame with Maximum Data at max varint value.
 * Maximum Data: (1ULL<<62)-1 = 0x3FFFFFFFFFFFFFFF
 */
static uint8_t test_data_blocked_max_value[] = {
    0x14,       /* Type: DATA_BLOCKED */
    /* Maximum Data: (1ULL<<62)-1. Encoded as 8-byte varint. */
    0xBF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

/* RFC 9000, Sec 19.13 - STREAM_DATA_BLOCKED frame with Stream ID and Max Stream Data at max varint values.
 * Stream ID: (1ULL<<62)-1
 * Maximum Stream Data: (1ULL<<62)-1
 */
static uint8_t test_stream_data_blocked_max_id_max_value[] = {
    0x15,       /* Type: STREAM_DATA_BLOCKED */
    /* Stream ID: (1ULL<<62)-1. Encoded as 8-byte varint. */
    0xBF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    /* Maximum Stream Data: (1ULL<<62)-1. Encoded as 8-byte varint. */
    0xBF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

/* --- Batch 3 of New Edge Case Test Variants (Stream Limit Frames) --- */

/* RFC 9000, Sec 19.14 - STREAMS_BLOCKED (bidirectional) with Maximum Streams over limit.
 * Maximum Streams: (1ULL<<60) + 1.
 * Expected: FRAME_ENCODING_ERROR or STREAM_LIMIT_ERROR by receiver.
 */
static uint8_t test_streams_blocked_bidi_over_limit[] = {
    0x16,       /* Type: STREAMS_BLOCKED (bidirectional) */
    /* Maximum Streams: (1ULL<<60) + 1. Varint encoded: */
    /* (1ULL<<60) is 0x1000000000000000. (1ULL<<60)+1 is 0x1000000000000001 */
    /* For 8-byte varint, first byte is (value >> 56) | 0xC0 */
    /* (0x1000000000000001 >> 56) & 0x3F = 0x10 & 0x3F = 0x10. */
    /* First byte: 0xC0 | 0x10 = 0xD0. */
    /* Remaining 7 bytes: 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01. */
    0xD0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};

/* RFC 9000, Sec 19.14 - STREAMS_BLOCKED (unidirectional) with Maximum Streams over limit.
 * Maximum Streams: (1ULL<<60) + 1.
 * Expected: FRAME_ENCODING_ERROR or STREAM_LIMIT_ERROR by receiver.
 */
static uint8_t test_streams_blocked_uni_over_limit[] = {
    0x17,       /* Type: STREAMS_BLOCKED (unidirectional) */
    /* Maximum Streams: (1ULL<<60) + 1. Varint encoded (same as above): */
    0xD0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};

/* --- Batch 5 of New Edge Case Test Variants (Other Control Frames) --- */

/* RFC 9000, Sec 19.5 - STOP_SENDING with max Stream ID and max App Error Code.
 * Stream ID: (1ULL<<62)-1
 * App Error Code: (1ULL<<62)-1
 */
static uint8_t test_stop_sending_max_id_max_error[] = {
    0x05,       /* Type: STOP_SENDING */
    /* Stream ID: (1ULL<<62)-1. Varint encoded: */
    0xBF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    /* Application Protocol Error Code: (1ULL<<62)-1. Varint encoded: */
    0xBF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

/* RFC 9000, Sec 19.16 - RETIRE_CONNECTION_ID with max Sequence Number.
 * Sequence Number: (1ULL<<62)-1
 */
static uint8_t test_retire_connection_id_max_sequence[] = {
    0x19,       /* Type: RETIRE_CONNECTION_ID */
    /* Sequence Number: (1ULL<<62)-1. Varint encoded: */
    0xBF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

/* RFC 9000, Sec 19.7 - NEW_TOKEN with Token Length > 0, but no token data (truncated).
 * Token Length: 5
 * Expected: FRAME_ENCODING_ERROR by receiver.
 */
static uint8_t test_new_token_len_gt_zero_no_token_data_truncated[] = {
    0x07,       /* Type: NEW_TOKEN */
    0x05        /* Token Length: 5 */
    /* Packet ends here, no token data */
};

/* RFC 9000, Sec 19.4 - RESET_STREAM with Stream ID, App Error Code, and Final Size all max.
 * Stream ID: (1ULL<<62)-1
 * App Error Code: (1ULL<<62)-1
 * Final Size: (1ULL<<62)-1
 * Expected: Likely FINAL_SIZE_ERROR by receiver.
 */
static uint8_t test_reset_stream_all_fields_max_value[] = {
    0x04,       /* Type: RESET_STREAM */
    /* Stream ID: (1ULL<<62)-1. Varint encoded: */
    0xBF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    /* Application Protocol Error Code: (1ULL<<62)-1. Varint encoded: */
    0xBF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    /* Final Size: (1ULL<<62)-1. Varint encoded: */
    0xBF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

/* --- Batch 4 of New Edge Case Test Variants (Path Validation Frames) --- */

/* RFC 9000, Sec 19.17 - PATH_CHALLENGE frame with Data field all ones. */
static uint8_t test_path_challenge_all_ones[] = {
    0x1a,       /* Type: PATH_CHALLENGE */
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF /* Data */
};

/* RFC 9000, Sec 19.18 - PATH_RESPONSE frame with Data field as 0xAA pattern. */
static uint8_t test_path_response_alt_bits_AA[] = {
    0x1b,       /* Type: PATH_RESPONSE */
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA /* Data */
};

/* RFC 9000, Sec 19.17 - PATH_CHALLENGE frame, truncated after 4 data bytes.
 * Expected: FRAME_ENCODING_ERROR by receiver.
 */
static uint8_t test_path_challenge_truncated_4bytes[] = {
    0x1a,       /* Type: PATH_CHALLENGE */
    0xDE, 0xAD, 0xBE, 0xEF /* Data (4 of 8 bytes) */
    /* Packet ends here */
};

/* RFC 9000, Sec 19.18 - PATH_RESPONSE frame, truncated after type (0 data bytes).
 * Expected: FRAME_ENCODING_ERROR by receiver.
 */
static uint8_t test_path_response_truncated_0bytes[] = {
    0x1b       /* Type: PATH_RESPONSE */
    /* Packet ends here */
};

/* --- Batch 6 of New Edge Case Test Variants (CRYPTO, DATAGRAM, PADDING) --- */

/* RFC 9000, Sec 19.6 - CRYPTO frame with Length > 0, but no data (truncated after Length).
 * Offset 0, Length 5. Expected: FRAME_ENCODING_ERROR.
 */
static uint8_t test_crypto_len_gt_zero_no_data_truncated[] = {
    0x06,       /* Type: CRYPTO */
    0x00,       /* Offset: 0 */
    0x05        /* Length: 5 */
    /* Packet ends here, no crypto data */
};

/* RFC 9221, Sec 4 - DATAGRAM frame (Type 0x30, no length) empty (truncated after type). */
static uint8_t test_datagram_type0x30_empty_truncated[] = {
    0x30        /* Type: DATAGRAM (no length) */
    /* Packet ends here */
};

/* RFC 9221, Sec 4 - DATAGRAM frame (Type 0x30, no length) with one byte of data. */
static uint8_t test_datagram_type0x30_one_byte[] = {
    0x30,       /* Type: DATAGRAM (no length) */
    0xAB        /* Datagram Data: 1 byte */
};

/* RFC 9221, Sec 4 - DATAGRAM frame (Type 0x31, with length) with max Length field, minimal data.
 * Length: (1ULL<<62)-1. Actual data: 1 byte (truncated).
 * Expected: FRAME_ENCODING_ERROR.
 */
static uint8_t test_datagram_type0x31_maxlength_field_min_data[] = {
    0x31,       /* Type: DATAGRAM (with length) */
    /* Length: (1ULL<<62)-1. Varint encoded (0xBF, 0xFF, ..., 0xFF) */
    0xBF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xCD        /* Datagram Data: 1 byte */
    /* Packet ends, far short of declared length */
};

/* RFC 9221, Sec 4 - DATAGRAM frame (Type 0x31, with length) with Length > 0, but no data (truncated after Length).
 * Length: 5. Expected: FRAME_ENCODING_ERROR.
 */
static uint8_t test_datagram_type0x31_len_gt_zero_no_data_truncated[] = {
    0x31,       /* Type: DATAGRAM (with length) */
    0x05        /* Length: 5 */
    /* Packet ends here, no datagram data */
};

/* RFC 9000, Sec 19.1, 12.4 - PADDING frame type (0x00) non-canonically encoded (2 bytes).
 * Expected: PROTOCOL_VIOLATION (optional).
 */
static uint8_t test_padding_type_non_canonical_2byte[] = {
    0x40, 0x00  /* PADDING type 0x00 encoded as 2-byte varint */
};

/* START OF JULES ADDED FRAMES (BATCHES 1-8) */

/* --- Batch 1: Unknown or Unassigned Frame Types --- */
// QUIC frame type 0x20 (in private use range, but could be unassigned for this impl)
static uint8_t test_frame_quic_unknown_0x20[] = { 0x20 };
// QUIC frame type 0x3F (max 1-byte varint, likely unassigned) with short payload
static uint8_t test_frame_quic_unknown_0x3f_payload[] = { 0x3F, 0x01, 0x02, 0x03 };
// QUIC frame type 0x402A (2-byte varint, greased pattern, likely unassigned)
static uint8_t test_frame_quic_unknown_greased_0x402a[] = { 0x40, 0x2A };
// HTTP/3 reserved frame type 0x02 (from RFC9114 Table 2) with empty payload
static uint8_t test_frame_h3_reserved_0x02[] = { 0x02, 0x00 };
// HTTP/3 reserved frame type 0x06 (from RFC9114 Table 2) with empty payload
static uint8_t test_frame_h3_reserved_0x06[] = { 0x06, 0x00 };
// HTTP/3 frame type 0x21 (unassigned in RFC9114, but in reserved block 0x21-0x3F for extensions)
static uint8_t test_frame_h3_unassigned_extension_0x21[] = { 0x21, 0x00 };

/* --- Batch 1: Malformed Frame Lengths --- */
// STREAM frame (0x0a: OFF=0,LEN=1,FIN=0), Len=0, but data is present
static uint8_t test_frame_quic_stream_len0_with_data[] = { 0x0a, 0x01, 0x00, 'd', 'a', 't', 'a' };
// STREAM frame (0x0a), Len=100, but data is "short" (5 bytes)
static uint8_t test_frame_quic_stream_len_gt_data[] = { 0x0a, 0x02, 0x64, 's', 'h', 'o', 'r', 't' };
// STREAM frame (0x0a), Len=2, but data is "longerdata" (10 bytes)
static uint8_t test_frame_quic_stream_len_lt_data[] = { 0x0a, 0x03, 0x02, 'l', 'o', 'n', 'g', 'e', 'r', 'd', 'a', 't', 'a' };
// CRYPTO frame (0x06), Len=0, but data is present
static uint8_t test_frame_quic_crypto_len0_with_data[] = { 0x06, 0x00, 0x00, 'c', 'r', 'y', 'p', 't' };
// NEW_TOKEN frame (0x07), Len=10, but token is "short" (5 bytes)
static uint8_t test_frame_quic_new_token_len_gt_data[] = { 0x07, 0x0A, 's', 'h', 'o', 'r', 't'};
// CONNECTION_CLOSE (0x1c), ReasonLen=10, but reason is "err" (3 bytes)
static uint8_t test_frame_quic_conn_close_reason_len_gt_data[] = { 0x1c, 0x01, 0x00, 0x0A, 'e', 'r', 'r' };

/* --- Batch 1: Invalid Frame Field Values --- */
// MAX_STREAMS Bidi (0x12), value 0 (disallowing any new bidi streams by peer)
static uint8_t test_frame_quic_max_streams_bidi_value0[] = { 0x12, 0x00 };
// STOP_SENDING (0x05) for Stream 1, with a very large error code (2^62-1)
static uint8_t test_frame_quic_stop_sending_large_error[] = { 0x05, 0x01, 0xBF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
// MAX_DATA (0x10) with value 0
static uint8_t test_frame_quic_max_data_value0_b1[] = { 0x10, 0x00 }; // Renamed to avoid conflict
// ACK frame (0x02) with LargestAck=0, Delay=0, 1 Range, RangeLen=0 (acks only pkt 0)
static uint8_t test_frame_quic_ack_largest0_delay0_1range0_b1[] = { 0x02, 0x00, 0x00, 0x01, 0x00 }; // Renamed
// NEW_CONNECTION_ID (0x18) with RetirePriorTo > SequenceNumber
static uint8_t test_frame_quic_ncid_retire_gt_seq_b1[] = { 0x18, 0x02, 0x05, 0x08, 0xD1,0xD2,0xD3,0xD4,0xD5,0xD6,0xD7,0xD8, 0xE1,0xE2,0xE3,0xE4,0xE5,0xE6,0xE7,0xE8,0xE9,0xEA,0xEB,0xEC,0xED,0xEE,0xEF,0xF0 }; // Renamed

/* --- Batch 2: More Invalid Frame Field Values --- */
// MAX_DATA (0x10) with value 0 - covered by test_frame_quic_max_data_value0_b1, keep one.
static uint8_t test_frame_quic_max_data_value0[] = { 0x10, 0x00 };
// ACK frame (0x02) with LargestAck=0, Delay=0, 1 Range, RangeLen=0 (acks only pkt 0) - covered by test_frame_quic_ack_largest0_delay0_1range0_b1, keep one.
static uint8_t test_frame_quic_ack_largest0_delay0_1range0[] = { 0x02, 0x00, 0x00, 0x01, 0x00 };
// ACK frame (0x02) with ACK Range Count = 0, but First ACK Range is set (valid per RFC 19.3)
static uint8_t test_frame_quic_ack_range_count0_first_range_set[] = { 0x02, 0x0A, 0x00, 0x00, 0x05 };
// H3 SETTINGS frame (type 0x04) with an unknown Setting ID (e.g. 0x7FFF, a large 2-byte varint) and value 0.
static uint8_t test_frame_h3_settings_unknown_id[] = { 0x04, 0x03, 0x7F, 0xFF, 0x00 };
// H3 SETTINGS frame (type 0x04) setting MAX_FIELD_SECTION_SIZE (ID 0x06) to 0.
static uint8_t test_frame_h3_settings_max_field_section_size0[] = { 0x04, 0x02, 0x06, 0x00 };
// MAX_STREAM_DATA (0x11) for Stream 1, with Max Stream Data = 0.
static uint8_t test_frame_quic_max_stream_data_value0[] = { 0x11, 0x01, 0x00 };
// CONNECTION_CLOSE (type 0x1c) with a reserved error code (e.g., 0x1A = PATH_CHALLENGE type)
static uint8_t test_frame_quic_conn_close_reserved_error[] = { 0x1c, 0x1A, 0x00, 0x00 }; // Error 0x1A, Frame Type PADDING, ReasonLen 0
// NEW_TOKEN (0x07) with Token Length = 0 (invalid according to RFC 19.7)
static uint8_t test_frame_quic_new_token_zero_len_invalid[] = { 0x07, 0x00 };

/* --- Batch 2: Padding Fuzzing --- */
// PADDING frame (0x00) making up an entire large packet (e.g. 70 bytes of PADDING frames)
static uint8_t test_frame_quic_padding_excessive_70bytes[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 10 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 20 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 30 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 40 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 50 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 60 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  /* 70 */
};
// PADDING frame followed by non-zero bytes (already covered by test_frame_padding_mixed_payload)
// PADDING frame at the end of a packet that's not full (valid, but fuzzer might try this context)
// A single PING frame followed by many PADDING frames (e.g. to reach MTU)
static uint8_t test_frame_quic_ping_then_many_padding[60]; // Initialized in code

/* --- Batch 2: Stream ID Fuzzing (static part) --- */
// STREAM frame (0x0a) for Stream ID 0 (client-initiated bidi)
static uint8_t test_frame_quic_stream_id0[] = { 0x0a, 0x00, 0x04, 't', 'e', 's', 't' };
// MAX_STREAM_DATA (0x11) for a server-initiated unidirectional stream ID (e.g. ID 3 from client perspective)
static uint8_t test_frame_quic_max_stream_data_server_uni[] = { 0x11, 0x03, 0x41, 0x00 }; /* Max data 256 */
// RESET_STREAM (0x04) for a client-initiated unidirectional stream ID (e.g. ID 2 from server perspective)
static uint8_t test_frame_quic_reset_stream_client_uni[] = { 0x04, 0x02, 0x00, 0x00 }; /* Error 0, Final Size 0 */
// STOP_SENDING (0x05) for a stream ID that is too large (exceeds peer's MAX_STREAMS limit if known, or just a large number)
static uint8_t test_frame_quic_stop_sending_large_stream_id[] = { 0x05, 0xBF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE, 0x00 }; // Stream ID 2^62-2, Error 0.
// STREAM frame (0x08) using a server-initiated stream ID from a client (e.g. ID 1)
static uint8_t test_frame_quic_stream_client_uses_server_id[] = { 0x08, 0x01, 'b', 'a', 'd' };


/* --- Batch 3: User Prioritized Frames (Part 1 - DATAGRAM) --- */
// DATAGRAM type 0x30 (no length) but includes a varint that looks like a length, then data
static uint8_t test_frame_datagram_type30_with_len_data_error[] = { 0x30, 0x04, 'd','a','t','a' };
// DATAGRAM type 0x31 (with length) but is truncated before the length field
static uint8_t test_frame_datagram_type31_missing_len_error[] = { 0x31 };
// DATAGRAM type 0x31 (with length), length is 0, but data is present
static uint8_t test_frame_datagram_type31_len_zero_with_data_error[] = { 0x31, 0x00, 'd','a','t','a' };
// DATAGRAM type 0x31, length is huge, data is small (truncated content)
static uint8_t test_frame_datagram_type31_len_huge_data_small[] = { 0x31, 0x80, 0x01, 0x00, 0x00, 't', 'i', 'n', 'y' }; /* Length 65536 */
// DATAGRAM type 0x30 (no length) but packet is empty after type (valid empty datagram)
static uint8_t test_frame_datagram_type30_empty_valid[] = { 0x30 };
// DATAGRAM type 0x31 (with length), length is 0, no data (valid empty datagram)
static uint8_t test_frame_datagram_type31_len0_empty_valid[] = { 0x31, 0x00 };

/* --- Batch 3: User Prioritized Frames (Part 1 - H3 SETTINGS) --- */
// H3 SETTINGS (type 0x04) with far too many ID/Value pairs (exceeds reasonable frame length)
// Length is 254 (0xFE), followed by 127 pairs of (ID=1, Value=1)
static uint8_t test_h3_settings_excessive_pairs[] = {
    0x04, 0xFE,
    0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, /* 8 pairs */
    0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, /* 16 pairs */
    0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, /* 24 pairs */
    0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, /* 32 pairs */
    0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, /* 40 pairs */
    0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, /* 48 pairs */
    0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, /* 56 pairs */
    0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, /* 64 pairs */
    0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, /* 72 pairs */
    0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, /* 80 pairs */
    0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, /* 88 pairs */
    0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, /* 96 pairs */
    0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, /* 104 pairs */
    0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, /* 112 pairs */
    0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, /* 120 pairs */
    0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, 0x01,0x01, /* 127 pairs */
};
// H3 SETTINGS frame with an unknown Setting ID (e.g., 0x7FFF)
static uint8_t test_h3_settings_unknown_id_b3[] = { 0x04, 0x03, 0x7F, 0xFF, 0x00 }; // Renamed
// H3 SETTINGS with duplicate setting ID
static uint8_t test_h3_settings_duplicate_id[] = { 0x04, 0x04, 0x01, 0x0A, 0x01, 0x0B }; // ID 1=10, ID 1=11
// H3 SETTINGS with a setting ID that requires a specific value range, but value is outside (e.g., hypothetical ID 0x20 requires value < 100, sent 1000)
static uint8_t test_h3_settings_invalid_value_for_id[] = { 0x04, 0x03, 0x20, 0x83, 0xE8 }; // ID 0x20, Value 1000


 /* --- Batch 3: User Prioritized Frames (Part 2 - H3 ORIGIN & QUIC STREAM) --- */
 // H3 ORIGIN frame (type 0x0c) sent when ORIGIN extension was not negotiated
 static uint8_t test_h3_origin_unnegotiated[] = { 0x0c, 0x14, 0x00, 0x12, 'h', 't', 't', 'p', ':', '/', '/', 'o', 'r', 'i', 'g', 'i', 'n', '.', 't', 'e', 's', 't' };
// H3 ORIGIN frame with multiple Origin entries (invalid, only one allowed per RFC draft-ietf-httpbis-origin-frame)
static uint8_t test_h3_origin_multiple_entries[] = { 0x0c, 0x2A, 0x00, 0x12, 'h','t','t','p',':','/','/','o','1','.','t','e','s','t', 0x00, 0x12, 'h','t','t','p',':','/','/','o','2','.','t','e','s','t' };
// H3 ORIGIN frame with empty Origin-Entry (e.g. Length 0 for the ASCII Origin value)
static uint8_t test_h3_origin_empty_entry[] = { 0x0c, 0x02, 0x00, 0x00 }; // Two Origin-Entries, both zero length
 // QUIC STREAM frame with LEN bit set (e.g. 0x0A) but Length field is missing (truncated)
 static uint8_t test_stream_len_bit_no_len_field[] = { 0x0A, 0x01 }; // Stream ID 1
 // QUIC STREAM frame with OFF bit set (e.g. 0x0C) but Offset field is missing (truncated)
 static uint8_t test_stream_off_bit_no_off_field[] = { 0x0C, 0x01 }; // Stream ID 1
 // QUIC STREAM frame with LEN and FIN set (e.g. 0x0B), Length is 0, but data is present after frame.
 static uint8_t test_stream_len_fin_zero_len_with_data[] = { 0x0B, 0x01, 0x00, 'e','x','t','r','a' };
// QUIC STREAM frame, type 0x08 (no OFF, no LEN, no FIN), but packet ends immediately (empty stream data)
static uint8_t test_stream_type08_empty_implicit_len[] = { 0x08, 0x04 }; // Stream ID 4
// QUIC STREAM frame, type 0x0C (OFF, no LEN, no FIN), Offset present, but packet ends (empty stream data)
static uint8_t test_stream_type0C_offset_empty_implicit_len[] = { 0x0C, 0x04, 0x40, 0x10 }; // Stream ID 4, Offset 16


 /* --- Batch 3: User Prioritized Frames (Part 3 - QUIC STREAM type range & WebSocket) --- */
 // Frame type just below STREAM range (e.g. 0x07 NEW_TOKEN) but formatted like a STREAM frame
 static uint8_t test_frame_type_stream_range_just_below[] = {0x07, 0x01, 0x00, 0x04, 'd','a','t','a'}; // ID 1, Offset 0, Len 4
 // Frame type PADDING (0x00) formatted like a STREAM frame (should be invalid)
 static uint8_t test_frame_type_padding_as_stream[] = {0x00, 0x01, 0x00, 0x04, 'd','a','t','a'};
 // Frame type at lower bound of STREAM (0x08)
 static uint8_t test_frame_type_stream_range_lower_bound[] = {0x08, 0x01, 'd','a','t','a'}; // Implicit off 0, implicit len
 // Frame type at upper bound of STREAM (0x0F)
 static uint8_t test_frame_type_stream_range_upper_bound[] = {0x0F, 0x01, 0x00, 0x04, 'd','a','t','a'}; // ID 1, Offset 0, Len 4, FIN
 // Frame type just above STREAM range (e.g. 0x10 MAX_DATA) but formatted like a STREAM frame
 static uint8_t test_frame_type_stream_range_just_above[] = {0x10, 0x01, 0x00, 0x04, 'd','a','t','a'};
 // WebSocket Control Frame (e.g. PING 0x89) with FIN bit = 0 (invalid for control frames)
 static uint8_t test_ws_control_frame_fin_zero_invalid[] = { 0x09, 0x00 }; // PING, FIN=0, len=0
 // WebSocket Text Frame (0x81 FIN=1) but RSV1 bit set (invalid if not negotiated)
 static uint8_t test_ws_text_frame_rsv1_set_invalid[] = { 0xC1, 0x04, 't','e','s','t'}; // FIN=1, RSV1=1, Opcode=Text, len=4
 // WebSocket Text Frame (0x01 FIN=0), then another Text Frame (0x01 FIN=0) instead of Continuation (0x00)
 static uint8_t test_ws_text_fin0_then_text_continuation_part1[] = { 0x01, 0x04, 'p','a','r','t' }; // Text, FIN=0, "part"
 static uint8_t test_ws_text_fin0_then_text_continuation_part2_invalid[] = { 0x01, 0x03, 't','w','o' }; // Text, FIN=0, "two" (invalid sequence)
// WebSocket frame with payload length 126, but length field indicates more data than available
static uint8_t test_ws_len126_data_truncated[] = { 0x81, 0x7E, 0x00, 0xFA, 's', 'h', 'o', 'r', 't' }; // Text, FIN=1, actual len 250, but only "short" provided
// WebSocket frame with payload length 127 (extended 64-bit), but length field indicates more data than available
static uint8_t test_ws_len127_data_truncated[] = { 0x81, 0x7F, 0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00, 's', 'm', 'a', 'l', 'l' }; // Text, FIN=1, actual len 65536

 /* --- Batch 4: More Static Frames (as per plan before user specified Batch 8) --- */
 // QUIC Unknown Frame Type (high value, e.g., 0x7FEE DEAD BEEF - uses max 2-byte varint for type)
 // QUIC Unknown Frame Type (high value, e.g., 0x7FEE DEAD BEEF - uses max 2-byte varint for type)


static uint8_t test_frame_quic_unknown_frame_high_value[] = { 0x7F, 0xEE, 0xDE, 0xAD, 0xBE, 0xEF };
// H3 Reserved Frame Type 0x08 (from RFC9114 Table 2) with empty payload
static uint8_t test_frame_h3_reserved_frame_0x08[] = { 0x08, 0x00 };
// H3 Unassigned Type (e.g., 0x4040 - 2-byte varint) with empty payload
static uint8_t test_frame_h3_unassigned_type_0x4040[] = { 0x40, 0x40, 0x00 };
// WebSocket Reserved Control Opcode (e.g. 0x8B - FIN + Opcode 0xB)
static uint8_t test_frame_ws_reserved_control_0x0B[] = { 0x8B, 0x00 };
// WebSocket Reserved Non-Control Opcode (e.g. 0x83 - FIN + Opcode 0x3)
static uint8_t test_frame_ws_reserved_non_control_0x03[] = { 0x83, 0x00 };
// H3 HEADERS frame (type 0x01) with incomplete QPACK data (e.g. length mismatch or truncated instruction)
static uint8_t test_frame_h3_headers_incomplete_qpack[] = { 0x01, 0x05, 0x00, 0x00 }; // Len 5, but only 2 bytes of QPACK placeholder
// WebSocket PING frame (0x89) with payload length > 125 (invalid for PING)
static uint8_t test_frame_ws_ping_payload_gt_125[] = { 0x89, 0x7E, 0x00, 0x7E, 0xFF }; // PING, FIN=1, len=126, one byte of payload
// QUIC MAX_STREAMS Uni (0x13), value 0
static uint8_t test_frame_quic_max_streams_uni_value0[] = { 0x13, 0x00 };
// QUIC NEW_CONNECTION_ID (0x18) with a very short token (e.g., 8 bytes instead of 16)
static uint8_t test_frame_quic_ncid_short_token[] = { 0x18, 0x01, 0x00, 0x08, 0xA1,0xA2,0xA3,0xA4,0xA5,0xA6,0xA7,0xA8, 0xB1,0xB2,0xB3,0xB4,0xB5,0xB6,0xB7,0xB8 }; // Token is only 8 bytes
// QUIC NEW_CONNECTION_ID (0x18) with CID length 0 (invalid)
static uint8_t test_frame_quic_ncid_zero_len_cid[] = { 0x18, 0x02, 0x00, 0x00, 0xC1,0xC2,0xC3,0xC4,0xC5,0xC6,0xC7,0xC8,0xC9,0xCA,0xCB,0xCC,0xCD,0xCE,0xCF,0xD0 };
// QUIC PATH_CHALLENGE (0x1a) with data all zeros
static uint8_t test_frame_quic_path_challenge_all_zero_data_b4[] = { 0x1a, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 }; // Renamed
// QUIC PATH_RESPONSE (0x1b) with data mismatching a typical challenge
static uint8_t test_frame_quic_path_response_mismatch_data_b4[] = { 0x1b, 0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88 }; // Renamed

 /* --- Batch 5: Further Static Frames (as per plan before user specified Batch 8) --- */
// QUIC Unknown Frame Type (greased 0x2A type from RFC9000 Sec 15) with some payload
static uint8_t test_frame_quic_unknown_frame_grease_0x2A[] = { 0x2A, 0x01, 0x02, 0x03, 0x04 };
// H3 Reserved Frame Type 0x09 (from RFC9114 Table 2) with empty payload
static uint8_t test_frame_h3_reserved_frame_0x09[] = { 0x09, 0x00 };
// WebSocket Control Frame Opcode 0x0C (invalid) with FIN=1
static uint8_t test_frame_ws_control_frame_0x0C_invalid[] = { 0x8C, 0x00 };
// QUIC CRYPTO frame (0x06) with length > actual crypto data in packet
static uint8_t test_frame_quic_crypto_len_gt_data_b5[] = { 0x06, 0x00, 0x64, 0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A }; // Renamed, Len 100, Data 10 bytes
// H3 PUSH_PROMISE frame (type 0x05) with incomplete payload (e.g. missing Push ID or header block)
static uint8_t test_frame_h3_push_promise_incomplete_payload[] = { 0x05, 0x0A, 0x01, 0x00, 0x00 }; // Len 10, Push ID 1, then truncated QPACK
// QUIC RETIRE_CONNECTION_ID (0x19) with a very large sequence number (2^62-1)
static uint8_t test_frame_quic_retire_connection_id_large_seq[] = { 0x19, 0xBF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF };
// H3 GOAWAY frame (type 0x07) with a very large Stream/Request ID (2^62-1)
static uint8_t test_frame_h3_goaway_large_id[] = { 0x07, 0x08, 0xBF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF }; // Len 8 for ID
// QUIC NEW_CONNECTION_ID (0x18) with RetirePriorTo > SequenceNumber (duplicate of _b1 for systematic inclusion)
static uint8_t test_frame_quic_ncid_retire_gt_seq_b5[] = { 0x18, 0x02, 0x05, 0x08, 0xD1,0xD2,0xD3,0xD4,0xD5,0xD6,0xD7,0xD8, 0xE1,0xE2,0xE3,0xE4,0xE5,0xE6,0xE7,0xE8,0xE9,0xEA,0xEB,0xEC,0xED,0xEE,0xEF,0xF0 }; // Renamed
// QUIC PATH_CHALLENGE (0x1a) frame truncated (empty data)
static uint8_t test_frame_quic_path_challenge_empty[] = { 0x1a };
// QUIC PATH_RESPONSE (0x1b) frame truncated (empty data)
static uint8_t test_frame_quic_path_response_empty[] = { 0x1b };
// QUIC ACK frame (0x02) with ACK Delay encoded using max varint (8 bytes)
static uint8_t test_frame_quic_ack_delay_max_varint[] = { 0x02, 0x0A, 0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x01, 0x01, 0x00 }; // LargestAck 10, Delay 1 (8-byte), RangeCount 1, FirstRange 0
// QUIC STREAM frame (0x0F, all bits set) with StreamID, Offset, Length all max varint values
static uint8_t test_frame_quic_stream_all_fields_max_varint[] = {
    0x0F,                                                               // Type
    0xBF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,                            // Stream ID (2^62-1)
    0xBF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,                            // Offset (2^62-1)
    0xBF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFD,                            // Length (2^62-3 to avoid total overflow with data)
    'd', 'a', 't', 'a'                                                  // Data (4 bytes)
};
// H3 DATA frame (type 0x00) with length 0, but payload present
static uint8_t test_frame_h3_data_len0_with_payload[] = { 0x00, 0x00, 0x01, 0x02, 0x03 };
// WebSocket Close frame (0x88) with invalid close code (e.g. 0)
static uint8_t test_frame_ws_close_invalid_code[] = { 0x88, 0x02, 0x00, 0x00 }; // FIN=1, Opcode=Close, Len=2, Code=0 (invalid)

 /* --- Batch 8: Combined Set (original Batch 6/7 + 4 new from user) --- */
 // H2 WINDOW_UPDATE frame (type 0x08) with 0 increment. Len 4, StreamID 0, Inc 0.
// H2 WINDOW_UPDATE frame (type 0x08) with 0 increment. Len 4, StreamID 0, Inc 0.
static uint8_t test_frame_h2_window_update_increment0_b7[] = { 0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }; // This is not a QUIC frame, but H2 frame payload. Assuming it's wrapped in QUIC STREAM.
// QUIC CONNECTION_CLOSE (type 0x1c) with an application error code (e.g., 0x0101 from app space)
static uint8_t test_frame_quic_conn_close_transport_app_err_code_b7[] = { 0x1c, 0x41, 0x01, 0x08, 0x00 }; // Error 0x101 (like app), Frame Type STREAM(0x08), ReasonLen 0
// H3 MAX_PUSH_ID (type 0x0D) with value 0
static uint8_t test_frame_h3_max_push_id_value0_b7[] = { 0x0D, 0x01, 0x00 }; // Len 1, ID 0
// QUIC NEW_CONNECTION_ID (0x18) with CID length > 20 (e.g. 21)
static uint8_t test_frame_quic_ncid_cid_len_gt_pico_max_b7[] = { 0x18, 0x04, 0x00, 21, 0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC, 0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB };
// WebSocket Text Frame with RSV2 bit set (invalid if not negotiated)
static uint8_t test_frame_ws_text_rsv2_set[] = { 0xA1, 0x04, 't','e','s','t' }; // FIN=1, RSV2=1, Opcode=Text
// WebSocket Text Frame with RSV3 bit set (invalid if not negotiated)
static uint8_t test_frame_ws_text_rsv3_set[] = { 0x91, 0x04, 't','e','s','t' }; // FIN=1, RSV3=1, Opcode=Text
// QUIC ACK frame type 0x02 (no ECN) but with ECN count fields present (malformed)
static uint8_t test_frame_quic_ack_non_ecn_with_ecn_counts_b7[] = { 0x02, 0x0A, 0x00, 0x01, 0x00, 0x01, 0x01, 0x01 }; // LargestAck 10, Delay 0, RangeCount 1, FirstRange 0, then ECT0=1, ECT1=1, CE=1
// QUIC Greased Frame Type (e.g. 0x5BEE from RFC9000 Sec 15 pattern 0x?a?a?a?a + 0x21, here 0x5BEE = 42*N+27 for N=1450, not exactly greased but using a high value for test)
static uint8_t test_frame_quic_greased_type_0x5BEE_with_payload[] = { 0x5B, 0xEE, 0x01, 0x02, 0x03, 0x04 }; // Type 0x5BEE, then payload
// H3 Reserved Frame Type encoded with 4-byte varint (e.g. 0x80000020)
static uint8_t test_frame_h3_reserved_type_4byte_varint[] = { 0x80, 0x00, 0x00, 0x20, 0x00 }; // Type 0x20 (hypothetical reserved), Len 0
// WebSocket Continuation Frame (opcode 0x00) with FIN=1 (valid, but can be fuzzed for interaction)
static uint8_t test_frame_ws_continuation_fin1_with_payload[] = { 0x80, 0x04, 'c','o','n','t' };
// QUIC NEW_CONNECTION_ID with a very large RetirePriorTo value but small SequenceNumber
static uint8_t test_frame_quic_ncid_large_retire_small_seq[] = { 0x18, 0x05, 0xBF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0x08, 0xF1,0xF2,0xF3,0xF4,0xF5,0xF6,0xF7,0xF8, 0x91,0x92,0x93,0x94,0x95,0x96,0x97,0x98,0x99,0x9A,0x9B,0x9C,0x9D,0x9E,0x9F,0xA0 };
// QUIC frame type 0x21 (RFC 9000 reserved for extensions, potentially unhandled)
static uint8_t test_frame_quic_extension_0x21[] = { 0x21 };
// H3 frame type 0x2F (RFC 9114 reserved for extensions) with empty payload
static uint8_t test_frame_h3_extension_0x2F[] = { 0x2F, 0x00 };
// QUIC ACK frame with first ACK range having length 0, and then a Gap of 0, then another range of 0. (Ack Pkt N, N-1)
static uint8_t test_frame_quic_ack_double_zero_range[] = { 0x02, 0x0A, 0x00, 0x02, 0x00, 0x00, 0x00 };
// WebSocket frame with RSV1, RSV2, and RSV3 all set (highly unlikely to be negotiated)
static uint8_t test_frame_ws_all_rsv_set[] = { 0xF1, 0x04, 'd', 'a', 't', 'a' }; // FIN=1, RSV1-3=1, Opcode=Text

 /* END OF JULES ADDED FRAMES */

/* === ADVANCED PROTOCOL VIOLATION TEST CASES === */

/* HTTP/3 Protocol Violations */
// SETTINGS frame sent on request stream (protocol violation)
static uint8_t test_frame_h3_settings_frame_on_request_stream[] = { 0x04, 0x00 }; // SETTINGS on stream 0
// DATA frame without preceding HEADERS
static uint8_t test_frame_h3_data_frame_without_headers[] = { 0x00, 0x05, 'h', 'e', 'l', 'l', 'o' };
// HEADERS frame after TRAILERS (protocol violation)
static uint8_t test_frame_h3_headers_after_trailers[] = { 0x01, 0x00 }; // Empty HEADERS after trailers
// PUSH_PROMISE on unidirectional stream
static uint8_t test_frame_h3_push_promise_on_unidirectional[] = { 0x05, 0x01, 0x00 };
// GOAWAY with invalid stream ID
static uint8_t test_frame_h3_goaway_with_invalid_id[] = { 0x07, 0x03 }; // Stream ID 3 (invalid)
// MAX_PUSH_ID decrease (protocol violation)
static uint8_t test_frame_h3_max_push_id_decrease[] = { 0x0D, 0x01 }; // Decreased from previous value
// CANCEL_PUSH for non-existent push
static uint8_t test_frame_h3_cancel_push_nonexistent[] = { 0x03, 0xFF }; // Push ID 255 never promised
// Duplicate SETTINGS frame
static uint8_t test_frame_h3_duplicate_settings[] = { 0x04, 0x02, 0x01, 0x00, 0x01, 0x01 };
// Reserved setting values
static uint8_t test_frame_h3_reserved_setting_values[] = { 0x04, 0x02, 0x02, 0x01, 0x05, 0x01 };
// Wrong frame type on QPACK encoder stream
static uint8_t test_frame_h3_qpack_encoder_stream_wrong_type[] = { 0x00, 0x04, 't', 'e', 's', 't' };

/* WebSocket Protocol Violations */
// CONTINUATION without fragmented frame start
static uint8_t test_frame_ws_continuation_without_start[] = { 0x80, 0x04, 't', 'e', 's', 't' };
// TEXT frame after BINARY frame start
static uint8_t test_frame_ws_text_after_binary_start[] = { 0x81, 0x04, 't', 'e', 's', 't' };
// Control frame with fragmentation (invalid)
static uint8_t test_frame_ws_control_frame_fragmented[] = { 0x08, 0x04, 0x00, 0x00, 't', 'e' };
// CLOSE frame after previous CLOSE
static uint8_t test_frame_ws_close_after_close[] = { 0x88, 0x02, 0x03, 0xE8 };
// TEXT frame with invalid UTF-8
static uint8_t test_frame_ws_invalid_utf8_text[] = { 0x81, 0x04, 0xFF, 0xFE, 0xFD, 0xFC };
// Server-to-client frame with MASK bit set
static uint8_t test_frame_ws_mask_bit_server_to_client[] = { 0x81, 0x84, 0x00, 0x00, 0x00, 0x00, 't', 'e', 's', 't' };
// Client-to-server frame without MASK bit
static uint8_t test_frame_ws_unmask_bit_client_to_server[] = { 0x81, 0x04, 't', 'e', 's', 't' };
// CLOSE frame with reserved code 1005
static uint8_t test_frame_ws_invalid_close_code_1005[] = { 0x88, 0x02, 0x03, 0xED };
// CLOSE frame with reason but no code
static uint8_t test_frame_ws_close_reason_without_code[] = { 0x88, 0x06, 'r', 'e', 'a', 's', 'o', 'n' };
// PONG frame without corresponding PING
static uint8_t test_frame_ws_pong_without_ping[] = { 0x8A, 0x04, 't', 'e', 's', 't' };

/* QUIC Connection Migration Attacks */
// PATH_CHALLENGE with wrong destination CID
static uint8_t test_frame_quic_path_challenge_wrong_dcid[] = { 0x1A, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 };
// PATH_RESPONSE replay attack
static uint8_t test_frame_quic_path_response_replay_attack[] = { 0x1B, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
// NEW_CONNECTION_ID for migration attack
static uint8_t test_frame_quic_new_cid_migration_attack[] = { 0x18, 0xFF, 0x00, 0x08, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
// RETIRE_CONNECTION_ID for active path
static uint8_t test_frame_quic_retire_cid_active_path[] = { 0x19, 0x00 }; // Retiring active CID
// Path validation amplification attack
static uint8_t test_frame_quic_path_validation_amplification[] = { 0x1A, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
// Connection migration flood
static uint8_t test_frame_quic_connection_migration_flood[] = { 0x1A, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 };

/* QUIC Cryptographic Attacks */
// CRYPTO frame reordering attack
static uint8_t test_frame_quic_crypto_frame_reordering[] = { 0x06, 0x40, 0x64, 0x04, 't', 'e', 's', 't' }; // Offset 100
// CRYPTO frame with duplicate offset
static uint8_t test_frame_quic_crypto_duplicate_offset[] = { 0x06, 0x00, 0x04, 's', 'a', 'm', 'e' };
// CRYPTO frame gap attack
static uint8_t test_frame_quic_crypto_gap_attack[] = { 0x06, 0x40, 0xFF, 0x04, 'g', 'a', 'p', 's' };
// Handshake replay attack
static uint8_t test_frame_quic_handshake_replay[] = { 0x06, 0x00, 0x08, 0x16, 0x03, 0x03, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00 };
// Crypto downgrade attack
static uint8_t test_frame_quic_crypto_downgrade_attack[] = { 0x06, 0x00, 0x06, 0x16, 0x03, 0x01, 0x00, 0x02, 0x00, 0x00 };
// Early data replay attack
static uint8_t test_frame_quic_early_data_replay[] = { 0x08, 0x00, 'r', 'e', 'p', 'l', 'a', 'y' };

/* QUIC Flow Control Attacks */
// Flow control bypass attempt
static uint8_t test_frame_quic_flow_control_bypass[] = { 0x08, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 'd', 'a', 't', 'a' };
// MAX_DATA oscillation attack
static uint8_t test_frame_quic_max_data_oscillation[] = { 0x10, 0x40, 0x64 }; // Oscillating values
// Stream data blocked lie
static uint8_t test_frame_quic_stream_data_blocked_lie[] = { 0x15, 0x01, 0x32 }; // False blocked claim
// Premature data blocked claim
static uint8_t test_frame_quic_data_blocked_premature[] = { 0x14, 0x32 }; // Premature blocking
// Max streams exhaustion attack
static uint8_t test_frame_quic_max_streams_exhaustion[] = { 0x12, 0xFF, 0xFF, 0xFF, 0xFF };
// Stream limit bypass attempt
static uint8_t test_frame_quic_stream_limit_bypass[] = { 0x08, 0xFF, 0xFF, 0xFF, 0xFF, 't', 'e', 's', 't' };

/* QUIC Packet Number Space Violations */
// ACK in wrong packet number space
static uint8_t test_frame_quic_ack_wrong_pn_space[] = { 0x02, 0x00, 0x00, 0x00, 0x00 };
// CRYPTO in application space
static uint8_t test_frame_quic_crypto_in_app_space[] = { 0x06, 0x00, 0x04, 't', 'e', 's', 't' };
// HANDSHAKE_DONE too early
static uint8_t test_frame_quic_handshake_done_early[] = { 0x1E };
// 0-RTT in handshake packet number space
static uint8_t test_frame_quic_0rtt_in_handshake_pn[] = { 0x08, 0x00, 'e', 'a', 'r', 'l', 'y' };
// STREAM in initial packet number space
static uint8_t test_frame_quic_stream_in_initial_pn[] = { 0x08, 0x00, 'i', 'n', 'i', 't' };

/* Advanced Varint Fuzzing */
// Varint canonical form violation
static uint8_t test_frame_quic_varint_canonical_violation[] = { 0x10, 0x40, 0x00 }; // Non-canonical encoding
// Varint length mismatch
static uint8_t test_frame_quic_varint_length_mismatch[] = { 0x10, 0x80, 0x01 }; // Wrong length prefix
// Varint with reserved bits set
static uint8_t test_frame_quic_varint_reserved_bits[] = { 0x10, 0xF0, 0x01 }; // Reserved bits set
// Varint maximum value plus one
static uint8_t test_frame_quic_varint_maximum_plus_one[] = { 0x10, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
// Varint underflow
static uint8_t test_frame_quic_varint_underflow[] = { 0x10, 0x00 }; // Underflow attempt

/* DoS and Resource Exhaustion */
// Memory exhaustion via stream IDs
static uint8_t test_frame_quic_memory_exhaustion_stream_ids[] = { 0x08, 0xFF, 0xFF, 0xFF, 0xFC, 'd', 'a', 't', 'a' };
// CPU exhaustion via ACK ranges
static uint8_t test_frame_quic_cpu_exhaustion_ack_ranges[] = { 0x02, 0xFF, 0x00, 0xFF, 0xFF, 0x01, 0x00, 0x01, 0x00 };
// Bandwidth exhaustion via padding
static uint8_t test_frame_quic_bandwidth_exhaustion_padding[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
// Connection table exhaustion
static uint8_t test_frame_quic_connection_table_exhaustion[] = { 0x18, 0xFF, 0xFF, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20 };
// Token cache pollution
static uint8_t test_frame_quic_token_cache_pollution[] = { 0x07, 0x10, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

/* State Machine Confusion */
// STREAM after CONNECTION_CLOSE
static uint8_t test_frame_quic_stream_after_connection_close[] = { 0x08, 0x01, 'b', 'a', 'd' };
// ACK after CONNECTION_CLOSE
static uint8_t test_frame_quic_ack_after_connection_close[] = { 0x02, 0x01, 0x00, 0x00, 0x00 };
// NEW_TOKEN after migration
static uint8_t test_frame_quic_new_token_after_migration[] = { 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
// PATH_CHALLENGE after close
static uint8_t test_frame_quic_path_challenge_after_close[] = { 0x1A, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
// HANDSHAKE_DONE sent twice
static uint8_t test_frame_quic_handshake_done_twice[] = { 0x1E };

/* Covert Channel Attacks */
// Timing channel via ACK delay
static uint8_t test_frame_quic_timing_channel_ack_delay[] = { 0x02, 0x01, 0xFF, 0xFF, 0xFF, 0x00, 0x00 };
// Padding pattern channel
static uint8_t test_frame_quic_padding_pattern_channel[] = { 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01 };
// Stream ID pattern channel
static uint8_t test_frame_quic_stream_id_pattern_channel[] = { 0x08, 0xAA, 'd', 'a', 't', 'a' };
// Error code channel
static uint8_t test_frame_quic_error_code_channel[] = { 0x1C, 0xDE, 0xAD, 0x00, 0x00 };
// Frame ordering channel
static uint8_t test_frame_quic_frame_ordering_channel[] = { 0x01, 0x08, 0x01, 'X' };

/* Protocol Downgrade Attacks */
// Version downgrade MITM
static uint8_t test_frame_quic_version_downgrade_mitm[] = { 0x1C, 0x0B, 0x00, 0x00, 'v', 'e', 'r', 's', 'i', 'o', 'n' };
// Transport parameter downgrade
static uint8_t test_frame_quic_transport_parameter_downgrade[] = { 0x06, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00 };
// Extension downgrade
static uint8_t test_frame_quic_extension_downgrade[] = { 0x40, 0x52, 0x04, 0x00, 0x00, 0x00, 0x00 };
// Cipher suite downgrade
static uint8_t test_frame_quic_cipher_suite_downgrade[] = { 0x06, 0x00, 0x06, 0x16, 0x03, 0x03, 0x00, 0x02, 0x00, 0x00 };

/* Side Channel Attacks */
// Cache timing attack vector
static uint8_t test_frame_quic_cache_timing_attack[] = { 0x08, 0x01, 0xCA, 0xCE, 0xCA, 0xCE };
// Branch prediction attack
static uint8_t test_frame_quic_branch_prediction_attack[] = { 0x02, 0x55, 0xAA, 0x01, 0x00 };
// Memory access pattern analysis
static uint8_t test_frame_quic_memory_access_pattern[] = { 0x10, 0x80, 0x00, 0x00, 0x01 };
// Power analysis resistant test
static uint8_t test_frame_quic_power_analysis_resistant[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

/* Implementation-Specific Edge Cases */
// Buffer boundary edge case
static uint8_t test_frame_quic_buffer_boundary_edge[] = { 0x08, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
// Alignment requirement violation
static uint8_t test_frame_quic_alignment_requirement_violation[] = { 0x10, 0x01, 0x02, 0x03 }; // Misaligned data
// Endianness confusion
static uint8_t test_frame_quic_endianness_confusion[] = { 0x10, 0x12, 0x34, 0x56, 0x78 };
// Stack overflow trigger
static uint8_t test_frame_quic_stack_overflow_trigger[] = { 0x02, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
// Heap overflow trigger
static uint8_t test_frame_quic_heap_overflow_trigger[] = { 0x31, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0x00 };

/* === ADDITIONAL ADVANCED ATTACK VECTORS === */

/* HTTP/2 Specific Violations */
// HTTP/2 HEADERS frame with invalid padding
static uint8_t test_frame_h2_headers_invalid_padding[] = { 0x00, 0x00, 0x05, 0x01, 0x08, 0x00, 0x00, 0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
// HTTP/2 DATA frame with invalid padding length
static uint8_t test_frame_h2_data_invalid_padding_len[] = { 0x00, 0x00, 0x06, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x10, 'd', 'a', 't', 'a', 0x00 };
// HTTP/2 PRIORITY frame with self-dependency
static uint8_t test_frame_h2_priority_self_dependency[] = { 0x00, 0x00, 0x05, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x80, 0x00, 0x00, 0x01, 0x10 };
// HTTP/2 WINDOW_UPDATE with zero increment
static uint8_t test_frame_h2_window_update_zero_increment[] = { 0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 };
// HTTP/2 SETTINGS ACK with payload
static uint8_t test_frame_h2_settings_ack_with_payload[] = { 0x00, 0x00, 0x06, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x10, 0x00 };
// HTTP/2 GOAWAY with invalid last stream ID
static uint8_t test_frame_h2_goaway_invalid_last_stream[] = { 0x00, 0x00, 0x08, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02 };
// HTTP/2 RST_STREAM with invalid error code
static uint8_t test_frame_h2_rst_stream_invalid_error[] = { 0x00, 0x00, 0x04, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFF };
// HTTP/2 PUSH_PROMISE with invalid promised ID
static uint8_t test_frame_h2_push_promise_invalid_id[] = { 0x00, 0x00, 0x04, 0x05, 0x00, 0x00, 0x00, 0x00, 0x01, 0x80, 0x00, 0x00, 0x00 };
// HTTP/2 CONTINUATION without HEADERS
static uint8_t test_frame_h2_continuation_without_headers[] = { 0x00, 0x00, 0x04, 0x09, 0x04, 0x00, 0x00, 0x00, 0x01, 't', 'e', 's', 't' };
// HTTP/2 Frame with reserved flags set
static uint8_t test_frame_h2_reserved_flags_set[] = { 0x00, 0x00, 0x00, 0x00, 0xF0, 0x00, 0x00, 0x00, 0x01 };

/* QPACK Specific Attacks */
// QPACK encoder stream with invalid instruction
static uint8_t test_frame_qpack_encoder_invalid_instruction[] = { 0xFF, 0xFF, 0xFF, 0xFF };
// QPACK decoder stream with malformed header block ACK
static uint8_t test_frame_qpack_decoder_malformed_ack[] = { 0x80, 0xFF, 0xFF };
// QPACK dynamic table size update overflow
static uint8_t test_frame_qpack_table_size_overflow[] = { 0x3F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
// QPACK literal header field with invalid name index
static uint8_t test_frame_qpack_invalid_name_index[] = { 0x5F, 0xFF, 0xFF, 0xFF, 0xFF, 0x04, 't', 'e', 's', 't' };
// QPACK duplicate instruction with invalid index
static uint8_t test_frame_qpack_duplicate_invalid_index[] = { 0x1F, 0xFF, 0xFF, 0xFF, 0xFF };
// QPACK header block with circular reference
static uint8_t test_frame_qpack_circular_reference[] = { 0xC0, 0xFF, 0xFF, 0xFF, 0xFF };
// QPACK encoder stream cancellation out of order
static uint8_t test_frame_qpack_cancellation_out_of_order[] = { 0x40, 0xFF, 0xFF, 0xFF, 0xFF };
// QPACK insert count increment overflow
static uint8_t test_frame_qpack_insert_count_overflow[] = { 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

/* Multi-Protocol Confusion Attacks */
// TLS Alert in QUIC CRYPTO frame
static uint8_t test_frame_tls_alert_in_crypto[] = { 0x06, 0x00, 0x02, 0x15, 0x02 }; // TLS fatal alert
// HTTP/1.1 request in QUIC STREAM
static uint8_t test_frame_http1_in_quic_stream[] = { 0x08, 0x00, 'G', 'E', 'T', ' ', '/', ' ', 'H', 'T', 'T', 'P', '/', '1', '.', '1', '\r', '\n', '\r', '\n' };
// SMTP command in QUIC STREAM
static uint8_t test_frame_smtp_in_quic_stream[] = { 0x08, 0x01, 'H', 'E', 'L', 'O', ' ', 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm' };
// DNS query in DATAGRAM frame
static uint8_t test_frame_dns_in_datagram[] = { 0x30, 0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01 };
// FTP command in STREAM frame
static uint8_t test_frame_ftp_in_stream[] = { 0x08, 0x02, 'U', 'S', 'E', 'R', ' ', 'a', 'n', 'o', 'n', 'y', 'm', 'o', 'u', 's' };
// RTSP request in STREAM frame
static uint8_t test_frame_rtsp_in_stream[] = { 0x08, 0x03, 'O', 'P', 'T', 'I', 'O', 'N', 'S', ' ', 'r', 't', 's', 'p', ':', '/', '/', 'e', 'x', 'a', 'm', 'p', 'l', 'e' };
// SIP INVITE in STREAM frame
static uint8_t test_frame_sip_in_stream[] = { 0x08, 0x04, 'I', 'N', 'V', 'I', 'T', 'E', ' ', 's', 'i', 'p', ':', 'u', 's', 'e', 'r', '@', 'e', 'x', 'a', 'm', 'p', 'l', 'e' };

/* Advanced WebSocket Edge Cases */
// WebSocket frame with invalid payload length encoding
static uint8_t test_frame_ws_invalid_payload_len_encoding[] = { 0x81, 0x7E, 0x00, 0x00 };
// WebSocket PING frame exceeding 125 bytes
static uint8_t test_frame_ws_ping_oversized[] = { 0x89, 0x7E, 0x00, 0x80, /* 128 bytes of data */ 0x00, 0x01, 0x02, 0x03 };
// WebSocket close frame with truncated reason
static uint8_t test_frame_ws_close_truncated_reason[] = { 0x88, 0x04, 0x03, 0xE8, 't', 'e' };
// WebSocket frame with mask key all zeros
static uint8_t test_frame_ws_mask_key_all_zeros[] = { 0x81, 0x84, 0x00, 0x00, 0x00, 0x00, 't', 'e', 's', 't' };
// WebSocket frame with predictable mask pattern
static uint8_t test_frame_ws_predictable_mask[] = { 0x81, 0x84, 0xAA, 0xAA, 0xAA, 0xAA, 0xDE, 0xDE, 0xDE, 0xDE };
// WebSocket binary frame with text-like content
static uint8_t test_frame_ws_binary_text_content[] = { 0x82, 0x05, 'h', 'e', 'l', 'l', 'o' };
// WebSocket text frame with binary-like content
static uint8_t test_frame_ws_text_binary_content[] = { 0x81, 0x04, 0x00, 0x01, 0x02, 0x03 };

/* Packet Fragmentation and Reassembly Attacks */
// QUIC STREAM frame with overlapping data ranges
static uint8_t test_frame_stream_overlapping_ranges[] = { 0x0C, 0x01, 0x02, 'A', 'B', 'C' }; // Overlaps with previous
// CRYPTO frame with gap in offset sequence
static uint8_t test_frame_crypto_gap_in_sequence[] = { 0x06, 0x40, 0xC8, 0x04, 'g', 'a', 'p', 's' }; // Offset 200
// STREAM frame with data beyond final size
static uint8_t test_frame_stream_data_beyond_final[] = { 0x0F, 0x01, 0x40, 0x64, 0x05, 'e', 'x', 't', 'r', 'a' };
// Multiple STREAM frames with same offset
static uint8_t test_frame_stream_duplicate_offset[] = { 0x0C, 0x01, 0x00, 'd', 'u', 'p', 'e' };
// STREAM frame with zero-length at non-zero offset
static uint8_t test_frame_stream_zero_len_nonzero_offset[] = { 0x0E, 0x01, 0x10, 0x00 };

/* Version Negotiation Attacks */
// Version negotiation with invalid version list
static uint8_t test_frame_version_negotiation_invalid[] = { 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF };
// Retry packet with invalid version
static uint8_t test_frame_retry_invalid_version[] = { 0x00, 0x00, 0x00, 0x00 };
// Version negotiation downgrade attack
static uint8_t test_frame_version_downgrade[] = { 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02 };
// Version negotiation with duplicate versions
static uint8_t test_frame_version_duplicates[] = { 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01 };

/* Transport Parameter Manipulation */
// Invalid transport parameter ID
static uint8_t test_frame_invalid_transport_param[] = { 0x06, 0x00, 0x04, 0xFF, 0xFF, 0x00, 0x00 };
// Transport parameter with invalid length
static uint8_t test_frame_transport_param_invalid_len[] = { 0x06, 0x00, 0x06, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00 };
// Duplicate transport parameter
static uint8_t test_frame_duplicate_transport_param[] = { 0x06, 0x00, 0x08, 0x01, 0x02, 0x10, 0x00, 0x01, 0x02, 0x10, 0x00 };
// Transport parameter with reserved value
static uint8_t test_frame_reserved_transport_param[] = { 0x06, 0x00, 0x04, 0x1F, 0x02, 0xFF, 0xFF };

/* Key Update Attacks */
// Premature key update
static uint8_t test_frame_premature_key_update[] = { 0x08, 0x00, 'e', 'a', 'r', 'l', 'y' }; // Before handshake complete
// Excessive key update frequency
static uint8_t test_frame_excessive_key_updates[] = { 0x08, 0x01, 'u', 'p', 'd', 'a', 't', 'e', '1' };
// Key update with old key
static uint8_t test_frame_key_update_old_key[] = { 0x08, 0x02, 'o', 'l', 'd', 'k', 'e', 'y' };
// Key update rollback attack
static uint8_t test_frame_key_update_rollback[] = { 0x08, 0x03, 'r', 'o', 'l', 'l', 'b', 'a', 'c', 'k' };

/* Connection ID Rotation Attacks */
// NEW_CONNECTION_ID with predictable sequence
static uint8_t test_frame_cid_predictable_sequence[] = { 0x18, 0x10, 0x0F, 0x08, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F };
// Connection ID rotation DoS
static uint8_t test_frame_cid_rotation_dos[] = { 0x18, 0xFF, 0xFE, 0x08, 0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8, 0xF7, 0xF6, 0xF5, 0xF4, 0xF3, 0xF2, 0xF1, 0xF0, 0xEF, 0xEE, 0xED, 0xEC, 0xEB, 0xEA, 0xE9, 0xE8 };
// RETIRE_CONNECTION_ID flood
static uint8_t test_frame_retire_cid_flood[] = { 0x19, 0xFF, 0xFF, 0xFF, 0xFF };
// Connection ID collision attack
static uint8_t test_frame_cid_collision_attack[] = { 0x18, 0x20, 0x00, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };

/* Token Validation Attacks */
// NEW_TOKEN with expired timestamp
static uint8_t test_frame_token_expired[] = { 0x07, 0x10, 0x00, 0x00, 0x00, 0x01, 0x60, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
// NEW_TOKEN with invalid signature
static uint8_t test_frame_token_invalid_signature[] = { 0x07, 0x20, 0xBA, 0xD5, 0x16, 0x7A, 0x7E, 0xC4, 0x02, 0x8F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
// Token replay attack
static uint8_t test_frame_token_replay[] = { 0x07, 0x08, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE };
// Token with malformed structure
static uint8_t test_frame_token_malformed_structure[] = { 0x07, 0x0C, 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00 };

/* Congestion Control Attacks */
// ACK frame with manipulated ECN counts
static uint8_t test_frame_ack_manipulated_ecn[] = { 0x03, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
// DATA_BLOCKED with false congestion signal
static uint8_t test_frame_false_congestion_signal[] = { 0x14, 0x01 }; // False signal
// Congestion window probing attack
static uint8_t test_frame_cwnd_probing_attack[] = { 0x08, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 'p', 'r', 'o', 'b', 'e' };
// Loss detection manipulation
static uint8_t test_frame_loss_detection_manipulation[] = { 0x02, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00 };

/* Advanced Timing Attacks */
// ACK delay manipulation for timing inference
static uint8_t test_frame_ack_delay_timing_inference[] = { 0x02, 0x01, 0xC0, 0x00, 0x00, 0x27, 0x10, 0x00, 0x00 };
// PING frame timing correlation
static uint8_t test_frame_ping_timing_correlation[] = { 0x01 }; // Timing-sensitive PING
// PATH_CHALLENGE timing side-channel
static uint8_t test_frame_path_challenge_timing_sidechannel[] = { 0x1A, 0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78 };
// Connection close timing attack
static uint8_t test_frame_connection_close_timing[] = { 0x1C, 0x01, 0x00, 0x00, 't', 'i', 'm', 'i', 'n', 'g' };

/* Memory Layout Attacks */
// Frame designed to trigger memory alignment issues
static uint8_t test_frame_memory_alignment_attack[] = { 0x08, 0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 }; // Odd alignment
// Frame with pointer-like values
static uint8_t test_frame_pointer_like_values[] = { 0x10, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
// Frame targeting specific memory regions
static uint8_t test_frame_memory_region_targeting[] = { 0x18, 0x00, 0x00, 0x08, 0x40, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
// Frame with return address-like patterns
static uint8_t test_frame_return_address_pattern[] = { 0x08, 0x01, 0x41, 0x41, 0x41, 0x41, 0x42, 0x42, 0x42, 0x42 };

/* === SPECIALIZED ATTACK VECTORS === */

/* DNS over QUIC (DoQ) Attacks */
static uint8_t test_frame_doq_malformed_query[] = { 0x08, 0x00, 0xFF, 0xFF, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00 };
static uint8_t test_frame_doq_amplification_attack[] = { 0x08, 0x01, 0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 'a', 'n', 'y', 0x00, 0x00, 0xFF, 0x00, 0x01 };
static uint8_t test_frame_doq_cache_poisoning[] = { 0x08, 0x02, 0xBA, 0xD1, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01 };

/* WebTransport Attacks */
static uint8_t test_frame_webtransport_invalid_session[] = { 0x41, 0x19, 0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00 };
static uint8_t test_frame_webtransport_stream_hijack[] = { 0x08, 0x42, 'h', 'i', 'j', 'a', 'c', 'k' };
static uint8_t test_frame_webtransport_capsule_bomb[] = { 0x08, 0x43, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

/* MASQUE Proxy Attacks */
static uint8_t test_frame_masque_connect_udp_spoof[] = { 0x08, 0x00, 'C', 'O', 'N', 'N', 'E', 'C', 'T', '-', 'U', 'D', 'P' };
static uint8_t test_frame_masque_ip_spoofing[] = { 0x08, 0x01, 0xC0, 0xA8, 0x01, 0x01, 0x00, 0x50 };
static uint8_t test_frame_masque_proxy_loop[] = { 0x08, 0x02, 'l', 'o', 'o', 'p', 'b', 'a', 'c', 'k' };

/* ECN Marking Attacks */
static uint8_t test_frame_ecn_bleaching_attack[] = { 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
static uint8_t test_frame_ecn_remarking_attack[] = { 0x03, 0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
static uint8_t test_frame_ecn_reflection_attack[] = { 0x02, 0x01, 0x00, 0x00, 0x00, 0x03, 0x03, 0x03 };

/* Multipath QUIC Attacks */
static uint8_t test_frame_mp_quic_path_scheduling_attack[] = { 0x1A, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11 };
static uint8_t test_frame_mp_quic_reinjection_attack[] = { 0x08, 0x01, 'r', 'e', 'i', 'n', 'j', 'e', 'c', 't' };
static uint8_t test_frame_mp_quic_path_confusion[] = { 0x1B, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };

/* Session Resumption Attacks */
static uint8_t test_frame_session_ticket_forge[] = { 0x07, 0x20, 0xF0, 0xED, 0xBE, 0xEF, 0xCA, 0xFE, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x01 };
static uint8_t test_frame_psk_confusion_attack[] = { 0x06, 0x00, 0x10, 0x16, 0x03, 0x03, 0x00, 0x0C, 0x02, 0x00, 0x08, 0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00 };
static uint8_t test_frame_resumption_replay[] = { 0x07, 0x10, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x01 };

/* Post-Quantum Crypto Attacks */
static uint8_t test_frame_pqc_hybrid_downgrade[] = { 0x06, 0x00, 0x08, 0x16, 0x03, 0x03, 0x00, 0x04, 0x0B, 0x00, 0x02, 0x00 };
static uint8_t test_frame_pqc_kyber_malleability[] = { 0x06, 0x00, 0x40, /* Kyber ciphertext */ 0xBA, 0xD1, 0x23, 0x45 };
static uint8_t test_frame_pqc_dilithium_forge[] = { 0x06, 0x00, 0x80, /* Dilithium signature */ 0xF0, 0xED, 0xBE, 0xEF };

/* Anti-Forensics Techniques */
static uint8_t test_frame_forensics_metadata_scrub[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
static uint8_t test_frame_forensics_traffic_shaping[] = { 0x08, 0x01, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE };
static uint8_t test_frame_forensics_flow_correlation[] = { 0x01, /* Timing-sensitive pattern */ };

/* Hardware-Specific Attacks */
static uint8_t test_frame_cpu_cache_eviction[] = { 0x08, 0x01, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00 };
static uint8_t test_frame_branch_predictor_poison[] = { 0x02, 0xAA, 0x55, 0xAA, 0x55, 0x00, 0x00, 0x00 };
static uint8_t test_frame_speculative_execution[] = { 0x10, 0x40, 0x00, 0x00, 0x01 };

/* ML Evasion Techniques */
static uint8_t test_frame_ml_adversarial_padding[] = { 0x00, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x00 };
static uint8_t test_frame_ml_feature_poisoning[] = { 0x08, 0x01, 0x7F, 0x7F, 0x7F, 0x7F, 0x80, 0x80 };
static uint8_t test_frame_ml_model_inversion[] = { 0x1C, 0x01, 0x00, 0x00, 'i', 'n', 'v', 'e', 'r', 't' };

/* === MISSING TEST FRAME DECLARATIONS === */

/* Memory Safety Attacks */
static uint8_t test_frame_format_string_attack[] = { 0x08, 0x01, '%', 's', '%', 'x', '%', 'n', '%', 'd' };
static uint8_t test_frame_integer_wraparound[] = { 0x10, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
static uint8_t test_frame_off_by_one_trigger[] = { 0x08, 0x01, 0xFF, 'A', 'A', 'A', 'A' };
static uint8_t test_frame_use_after_free_pattern[] = { 0x08, 0x02, 0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED, 0xFA, 0xCE };
static uint8_t test_frame_double_free_trigger[] = { 0x19, 0x01 };

/* === COMPREHENSIVE NEGATIVE TEST CASES AND ADDITIONAL EDGE CASES === */

/* Frame Type Boundary Testing */
// Frame type at exact boundary values
static uint8_t test_frame_type_boundary_0x3F[] = { 0x3F }; // Highest 1-byte varint
static uint8_t test_frame_type_boundary_0x4000[] = { 0x40, 0x00 }; // Lowest 2-byte varint
static uint8_t test_frame_type_boundary_0x7FFF[] = { 0x7F, 0xFF }; // Highest 2-byte varint
static uint8_t test_frame_type_boundary_0x80000000[] = { 0x80, 0x00, 0x00, 0x00 }; // Lowest 4-byte varint
static uint8_t test_frame_type_boundary_0xBFFFFFFF[] = { 0xBF, 0xFF, 0xFF, 0xFF }; // Highest 4-byte varint

/* Stream State Violations */
// STREAM frame after RESET_STREAM sent (state violation)
static uint8_t test_stream_after_reset_violation[] = { 0x08, 0x01, 'b', 'a', 'd' }; // Stream 1 data after reset
// STOP_SENDING after stream finished (state violation)
static uint8_t test_stop_sending_after_fin_violation[] = { 0x05, 0x01, 0x00 }; // Stream 1 already finished
// MAX_STREAM_DATA for closed stream (state violation)
static uint8_t test_max_stream_data_closed_stream[] = { 0x11, 0x01, 0x41, 0x00 }; // Stream 1 closed

/* Flow Control Edge Cases */
// MAX_DATA smaller than current data sent
static uint8_t test_max_data_regression[] = { 0x10, 0x32 }; // 50 bytes, less than already sent
// MAX_STREAM_DATA smaller than current stream data
static uint8_t test_max_stream_data_regression[] = { 0x11, 0x01, 0x32 }; // Stream 1, 50 bytes
// STREAM data exceeding announced MAX_DATA
static uint8_t test_stream_exceed_max_data[] = { 0x0A, 0x01, 0xFF, 0xFF, 'd','a','t','a' }; // Huge length

/* Connection ID Management Violations */
// NEW_CONNECTION_ID with sequence number regression
static uint8_t test_new_cid_seq_regression[] = { 0x18, 0x01, 0x05, 0x08, 0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA, 0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB };
// RETIRE_CONNECTION_ID for non-existent sequence
static uint8_t test_retire_cid_nonexistent[] = { 0x19, 0xFF }; // Sequence 255 never announced
// NEW_CONNECTION_ID with identical CID to existing
static uint8_t test_new_cid_duplicate_cid[] = { 0x18, 0x03, 0x00, 0x08, 0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08, 0xC1,0xC2,0xC3,0xC4,0xC5,0xC6,0xC7,0xC8,0xC9,0xCA,0xCB,0xCC,0xCD,0xCE,0xCF,0xD0 };

/* Frame Fragmentation Attacks */
// Partial frame (truncated mid-field)
static uint8_t test_frame_partial_stream[] = { 0x0F, 0x01, 0x40 }; // STREAM frame cut off in offset field
// Partial varint (incomplete encoding)
static uint8_t test_frame_partial_varint[] = { 0x10, 0x80 }; // MAX_DATA with incomplete 2-byte varint
// Frame with missing required fields
static uint8_t test_frame_missing_fields[] = { 0x04, 0x01 }; // RESET_STREAM missing error code and final size

/* Varint Encoding Attacks */
// Varint with excessive leading zeros
static uint8_t test_varint_excessive_zeros[] = { 0x10, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }; // MAX_DATA value 1 in 8 bytes
// Varint encoding edge case (exactly at boundary)
static uint8_t test_varint_boundary_63[] = { 0x10, 0x3F }; // MAX_DATA value 63 (boundary)
// Varint encoding edge case (exactly at boundary + 1)
static uint8_t test_varint_boundary_64[] = { 0x10, 0x40, 0x40 }; // MAX_DATA value 64 (boundary + 1)

/* Timing Attack Vectors */
// ACK with unusual timing patterns (potential timing analysis)
static uint8_t test_ack_timing_pattern[] = { 0x02, 0x64, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x00 }; // Large delay pattern
// PATH_CHALLENGE with predictable timing
static uint8_t test_path_challenge_timing[] = { 0x1a, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02 }; // Predictable sequence

/* Resource Exhaustion Patterns */
// Many small STREAM frames for same stream
static uint8_t test_stream_fragment_spam1[] = { 0x0C, 0x01, 0x00, 'A' }; // Offset 0
static uint8_t test_stream_fragment_spam2[] = { 0x0C, 0x01, 0x01, 'B' }; // Offset 1
static uint8_t test_stream_fragment_spam3[] = { 0x0C, 0x01, 0x02, 'C' }; // Offset 2
// Rapid fire NEW_CONNECTION_ID frames
static uint8_t test_rapid_new_cid1[] = { 0x18, 0x10, 0x00, 0x08, 0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10, 0xE1,0xE1,0xE1,0xE1,0xE1,0xE1,0xE1,0xE1,0xE1,0xE1,0xE1,0xE1,0xE1,0xE1,0xE1,0xE1 };
static uint8_t test_rapid_new_cid2[] = { 0x18, 0x11, 0x00, 0x08, 0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11, 0xE2,0xE2,0xE2,0xE2,0xE2,0xE2,0xE2,0xE2,0xE2,0xE2,0xE2,0xE2,0xE2,0xE2,0xE2,0xE2 };

/* Protocol State Machine Violations */
// HANDSHAKE_DONE in wrong packet number space
static uint8_t test_handshake_done_wrong_space[] = { 0x1e }; // In Initial/Handshake space
// CRYPTO frame in Application space after handshake
static uint8_t test_crypto_post_handshake[] = { 0x06, 0x00, 0x04, 't', 'e', 's', 't' };
// ACK_FREQUENCY before handshake complete
static uint8_t test_ack_frequency_early[] = { 0x40, 0xAF, 0x01, 0x01, 0x00, 0x00, 0x00 }; // Draft extension

/* Frame Size Manipulation */
// Extremely large frame claims
static uint8_t test_frame_size_bomb[] = { 0x31, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01 }; // DATAGRAM claiming max size
// Zero-size frames with non-zero claims
static uint8_t test_frame_zero_size_claim[] = { 0x31, 0x40, 0x64 }; // DATAGRAM length 100, no data

/* Cross-Protocol Confusion */
// HTTP/2 frame patterns in QUIC STREAM
static uint8_t test_h2_in_quic_stream[] = { 0x08, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 }; // H2 HEADERS frame pattern
// WebSocket frame patterns in QUIC STREAM  
static uint8_t test_ws_in_quic_stream[] = { 0x08, 0x01, 0x81, 0x05, 'h', 'e', 'l', 'l', 'o' }; // WS Text frame pattern
// TLS record patterns in CRYPTO frame
static uint8_t test_tls_record_pattern[] = { 0x06, 0x00, 0x05, 0x16, 0x03, 0x03, 0x00, 0x01 }; // TLS handshake record start

/* Integer Overflow Attempts */
// Values designed to cause integer overflow in calculations
static uint8_t test_overflow_offset_plus_len[] = { 0x0F, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 'X' }; // Max offset + large len
// ACK range calculations that might overflow
static uint8_t test_overflow_ack_range[] = { 0x02, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

/* Extension Frame Spoofing */
// Frames that look like legitimate extensions but aren't
static uint8_t test_fake_extension_frame[] = { 0x40, 0x52, 0x05, 0x01, 0x02, 0x03, 0x04 }; // Fake frame type with payload
// Greased frame types with malicious patterns
static uint8_t test_malicious_grease[] = { 0x1A, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE }; // Suspicious payload pattern

/* Path Validation Exploits */
// PATH_CHALLENGE with all identical bytes
static uint8_t test_path_challenge_identical[] = { 0x1a, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA };
// PATH_RESPONSE with wrong challenge data
static uint8_t test_path_response_wrong[] = { 0x1b, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 };

/* Token Management Attacks */
// NEW_TOKEN with malformed token structure
static uint8_t test_new_token_malformed[] = { 0x07, 0x10, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
// NEW_TOKEN with token containing NULL bytes
static uint8_t test_new_token_null_bytes[] = { 0x07, 0x08, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04 };

/* Stream Limit Boundary Testing */
// Stream ID exactly at client/server boundary
static uint8_t test_stream_boundary_client[] = { 0x08, 0xFC, 'd', 'a', 't', 'a' }; // Stream ID -4 (client uni)
static uint8_t test_stream_boundary_server[] = { 0x08, 0xFD, 'd', 'a', 't', 'a' }; // Stream ID -3 (server uni)
// Stream operations on wrong stream types
static uint8_t test_bidi_ops_on_uni[] = { 0x05, 0x02, 0x00 }; // STOP_SENDING on uni stream

/* Congestion Control Attacks */
// Rapid MAX_DATA increases (bandwidth probing)
static uint8_t test_rapid_max_data_increase[] = { 0x10, 0xFF, 0xFF, 0xFF, 0xFF }; // Sudden large increase
// DATA_BLOCKED with suspicious values
static uint8_t test_suspicious_data_blocked[] = { 0x14, 0x01 }; // Blocked at 1 byte

/* Frame Ordering Violations */
// ACK frame acknowledging future packets
static uint8_t test_ack_future_packets[] = { 0x02, 0xFF, 0xFF, 0x00, 0x01, 0x00 }; // ACK packet 65535
// CRYPTO frame with decreasing offset (reordering)
static uint8_t test_crypto_reorder[] = { 0x06, 0x32, 0x04, 'l', 'a', 't', 'e' }; // Offset 50 after higher offset

/* Padding Pattern Analysis */
// Padding with non-zero patterns (covert channel)
static uint8_t test_padding_covert_channel[] = { 0x00, 0x01, 0x00, 0x01, 0x00, 0x01 }; // Pattern in padding
// Mixed padding and other frames
static uint8_t test_padding_frame_mix[] = { 0x00, 0x01, 0x00, 0x08, 0x01, 'X', 0x00, 0x00 }; // PADDING, PING, PADDING, STREAM, PADDING

/* Memory Exhaustion Patterns */
// Many overlapping STREAM fragments
static uint8_t test_overlap_fragment1[] = { 0x0C, 0x01, 0x00, 'A','A','A','A' }; // Offset 0-3
static uint8_t test_overlap_fragment2[] = { 0x0C, 0x01, 0x02, 'B','B','B','B' }; // Offset 2-5 (overlap)
static uint8_t test_overlap_fragment3[] = { 0x0C, 0x01, 0x01, 'C','C','C','C' }; // Offset 1-4 (overlap)

/* Version Negotiation Confusion */
// Frames that might confuse version negotiation
static uint8_t test_version_confusion[] = { 0x40, 0x00, 0x00, 0x00, 0x00, 0x01 }; // Looks like version negotiation

/* Error Code Enumeration */
// CONNECTION_CLOSE with every possible error code
static uint8_t test_conn_close_enum_error[] = { 0x1c, 0x40, 0xFF, 0x00, 0x00 }; // Error code 255

/* Additional QUIC Negative Test Cases for Comprehensive Fuzzing */

// CRYPTO frame with offset exceeding limits  
static uint8_t test_frame_quic_crypto_offset_max[] = { 0x06, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x04, 't', 'e', 's', 't' };

// STREAM frame with invalid final size (smaller than offset)
static uint8_t test_frame_quic_stream_invalid_final_size[] = { 0x0f, 0x01, 0x0A, 0x05, 't', 'e', 's', 't' };

// ACK frame with packet number overflow
static uint8_t test_frame_quic_ack_pkt_overflow[] = { 0x02, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x01, 0x00 };

// HANDSHAKE_DONE in wrong context
static uint8_t test_frame_quic_handshake_done_invalid[] = { 0x1e };

// Multiple HANDSHAKE_DONE frames
static uint8_t test_frame_quic_multiple_handshake_done[] = { 0x1e, 0x1e };

// STREAM frame with maximum stream ID
static uint8_t test_frame_quic_stream_id_maximum[] = { 0x08, 0xBF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC, 'd', 'a', 't', 'a' };

// PING frame in wrong packet type context
static uint8_t test_frame_quic_ping_invalid_context[] = { 0x01 };

// CONNECTION_CLOSE with maximum error code
static uint8_t test_frame_quic_conn_close_max_err[] = { 0x1c, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00 };

// RESET_STREAM after FIN violation
static uint8_t test_frame_quic_reset_after_fin_violation[] = { 0x04, 0x01, 0x00, 0x04 };

// Unknown frame types for stress testing
static uint8_t test_frame_quic_unknown_type_0x40[] = { 0x40, 0x00 };
static uint8_t test_frame_quic_unknown_type_0x41[] = { 0x41, 0x01, 0x02 };
static uint8_t test_frame_quic_unknown_type_0x42[] = { 0x42, 0x03, 0x04, 0x05 };

// PATH_RESPONSE with incorrect data
static uint8_t test_frame_quic_path_response_incorrect[] = { 0x1b, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 };

// STREAM frame exceeding flow control
static uint8_t test_frame_quic_stream_flow_violation[] = { 0x0a, 0x01, 0xFF, 0xFF, 'd','a','t','a' };

// CRYPTO frame in 0-RTT packet (invalid)
static uint8_t test_frame_quic_crypto_0rtt_invalid[] = { 0x06, 0x00, 0x04, 't', 'e', 's', 't' };

// ACK frame in 0-RTT packet (invalid)
static uint8_t test_frame_quic_ack_0rtt_invalid[] = { 0x02, 0x01, 0x00, 0x01, 0x00 };

// NEW_CONNECTION_ID flooding (rapid sequence numbers)
static uint8_t test_frame_quic_ncid_flood_seq1[] = { 0x18, 0x01, 0x00, 0x08, 0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01, 0xB1,0xB1,0xB1,0xB1,0xB1,0xB1,0xB1,0xB1,0xB1,0xB1,0xB1,0xB1,0xB1,0xB1,0xB1,0xB1 };
static uint8_t test_frame_quic_ncid_flood_seq2[] = { 0x18, 0x02, 0x00, 0x08, 0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02, 0xB2,0xB2,0xB2,0xB2,0xB2,0xB2,0xB2,0xB2,0xB2,0xB2,0xB2,0xB2,0xB2,0xB2,0xB2,0xB2 };

// MAX_STREAMS rapid changes for DoS testing
static uint8_t test_frame_quic_max_streams_rapid1[] = { 0x12, 0x64 }; // 100 streams
static uint8_t test_frame_quic_max_streams_rapid2[] = { 0x12, 0x32 }; // 50 streams

// STREAM frame with zero-length data but LEN bit set
static uint8_t test_frame_quic_stream_zero_len_explicit[] = { 0x0a, 0x01, 0x00 };

// PATH_CHALLENGE replay attack simulation
static uint8_t test_frame_quic_path_challenge_replay[] = { 0x1a, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE };

// MAX_STREAM_DATA with decreasing value
static uint8_t test_frame_quic_max_stream_data_decrease[] = { 0x11, 0x01, 0x32 };

// STREAMS_BLOCKED with invalid higher limit
static uint8_t test_frame_quic_streams_blocked_invalid_limit[] = { 0x16, 0xC8 };

// Frame with invalid varint encoding
static uint8_t test_frame_quic_invalid_varint[] = { 0xFF, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };

// ACK frame with malformed ack range
static uint8_t test_frame_quic_ack_malformed[] = { 0x02, 0x0A, 0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFF };

// Multiple PATH_CHALLENGE frames in single packet
static uint8_t test_frame_quic_multiple_path_challenge[] = { 
    0x1a, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x1a, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18
};

// STREAM fragments for memory pressure testing
static uint8_t test_frame_quic_stream_fragment1[] = { 0x0a, 0x01, 0x01, 'A' };
static uint8_t test_frame_quic_stream_fragment2[] = { 0x0c, 0x01, 0x01, 0x01, 'B' };

// ACK frame with many ranges for memory pressure
static uint8_t test_frame_quic_ack_many_ranges[] = { 
    0x02, 0x64, 0x00, 0x05, // Largest 100, delay 0, 5 ranges
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01
};

// NEW_CONNECTION_ID with duplicate sequence number
static uint8_t test_frame_quic_ncid_duplicate[] = { 0x18, 0x01, 0x00, 0x08, 0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD, 0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE };

// Connection ID at maximum length (20 bytes)
static uint8_t test_frame_quic_ncid_max_len[] = { 
    0x18, 0x05, 0x00, 20, 
    0xF1,0xF2,0xF3,0xF4,0xF5,0xF6,0xF7,0xF8,0xF9,0xFA,0xFB,0xFC,0xFD,0xFE,0xFF,0x00,0x01,0x02,0x03,0x04,
    0xA1,0xA2,0xA3,0xA4,0xA5,0xA6,0xA7,0xA8,0xA9,0xAA,0xAB,0xAC,0xAD,0xAE,0xAF,0xB0
};

// Reset flood simulation
static uint8_t test_frame_quic_reset_flood1[] = { 0x04, 0x05, 0x00, 0x00 };
static uint8_t test_frame_quic_reset_flood2[] = { 0x04, 0x09, 0x00, 0x00 };

// Buffer overflow attempts
static uint8_t test_frame_quic_crypto_overflow[] = { 0x06, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x01 };
static uint8_t test_frame_quic_new_token_overflow[] = { 0x07, 0xFF, 0xFF, 0x01 };

// ACK with suspicious timing patterns
static uint8_t test_frame_quic_ack_timing_suspicious[] = { 0x02, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x00 };

// Additional missing test cases referenced in FUZI_Q_ITEM array
static uint8_t test_quic_conn_close_missing_error[] = { 0x1c }; // CONNECTION_CLOSE with missing error code
static uint8_t test_quic_ack_bad_range[] = { 0x02, 0x05, 0x00, 0x01, 0x10 }; // ACK with invalid range
static uint8_t test_quic_reset_zero_error[] = { 0x04, 0x01, 0x00, 0x00 }; // RESET_STREAM with error 0
static uint8_t test_quic_crypto_big_offset[] = { 0x06, 0xBF, 0xFF, 0xFF, 0xFF, 0x04, 't', 'e', 's', 't' }; // CRYPTO with large offset
static uint8_t test_quic_new_token_empty[] = { 0x07, 0x00 }; // NEW_TOKEN with zero length
static uint8_t test_quic_stream_id_zero[] = { 0x08, 0x00, 'z', 'e', 'r', 'o' }; // STREAM with ID 0
static uint8_t test_quic_max_data_zero[] = { 0x10, 0x00 }; // MAX_DATA with value 0
static uint8_t test_quic_max_streams_huge[] = { 0x12, 0xFF, 0xFF, 0xFF, 0xFF }; // MAX_STREAMS with huge value
static uint8_t test_quic_ncid_bad_seq[] = { 0x18, 0xFF, 0x00, 0x08, 0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA, 0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB }; // NEW_CONNECTION_ID with bad sequence
static uint8_t test_quic_retire_seq_zero[] = { 0x19, 0x00 }; // RETIRE_CONNECTION_ID with sequence 0
static uint8_t test_quic_path_challenge_predictable[] = { 0x1a, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 }; // PATH_CHALLENGE with predictable data

// Additional QUIC negative test cases that were missing
static uint8_t test_quic_reserved_frame_type[] = { 0x1f }; // Reserved frame type
static uint8_t test_quic_stream_len_mismatch[] = { 0x0a, 0x01, 0x05, 'x', 'y' }; // STREAM with length mismatch
static uint8_t test_quic_ack_future[] = { 0x02, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x01, 0x00 }; // ACK for future packet
static uint8_t test_quic_datagram_bad_len[] = { 0x30, 0x10, 'x' }; // DATAGRAM with bad length
static uint8_t test_quic_stream_noncanon_varint[] = { 0x08, 0x40, 0x01, 't', 'e', 's', 't' }; // STREAM with non-canonical varint
static uint8_t test_quic_conn_close_bad_frame_ref[] = { 0x1c, 0x01, 0xFF, 0x00 }; // CONNECTION_CLOSE with bad frame reference

/* RFC 9204 (QPACK Instructions) Placeholders */
/* Encoder Instructions */
static uint8_t test_qpack_enc_set_dynamic_table_capacity[] = {0x20}; /* Placeholder: Set Dynamic Table Capacity (e.g., 001xxxxx) */
static uint8_t test_qpack_enc_insert_with_name_ref[] = {0x80}; /* Placeholder: Insert With Name Reference (Indexed Name, e.g., 1xxxxxxx) */
static uint8_t test_qpack_enc_insert_without_name_ref[] = {0x40}; /* Placeholder: Insert Without Name Reference (e.g., 0100xxxx) */
static uint8_t test_qpack_enc_duplicate[] = {0x00}; /* Placeholder: Duplicate (e.g., 000xxxxx) */

/* Decoder Instructions (as per prompt, acknowledging potential mismatch with RFC for "Set Dynamic Table Capacity") */
static uint8_t test_qpack_dec_header_block_ack[] = {0x80}; /* Placeholder: Section Acknowledgment (Decoder, e.g., 1xxxxxxx) */
static uint8_t test_qpack_dec_stream_cancellation[] = {0x40}; /* Placeholder: Stream Cancellation (Decoder, e.g., 01xxxxxx) */
static uint8_t test_qpack_dec_insert_count_increment[] = {0x01}; /* Placeholder: Insert Count Increment (Decoder, e.g., 00xxxxxx) */
static uint8_t test_qpack_dec_set_dynamic_table_capacity[] = {0x20}; /* Placeholder: Set Dynamic Table Capacity (Encoder Instruction pattern 001xxxxx) */

// HTTP/2 Frame Types (RFC 9113) - Placeholders
static uint8_t test_h2_frame_type_data[] = {0x00}; /* H2 DATA frame type */
static uint8_t test_h2_frame_type_headers[] = {0x01}; /* H2 HEADERS frame type */
static uint8_t test_h2_frame_type_priority[] = {0x02}; /* H2 PRIORITY frame type */
static uint8_t test_h2_frame_type_rst_stream[] = {0x03}; /* H2 RST_STREAM frame type */
static uint8_t test_h2_frame_type_settings[] = {0x04}; /* H2 SETTINGS frame type */
static uint8_t test_h2_frame_type_push_promise[] = {0x05}; /* H2 PUSH_PROMISE frame type */
static uint8_t test_h2_frame_type_ping[] = {0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; /* H2 PING frame type (type + 8 bytes opaque data) */
static uint8_t test_h2_frame_type_goaway[] = {0x07}; /* H2 GOAWAY frame type */
static uint8_t test_h2_frame_type_window_update[] = {0x08}; /* H2 WINDOW_UPDATE frame type */
static uint8_t test_h2_frame_type_continuation[] = {0x09}; /* H2 CONTINUATION frame type */

// HPACK Representations/Instructions (RFC 7541) - Placeholders
static uint8_t test_hpack_indexed_header_field[] = {0x80}; /* HPACK Indexed Header Field (pattern 1xxxxxxx) */
static uint8_t test_hpack_literal_inc_indexing[] = {0x40}; /* HPACK Literal Header Field with Incremental Indexing (pattern 01xxxxxx) */
static uint8_t test_hpack_literal_no_indexing[] = {0x00}; /* HPACK Literal Header Field without Indexing (pattern 0000xxxx) */
static uint8_t test_hpack_literal_never_indexed[] = {0x10}; /* HPACK Literal Header Field Never Indexed (pattern 0001xxxx) */
static uint8_t test_hpack_dynamic_table_size_update[] = {0x20}; /* HPACK Dynamic Table Size Update (pattern 001xxxxx) */

// HTTP Alternative Services (RFC 7838) - H2 Frame Type Placeholder
static uint8_t test_h2_frame_type_altsvc[] = {0x0a}; /* H2 ALTSVC frame type (0xa) */

// WebSocket Frame Types (RFC 6455) - Placeholders (minimal frames, FIN=1, Mask=0, PayloadLen=0)
static uint8_t test_ws_frame_continuation[] = {0x80, 0x00}; /* WebSocket Continuation Frame (FIN + Opcode 0x0) */
static uint8_t test_ws_frame_text[] = {0x81, 0x00};         /* WebSocket Text Frame (FIN + Opcode 0x1) */
static uint8_t test_ws_frame_binary[] = {0x82, 0x00};        /* WebSocket Binary Frame (FIN + Opcode 0x2) */
static uint8_t test_ws_frame_connection_close[] = {0x88, 0x00}; /* WebSocket Connection Close Frame (FIN + Opcode 0x8) */
static uint8_t test_ws_frame_ping[] = {0x89, 0x00};          /* WebSocket Ping Frame (FIN + Opcode 0x9) */
static uint8_t test_ws_frame_pong[] = {0x8a, 0x00};          /* WebSocket Pong Frame (FIN + Opcode 0xA) */

fuzi_q_frames_t fuzi_q_frame_list[] = {
    FUZI_Q_ITEM("padding", test_frame_type_padding),
    FUZI_Q_ITEM("padding_zero_byte", test_frame_type_padding_zero_byte),
    FUZI_Q_ITEM("padding_large", test_frame_type_padding_large),
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
    FUZI_Q_ITEM("reset_stream_error_code_max", test_frame_reset_stream_error_code_max),
    FUZI_Q_ITEM("reset_stream_final_size_max_new", test_frame_reset_stream_final_size_max_new),
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
    FUZI_Q_ITEM("max_data_small_value", test_frame_max_data_small_value),
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
    /* STREAM SID: Non-Canonical Varints */
    FUZI_Q_ITEM("stream_sid_0_nc2", test_stream_sid_0_nc2),
    FUZI_Q_ITEM("stream_sid_0_nc4", test_stream_sid_0_nc4),
    FUZI_Q_ITEM("stream_sid_0_nc8", test_stream_sid_0_nc8),
    FUZI_Q_ITEM("stream_sid_1_nc2", test_stream_sid_1_nc2),
    FUZI_Q_ITEM("stream_sid_1_nc4", test_stream_sid_1_nc4),
    FUZI_Q_ITEM("stream_sid_1_nc8", test_stream_sid_1_nc8),
    FUZI_Q_ITEM("stream_sid_5_nc2", test_stream_sid_5_nc2),
    FUZI_Q_ITEM("stream_sid_5_nc4", test_stream_sid_5_nc4),
    FUZI_Q_ITEM("stream_sid_5_nc8", test_stream_sid_5_nc8),
    /* STREAM Offset: Non-Canonical Varints */
    FUZI_Q_ITEM("stream_off_0_nc2", test_stream_off_0_nc2),
    FUZI_Q_ITEM("stream_off_0_nc4", test_stream_off_0_nc4),
    FUZI_Q_ITEM("stream_off_0_nc8", test_stream_off_0_nc8),
    FUZI_Q_ITEM("stream_off_1_nc2", test_stream_off_1_nc2),
    FUZI_Q_ITEM("stream_off_1_nc4", test_stream_off_1_nc4),
    FUZI_Q_ITEM("stream_off_1_nc8", test_stream_off_1_nc8),
    FUZI_Q_ITEM("stream_off_5_nc2", test_stream_off_5_nc2),
    FUZI_Q_ITEM("stream_off_5_nc4", test_stream_off_5_nc4),
    FUZI_Q_ITEM("stream_off_5_nc8", test_stream_off_5_nc8),
    /* STREAM Length: Non-Canonical Varints */
    FUZI_Q_ITEM("stream_len_0_nc2", test_stream_len_0_nc2),
    FUZI_Q_ITEM("stream_len_0_nc4", test_stream_len_0_nc4),
    FUZI_Q_ITEM("stream_len_0_nc8", test_stream_len_0_nc8),
    FUZI_Q_ITEM("stream_len_1_nc2", test_stream_len_1_nc2),
    FUZI_Q_ITEM("stream_len_1_nc4", test_stream_len_1_nc4),
    FUZI_Q_ITEM("stream_len_1_nc8", test_stream_len_1_nc8),
    FUZI_Q_ITEM("stream_len_4_nc2", test_stream_len_4_nc2),
    FUZI_Q_ITEM("stream_len_4_nc4", test_stream_len_4_nc4),
    FUZI_Q_ITEM("stream_len_4_nc8", test_stream_len_4_nc8),
    /* ACK Largest Acknowledged: Non-Canonical Varints */
    FUZI_Q_ITEM("ack_largest_ack_0_nc2", test_ack_largest_ack_0_nc2),
    FUZI_Q_ITEM("ack_largest_ack_0_nc4", test_ack_largest_ack_0_nc4),
    FUZI_Q_ITEM("ack_largest_ack_0_nc8", test_ack_largest_ack_0_nc8),
    FUZI_Q_ITEM("ack_largest_ack_1_nc2", test_ack_largest_ack_1_nc2),
    FUZI_Q_ITEM("ack_largest_ack_1_nc4", test_ack_largest_ack_1_nc4),
    FUZI_Q_ITEM("ack_largest_ack_1_nc8", test_ack_largest_ack_1_nc8),
    FUZI_Q_ITEM("ack_largest_ack_5_nc2", test_ack_largest_ack_5_nc2),
    FUZI_Q_ITEM("ack_largest_ack_5_nc4", test_ack_largest_ack_5_nc4),
    FUZI_Q_ITEM("ack_largest_ack_5_nc8", test_ack_largest_ack_5_nc8),
    /* ACK Delay: Non-Canonical Varints */
    FUZI_Q_ITEM("ack_delay_0_nc2", test_ack_delay_0_nc2),
    FUZI_Q_ITEM("ack_delay_0_nc4", test_ack_delay_0_nc4),
    FUZI_Q_ITEM("ack_delay_0_nc8", test_ack_delay_0_nc8),
    FUZI_Q_ITEM("ack_delay_1_nc2", test_ack_delay_1_nc2),
    FUZI_Q_ITEM("ack_delay_1_nc4", test_ack_delay_1_nc4),
    FUZI_Q_ITEM("ack_delay_1_nc8", test_ack_delay_1_nc8),
    FUZI_Q_ITEM("ack_delay_5_nc2", test_ack_delay_5_nc2),
    FUZI_Q_ITEM("ack_delay_5_nc4", test_ack_delay_5_nc4),
    FUZI_Q_ITEM("ack_delay_5_nc8", test_ack_delay_5_nc8),
    /* ACK Range Count: Non-Canonical Varints */
    FUZI_Q_ITEM("ack_range_count_1_nc2", test_ack_range_count_1_nc2),
    FUZI_Q_ITEM("ack_range_count_1_nc4", test_ack_range_count_1_nc4),
    FUZI_Q_ITEM("ack_range_count_1_nc8", test_ack_range_count_1_nc8),
    FUZI_Q_ITEM("ack_range_count_2_nc2", test_ack_range_count_2_nc2),
    FUZI_Q_ITEM("ack_range_count_2_nc4", test_ack_range_count_2_nc4),
    FUZI_Q_ITEM("ack_range_count_2_nc8", test_ack_range_count_2_nc8),
    /* ACK First ACK Range: Non-Canonical Varints */
    FUZI_Q_ITEM("ack_first_range_0_nc2", test_ack_first_range_0_nc2),
    FUZI_Q_ITEM("ack_first_range_0_nc4", test_ack_first_range_0_nc4),
    FUZI_Q_ITEM("ack_first_range_0_nc8", test_ack_first_range_0_nc8),
    FUZI_Q_ITEM("ack_first_range_1_nc2", test_ack_first_range_1_nc2),
    FUZI_Q_ITEM("ack_first_range_1_nc4", test_ack_first_range_1_nc4),
    FUZI_Q_ITEM("ack_first_range_1_nc8", test_ack_first_range_1_nc8),
    FUZI_Q_ITEM("ack_first_range_5_nc2", test_ack_first_range_5_nc2),
    FUZI_Q_ITEM("ack_first_range_5_nc4", test_ack_first_range_5_nc4),
    FUZI_Q_ITEM("ack_first_range_5_nc8", test_ack_first_range_5_nc8),
    /* ACK Gap: Non-Canonical Varints */
    FUZI_Q_ITEM("ack_gap_0_nc2", test_ack_gap_0_nc2),
    FUZI_Q_ITEM("ack_gap_0_nc4", test_ack_gap_0_nc4),
    FUZI_Q_ITEM("ack_gap_0_nc8", test_ack_gap_0_nc8),
    FUZI_Q_ITEM("ack_gap_1_nc2", test_ack_gap_1_nc2),
    FUZI_Q_ITEM("ack_gap_1_nc4", test_ack_gap_1_nc4),
    FUZI_Q_ITEM("ack_gap_1_nc8", test_ack_gap_1_nc8),
    FUZI_Q_ITEM("ack_gap_2_nc2", test_ack_gap_2_nc2),
    FUZI_Q_ITEM("ack_gap_2_nc4", test_ack_gap_2_nc4),
    FUZI_Q_ITEM("ack_gap_2_nc8", test_ack_gap_2_nc8),
    /* ACK Range Length: Non-Canonical Varints */
    FUZI_Q_ITEM("ack_range_len_0_nc2", test_ack_range_len_0_nc2),
    FUZI_Q_ITEM("ack_range_len_0_nc4", test_ack_range_len_0_nc4),
    FUZI_Q_ITEM("ack_range_len_0_nc8", test_ack_range_len_0_nc8),
    FUZI_Q_ITEM("ack_range_len_1_nc2", test_ack_range_len_1_nc2),
    FUZI_Q_ITEM("ack_range_len_1_nc4", test_ack_range_len_1_nc4),
    FUZI_Q_ITEM("ack_range_len_1_nc8", test_ack_range_len_1_nc8),
    FUZI_Q_ITEM("ack_range_len_5_nc2", test_ack_range_len_5_nc2),
    FUZI_Q_ITEM("ack_range_len_5_nc4", test_ack_range_len_5_nc4),
    FUZI_Q_ITEM("ack_range_len_5_nc8", test_ack_range_len_5_nc8),
    /* RESET_STREAM Stream ID: Non-Canonical Varints */
    FUZI_Q_ITEM("reset_stream_sid_0_nc2", test_reset_stream_sid_0_nc2),
    FUZI_Q_ITEM("reset_stream_sid_0_nc4", test_reset_stream_sid_0_nc4),
    FUZI_Q_ITEM("reset_stream_sid_0_nc8", test_reset_stream_sid_0_nc8),
    FUZI_Q_ITEM("reset_stream_sid_1_nc2", test_reset_stream_sid_1_nc2),
    FUZI_Q_ITEM("reset_stream_sid_1_nc4", test_reset_stream_sid_1_nc4),
    FUZI_Q_ITEM("reset_stream_sid_1_nc8", test_reset_stream_sid_1_nc8),
    FUZI_Q_ITEM("reset_stream_sid_5_nc2", test_reset_stream_sid_5_nc2),
    FUZI_Q_ITEM("reset_stream_sid_5_nc4", test_reset_stream_sid_5_nc4),
    FUZI_Q_ITEM("reset_stream_sid_5_nc8", test_reset_stream_sid_5_nc8),
    /* RESET_STREAM App Error Code: Non-Canonical Varints */
    FUZI_Q_ITEM("reset_stream_err_0_nc2", test_reset_stream_err_0_nc2),
    FUZI_Q_ITEM("reset_stream_err_0_nc4", test_reset_stream_err_0_nc4),
    FUZI_Q_ITEM("reset_stream_err_0_nc8", test_reset_stream_err_0_nc8),
    FUZI_Q_ITEM("reset_stream_err_1_nc2", test_reset_stream_err_1_nc2),
    FUZI_Q_ITEM("reset_stream_err_1_nc4", test_reset_stream_err_1_nc4),
    FUZI_Q_ITEM("reset_stream_err_1_nc8", test_reset_stream_err_1_nc8),
    FUZI_Q_ITEM("reset_stream_err_5_nc2", test_reset_stream_err_5_nc2),
    FUZI_Q_ITEM("reset_stream_err_5_nc4", test_reset_stream_err_5_nc4),
    FUZI_Q_ITEM("reset_stream_err_5_nc8", test_reset_stream_err_5_nc8),
    /* RESET_STREAM Final Size: Non-Canonical Varints */
    FUZI_Q_ITEM("reset_stream_final_0_nc2", test_reset_stream_final_0_nc2),
    FUZI_Q_ITEM("reset_stream_final_0_nc4", test_reset_stream_final_0_nc4),
    FUZI_Q_ITEM("reset_stream_final_0_nc8", test_reset_stream_final_0_nc8),
    FUZI_Q_ITEM("reset_stream_final_1_nc2", test_reset_stream_final_1_nc2),
    FUZI_Q_ITEM("reset_stream_final_1_nc4", test_reset_stream_final_1_nc4),
    FUZI_Q_ITEM("reset_stream_final_1_nc8", test_reset_stream_final_1_nc8),
    FUZI_Q_ITEM("reset_stream_final_5_nc2", test_reset_stream_final_5_nc2),
    FUZI_Q_ITEM("reset_stream_final_5_nc4", test_reset_stream_final_5_nc4),
    FUZI_Q_ITEM("reset_stream_final_5_nc8", test_reset_stream_final_5_nc8),
    /* STOP_SENDING Stream ID: Non-Canonical Varints */
    FUZI_Q_ITEM("stop_sending_sid_0_nc2", test_stop_sending_sid_0_nc2),
    FUZI_Q_ITEM("stop_sending_sid_0_nc4", test_stop_sending_sid_0_nc4),
    FUZI_Q_ITEM("stop_sending_sid_0_nc8", test_stop_sending_sid_0_nc8),
    FUZI_Q_ITEM("stop_sending_sid_1_nc2", test_stop_sending_sid_1_nc2),
    FUZI_Q_ITEM("stop_sending_sid_1_nc4", test_stop_sending_sid_1_nc4),
    FUZI_Q_ITEM("stop_sending_sid_1_nc8", test_stop_sending_sid_1_nc8),
    FUZI_Q_ITEM("stop_sending_sid_5_nc2", test_stop_sending_sid_5_nc2),
    FUZI_Q_ITEM("stop_sending_sid_5_nc4", test_stop_sending_sid_5_nc4),
    FUZI_Q_ITEM("stop_sending_sid_5_nc8", test_stop_sending_sid_5_nc8),
    /* STOP_SENDING App Error Code: Non-Canonical Varints */
    FUZI_Q_ITEM("stop_sending_err_0_nc2", test_stop_sending_err_0_nc2),
    FUZI_Q_ITEM("stop_sending_err_0_nc4", test_stop_sending_err_0_nc4),
    FUZI_Q_ITEM("stop_sending_err_0_nc8", test_stop_sending_err_0_nc8),
    FUZI_Q_ITEM("stop_sending_err_1_nc2", test_stop_sending_err_1_nc2),
    FUZI_Q_ITEM("stop_sending_err_1_nc4", test_stop_sending_err_1_nc4),
    FUZI_Q_ITEM("stop_sending_err_1_nc8", test_stop_sending_err_1_nc8),
    FUZI_Q_ITEM("stop_sending_err_5_nc2", test_stop_sending_err_5_nc2),
    FUZI_Q_ITEM("stop_sending_err_5_nc4", test_stop_sending_err_5_nc4),
    FUZI_Q_ITEM("stop_sending_err_5_nc8", test_stop_sending_err_5_nc8),
    /* MAX_DATA Maximum Data: Non-Canonical Varints */
    FUZI_Q_ITEM("max_data_0_nc2", test_max_data_0_nc2),
    FUZI_Q_ITEM("max_data_0_nc4", test_max_data_0_nc4),
    FUZI_Q_ITEM("max_data_0_nc8", test_max_data_0_nc8),
    FUZI_Q_ITEM("max_data_1_nc2", test_max_data_1_nc2),
    FUZI_Q_ITEM("max_data_1_nc4", test_max_data_1_nc4),
    FUZI_Q_ITEM("max_data_1_nc8", test_max_data_1_nc8),
    FUZI_Q_ITEM("max_data_10_nc2", test_max_data_10_nc2),
    FUZI_Q_ITEM("max_data_10_nc4", test_max_data_10_nc4),
    FUZI_Q_ITEM("max_data_10_nc8", test_max_data_10_nc8),
    /* MAX_STREAM_DATA Stream ID: Non-Canonical Varints */
    FUZI_Q_ITEM("max_sdata_sid_0_nc2", test_max_sdata_sid_0_nc2),
    FUZI_Q_ITEM("max_sdata_sid_0_nc4", test_max_sdata_sid_0_nc4),
    FUZI_Q_ITEM("max_sdata_sid_0_nc8", test_max_sdata_sid_0_nc8),
    FUZI_Q_ITEM("max_sdata_sid_1_nc2", test_max_sdata_sid_1_nc2),
    FUZI_Q_ITEM("max_sdata_sid_1_nc4", test_max_sdata_sid_1_nc4),
    FUZI_Q_ITEM("max_sdata_sid_1_nc8", test_max_sdata_sid_1_nc8),
    FUZI_Q_ITEM("max_sdata_sid_5_nc2", test_max_sdata_sid_5_nc2),
    FUZI_Q_ITEM("max_sdata_sid_5_nc4", test_max_sdata_sid_5_nc4),
    FUZI_Q_ITEM("max_sdata_sid_5_nc8", test_max_sdata_sid_5_nc8),
    /* MAX_STREAM_DATA Max Value: Non-Canonical Varints */
    FUZI_Q_ITEM("max_sdata_val_0_nc2", test_max_sdata_val_0_nc2),
    FUZI_Q_ITEM("max_sdata_val_0_nc4", test_max_sdata_val_0_nc4),
    FUZI_Q_ITEM("max_sdata_val_0_nc8", test_max_sdata_val_0_nc8),
    FUZI_Q_ITEM("max_sdata_val_1_nc2", test_max_sdata_val_1_nc2),
    FUZI_Q_ITEM("max_sdata_val_1_nc4", test_max_sdata_val_1_nc4),
    FUZI_Q_ITEM("max_sdata_val_1_nc8", test_max_sdata_val_1_nc8),
    FUZI_Q_ITEM("max_sdata_val_10_nc2", test_max_sdata_val_10_nc2),
    FUZI_Q_ITEM("max_sdata_val_10_nc4", test_max_sdata_val_10_nc4),
    FUZI_Q_ITEM("max_sdata_val_10_nc8", test_max_sdata_val_10_nc8),
    /* MAX_STREAMS (Bidi): Non-Canonical Varints */
    FUZI_Q_ITEM("max_streams_bidi_0_nc2", test_max_streams_bidi_0_nc2),
    FUZI_Q_ITEM("max_streams_bidi_0_nc4", test_max_streams_bidi_0_nc4),
    FUZI_Q_ITEM("max_streams_bidi_0_nc8", test_max_streams_bidi_0_nc8),
    FUZI_Q_ITEM("max_streams_bidi_1_nc2", test_max_streams_bidi_1_nc2),
    FUZI_Q_ITEM("max_streams_bidi_1_nc4", test_max_streams_bidi_1_nc4),
    FUZI_Q_ITEM("max_streams_bidi_1_nc8", test_max_streams_bidi_1_nc8),
    FUZI_Q_ITEM("max_streams_bidi_5_nc2", test_max_streams_bidi_5_nc2),
    FUZI_Q_ITEM("max_streams_bidi_5_nc4", test_max_streams_bidi_5_nc4),
    FUZI_Q_ITEM("max_streams_bidi_5_nc8", test_max_streams_bidi_5_nc8),
    /* MAX_STREAMS (Uni): Non-Canonical Varints */
    FUZI_Q_ITEM("max_streams_uni_0_nc2", test_max_streams_uni_0_nc2),
    FUZI_Q_ITEM("max_streams_uni_0_nc4", test_max_streams_uni_0_nc4),
    FUZI_Q_ITEM("max_streams_uni_0_nc8", test_max_streams_uni_0_nc8),
    FUZI_Q_ITEM("max_streams_uni_1_nc2", test_max_streams_uni_1_nc2),
    FUZI_Q_ITEM("max_streams_uni_1_nc4", test_max_streams_uni_1_nc4),
    FUZI_Q_ITEM("max_streams_uni_1_nc8", test_max_streams_uni_1_nc8),
    FUZI_Q_ITEM("max_streams_uni_5_nc2", test_max_streams_uni_5_nc2),
    FUZI_Q_ITEM("max_streams_uni_5_nc4", test_max_streams_uni_5_nc4),
    FUZI_Q_ITEM("max_streams_uni_5_nc8", test_max_streams_uni_5_nc8),
    /* RESET_STREAM Stream ID: Non-Canonical Varints */
    FUZI_Q_ITEM("reset_stream_sid_0_nc2", test_reset_stream_sid_0_nc2),
    FUZI_Q_ITEM("reset_stream_sid_0_nc4", test_reset_stream_sid_0_nc4),
    FUZI_Q_ITEM("reset_stream_sid_0_nc8", test_reset_stream_sid_0_nc8),
    FUZI_Q_ITEM("reset_stream_sid_1_nc2", test_reset_stream_sid_1_nc2),
    FUZI_Q_ITEM("reset_stream_sid_1_nc4", test_reset_stream_sid_1_nc4),
    FUZI_Q_ITEM("reset_stream_sid_1_nc8", test_reset_stream_sid_1_nc8),
    FUZI_Q_ITEM("reset_stream_sid_5_nc2", test_reset_stream_sid_5_nc2),
    FUZI_Q_ITEM("reset_stream_sid_5_nc4", test_reset_stream_sid_5_nc4),
    FUZI_Q_ITEM("reset_stream_sid_5_nc8", test_reset_stream_sid_5_nc8),
    /* RESET_STREAM App Error Code: Non-Canonical Varints */
    FUZI_Q_ITEM("reset_stream_err_0_nc2", test_reset_stream_err_0_nc2),
    FUZI_Q_ITEM("reset_stream_err_0_nc4", test_reset_stream_err_0_nc4),
    FUZI_Q_ITEM("reset_stream_err_0_nc8", test_reset_stream_err_0_nc8),
    FUZI_Q_ITEM("reset_stream_err_1_nc2", test_reset_stream_err_1_nc2),
    FUZI_Q_ITEM("reset_stream_err_1_nc4", test_reset_stream_err_1_nc4),
    FUZI_Q_ITEM("reset_stream_err_1_nc8", test_reset_stream_err_1_nc8),
    FUZI_Q_ITEM("reset_stream_err_5_nc2", test_reset_stream_err_5_nc2),
    FUZI_Q_ITEM("reset_stream_err_5_nc4", test_reset_stream_err_5_nc4),
    FUZI_Q_ITEM("reset_stream_err_5_nc8", test_reset_stream_err_5_nc8),
    /* RESET_STREAM Final Size: Non-Canonical Varints */
    FUZI_Q_ITEM("reset_stream_final_0_nc2", test_reset_stream_final_0_nc2),
    FUZI_Q_ITEM("reset_stream_final_0_nc4", test_reset_stream_final_0_nc4),
    FUZI_Q_ITEM("reset_stream_final_0_nc8", test_reset_stream_final_0_nc8),
    FUZI_Q_ITEM("reset_stream_final_1_nc2", test_reset_stream_final_1_nc2),
    FUZI_Q_ITEM("reset_stream_final_1_nc4", test_reset_stream_final_1_nc4),
    FUZI_Q_ITEM("reset_stream_final_1_nc8", test_reset_stream_final_1_nc8),
    FUZI_Q_ITEM("reset_stream_final_5_nc2", test_reset_stream_final_5_nc2),
    FUZI_Q_ITEM("reset_stream_final_5_nc4", test_reset_stream_final_5_nc4),
    FUZI_Q_ITEM("reset_stream_final_5_nc8", test_reset_stream_final_5_nc8),
    /* STOP_SENDING Stream ID: Non-Canonical Varints */
    FUZI_Q_ITEM("stop_sending_sid_0_nc2", test_stop_sending_sid_0_nc2),
    FUZI_Q_ITEM("stop_sending_sid_0_nc4", test_stop_sending_sid_0_nc4),
    FUZI_Q_ITEM("stop_sending_sid_0_nc8", test_stop_sending_sid_0_nc8),
    FUZI_Q_ITEM("stop_sending_sid_1_nc2", test_stop_sending_sid_1_nc2),
    FUZI_Q_ITEM("stop_sending_sid_1_nc4", test_stop_sending_sid_1_nc4),
    FUZI_Q_ITEM("stop_sending_sid_1_nc8", test_stop_sending_sid_1_nc8),
    FUZI_Q_ITEM("stop_sending_sid_5_nc2", test_stop_sending_sid_5_nc2),
    FUZI_Q_ITEM("stop_sending_sid_5_nc4", test_stop_sending_sid_5_nc4),
    FUZI_Q_ITEM("stop_sending_sid_5_nc8", test_stop_sending_sid_5_nc8),
    /* STOP_SENDING App Error Code: Non-Canonical Varints */
    FUZI_Q_ITEM("stop_sending_err_0_nc2", test_stop_sending_err_0_nc2),
    FUZI_Q_ITEM("stop_sending_err_0_nc4", test_stop_sending_err_0_nc4),
    FUZI_Q_ITEM("stop_sending_err_0_nc8", test_stop_sending_err_0_nc8),
    FUZI_Q_ITEM("stop_sending_err_1_nc2", test_stop_sending_err_1_nc2),
    FUZI_Q_ITEM("stop_sending_err_1_nc4", test_stop_sending_err_1_nc4),
    FUZI_Q_ITEM("stop_sending_err_1_nc8", test_stop_sending_err_1_nc8),
    FUZI_Q_ITEM("stop_sending_err_5_nc2", test_stop_sending_err_5_nc2),
    FUZI_Q_ITEM("stop_sending_err_5_nc4", test_stop_sending_err_5_nc4),
    FUZI_Q_ITEM("stop_sending_err_5_nc8", test_stop_sending_err_5_nc8),
    /* DATA_BLOCKED Maximum Data: Non-Canonical Varints */
    FUZI_Q_ITEM("data_blocked_0_nc2", test_data_blocked_0_nc2),
    FUZI_Q_ITEM("data_blocked_0_nc4", test_data_blocked_0_nc4),
    FUZI_Q_ITEM("data_blocked_0_nc8", test_data_blocked_0_nc8),
    FUZI_Q_ITEM("data_blocked_1_nc2", test_data_blocked_1_nc2),
    FUZI_Q_ITEM("data_blocked_1_nc4", test_data_blocked_1_nc4),
    FUZI_Q_ITEM("data_blocked_1_nc8", test_data_blocked_1_nc8),
    FUZI_Q_ITEM("data_blocked_10_nc2", test_data_blocked_10_nc2),
    FUZI_Q_ITEM("data_blocked_10_nc4", test_data_blocked_10_nc4),
    FUZI_Q_ITEM("data_blocked_10_nc8", test_data_blocked_10_nc8),
    /* STREAM_DATA_BLOCKED Stream ID: Non-Canonical Varints */
    FUZI_Q_ITEM("sdata_blocked_sid_0_nc2", test_sdata_blocked_sid_0_nc2),
    FUZI_Q_ITEM("sdata_blocked_sid_0_nc4", test_sdata_blocked_sid_0_nc4),
    FUZI_Q_ITEM("sdata_blocked_sid_0_nc8", test_sdata_blocked_sid_0_nc8),
    FUZI_Q_ITEM("sdata_blocked_sid_1_nc2", test_sdata_blocked_sid_1_nc2),
    FUZI_Q_ITEM("sdata_blocked_sid_1_nc4", test_sdata_blocked_sid_1_nc4),
    FUZI_Q_ITEM("sdata_blocked_sid_1_nc8", test_sdata_blocked_sid_1_nc8),
    FUZI_Q_ITEM("sdata_blocked_sid_5_nc2", test_sdata_blocked_sid_5_nc2),
    FUZI_Q_ITEM("sdata_blocked_sid_5_nc4", test_sdata_blocked_sid_5_nc4),
    FUZI_Q_ITEM("sdata_blocked_sid_5_nc8", test_sdata_blocked_sid_5_nc8),
    /* STREAM_DATA_BLOCKED Stream Data Limit: Non-Canonical Varints */
    FUZI_Q_ITEM("sdata_blocked_limit_0_nc2", test_sdata_blocked_limit_0_nc2),
    FUZI_Q_ITEM("sdata_blocked_limit_0_nc4", test_sdata_blocked_limit_0_nc4),
    FUZI_Q_ITEM("sdata_blocked_limit_0_nc8", test_sdata_blocked_limit_0_nc8),
    FUZI_Q_ITEM("sdata_blocked_limit_1_nc2", test_sdata_blocked_limit_1_nc2),
    FUZI_Q_ITEM("sdata_blocked_limit_1_nc4", test_sdata_blocked_limit_1_nc4),
    FUZI_Q_ITEM("sdata_blocked_limit_1_nc8", test_sdata_blocked_limit_1_nc8),
    FUZI_Q_ITEM("sdata_blocked_limit_10_nc2", test_sdata_blocked_limit_10_nc2),
    FUZI_Q_ITEM("sdata_blocked_limit_10_nc4", test_sdata_blocked_limit_10_nc4),
    FUZI_Q_ITEM("sdata_blocked_limit_10_nc8", test_sdata_blocked_limit_10_nc8),
    /* STREAMS_BLOCKED (Bidi) Maximum Streams: Non-Canonical Varints */
    FUZI_Q_ITEM("streams_blocked_bidi_0_nc2", test_streams_blocked_bidi_0_nc2),
    FUZI_Q_ITEM("streams_blocked_bidi_0_nc4", test_streams_blocked_bidi_0_nc4),
    FUZI_Q_ITEM("streams_blocked_bidi_0_nc8", test_streams_blocked_bidi_0_nc8),
    FUZI_Q_ITEM("streams_blocked_bidi_1_nc2", test_streams_blocked_bidi_1_nc2),
    FUZI_Q_ITEM("streams_blocked_bidi_1_nc4", test_streams_blocked_bidi_1_nc4),
    FUZI_Q_ITEM("streams_blocked_bidi_1_nc8", test_streams_blocked_bidi_1_nc8),
    FUZI_Q_ITEM("streams_blocked_bidi_5_nc2", test_streams_blocked_bidi_5_nc2),
    FUZI_Q_ITEM("streams_blocked_bidi_5_nc4", test_streams_blocked_bidi_5_nc4),
    FUZI_Q_ITEM("streams_blocked_bidi_5_nc8", test_streams_blocked_bidi_5_nc8),
    /* STREAMS_BLOCKED (Uni) Maximum Streams: Non-Canonical Varints */
    FUZI_Q_ITEM("streams_blocked_uni_0_nc2", test_streams_blocked_uni_0_nc2),
    FUZI_Q_ITEM("streams_blocked_uni_0_nc4", test_streams_blocked_uni_0_nc4),
    FUZI_Q_ITEM("streams_blocked_uni_0_nc8", test_streams_blocked_uni_0_nc8),
    FUZI_Q_ITEM("streams_blocked_uni_1_nc2", test_streams_blocked_uni_1_nc2),
    FUZI_Q_ITEM("streams_blocked_uni_1_nc4", test_streams_blocked_uni_1_nc4),
    FUZI_Q_ITEM("streams_blocked_uni_1_nc8", test_streams_blocked_uni_1_nc8),
    FUZI_Q_ITEM("streams_blocked_uni_5_nc2", test_streams_blocked_uni_5_nc2),
    FUZI_Q_ITEM("streams_blocked_uni_5_nc4", test_streams_blocked_uni_5_nc4),
    FUZI_Q_ITEM("streams_blocked_uni_5_nc8", test_streams_blocked_uni_5_nc8),
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
    FUZI_Q_ITEM("retire_cid_to_zero_len_provider", test_frame_retire_cid_to_zero_len_provider),

    /* --- Adding More Variations (Systematic Review Part 1) --- */
    /* RESET_STREAM Non-Canonical Varints */
    FUZI_Q_ITEM("reset_stream_sid_non_canon", test_frame_reset_stream_sid_non_canon),
    FUZI_Q_ITEM("reset_stream_err_non_canon", test_frame_reset_stream_err_non_canon),
    FUZI_Q_ITEM("reset_stream_final_non_canon", test_frame_reset_stream_final_non_canon),
    /* STOP_SENDING Non-Canonical Varints */
    FUZI_Q_ITEM("stop_sending_sid_non_canon", test_frame_stop_sending_sid_non_canon),
    FUZI_Q_ITEM("stop_sending_err_non_canon", test_frame_stop_sending_err_non_canon),
    /* CRYPTO Non-Canonical Varints */
    FUZI_Q_ITEM("crypto_offset_small_non_canon", test_frame_crypto_offset_small_non_canon),
    FUZI_Q_ITEM("crypto_len_small_non_canon", test_frame_crypto_len_small_non_canon),
    /* NEW_TOKEN Non-Canonical Varint */
    FUZI_Q_ITEM("new_token_len_non_canon", test_frame_new_token_len_non_canon),
	/* Test frame for invalid ACK gap of 1 */
    FUZI_Q_ITEM("test_frame_ack_invalid_gap_1_specific_val", test_frame_ack_invalid_gap_1_specific_val),
	FUZI_Q_ITEM("ack_invalid_gap_1_specific", ack_invalid_gap_1_specific),
    /* PADDING Variation */
    FUZI_Q_ITEM("padding_single", test_frame_padding_single),
    /* ACK Variations */
    FUZI_Q_ITEM("ack_range_count_zero_first_range_set", test_frame_ack_range_count_zero_first_range_set),
    FUZI_Q_ITEM("ack_delay_potentially_large_calc", test_frame_ack_delay_potentially_large_calc),
    FUZI_Q_ITEM("ack_largest_zero_first_zero", test_frame_ack_largest_zero_first_zero),
    FUZI_Q_ITEM("ack_ecn_non_minimal_ect0", test_frame_ack_ecn_non_minimal_ect0),

    /* Frame sequence test items */
    FUZI_Q_ITEM("sequence_stream_ping_padding_val", sequence_stream_ping_padding_val),
	FUZI_Q_ITEM("sequence_stream_ping_padding", sequence_stream_ping_padding),
    FUZI_Q_ITEM("sequence_max_data_max_stream_data_val", sequence_max_data_max_stream_data_val),
	FUZI_Q_ITEM("sequence_max_data_max_stream_data", sequence_max_data_max_stream_data),

    /* Error condition test items Add commentMore actions */
    FUZI_Q_ITEM("error_stream_client_on_server_uni", error_stream_client_on_server_uni_val),
    FUZI_Q_ITEM("error_stream_len_shorter", error_stream_len_shorter_val),
    /* --- Adding More Variations (Systematic Review Part 2 - STREAM & MAX_DATA) --- */
    /* STREAM Contextual Violations (require fuzzer logic for role-specific injection) */
    FUZI_Q_ITEM("stream_client_sends_server_bidi", test_stream_client_sends_server_bidi_stream),
    FUZI_Q_ITEM("stream_client_sends_server_uni", test_stream_client_sends_server_uni_stream),
    FUZI_Q_ITEM("stream_server_sends_client_bidi", test_stream_server_sends_client_bidi_stream),
    FUZI_Q_ITEM("stream_server_sends_client_uni", test_stream_server_sends_client_uni_stream),
    /* STREAM Edge Cases */
    FUZI_Q_ITEM("stream_explicit_len_zero_with_data", test_stream_explicit_len_zero_with_data),
    FUZI_Q_ITEM("stream_fin_only_implicit_len_zero_offset", test_stream_fin_only_implicit_len_zero_offset),
    FUZI_Q_ITEM("stream_fin_len_zero_with_trailing_data", test_stream_fin_len_zero_with_trailing_data),
    /* MAX_DATA Non-Canonical Varint */
    FUZI_Q_ITEM("max_data_long_varint_8byte_small", test_frame_max_data_long_varint_8byte_small),
    /* MAX_STREAM_DATA Variations */
    FUZI_Q_ITEM("max_stream_data_id_zero_val_set", test_frame_max_stream_data_id_zero_val_set),
    FUZI_Q_ITEM("max_stream_data_sid_non_canon", test_frame_max_stream_data_sid_non_canon),
    FUZI_Q_ITEM("max_stream_data_val_non_canon", test_frame_max_stream_data_val_non_canon),
    /* MAX_STREAMS Variations */
    FUZI_Q_ITEM("max_streams_bidi_val_2_pow_50", test_frame_max_streams_bidi_val_2_pow_50),
    FUZI_Q_ITEM("max_streams_bidi_small_non_canon8", test_frame_max_streams_bidi_small_non_canon8),
    /* DATA_BLOCKED Non-Canonical Varints */
    FUZI_Q_ITEM("data_blocked_non_canon2", test_frame_data_blocked_non_canon2),
    FUZI_Q_ITEM("data_blocked_non_canon4", test_frame_data_blocked_non_canon4),

    /* --- Adding More Variations (Systematic Review Part 3 - SDB, SB, NCID) --- */
    /* STREAM_DATA_BLOCKED Variations */
    FUZI_Q_ITEM("sdb_sid_non_canon", test_frame_sdb_sid_non_canon),
    FUZI_Q_ITEM("sdb_val_non_canon", test_frame_sdb_val_non_canon),
    FUZI_Q_ITEM("sdb_sid_zero", test_frame_sdb_sid_zero),
    /* STREAMS_BLOCKED Variations */
    FUZI_Q_ITEM("streams_blocked_bidi_at_limit", test_frame_streams_blocked_bidi_at_limit),
    FUZI_Q_ITEM("streams_blocked_uni_at_limit", test_frame_streams_blocked_uni_at_limit),
    FUZI_Q_ITEM("streams_blocked_bidi_non_canon2", test_frame_streams_blocked_bidi_non_canon2),
    FUZI_Q_ITEM("streams_blocked_uni_non_canon4", test_frame_streams_blocked_uni_non_canon4),
    /* NEW_CONNECTION_ID Variations */
    FUZI_Q_ITEM("ncid_seq_non_canon", test_frame_ncid_seq_non_canon),
    FUZI_Q_ITEM("ncid_ret_non_canon", test_frame_ncid_ret_non_canon),
    FUZI_Q_ITEM("ncid_cid_len_min", test_frame_ncid_cid_len_min),

    /* --- Adding More Variations (Systematic Review Part 4 - RCID, CC, HSD) --- */
    /* RETIRE_CONNECTION_ID Variations */
    FUZI_Q_ITEM("retire_cid_seq_non_canon", test_frame_retire_cid_seq_non_canon),
    /* CONNECTION_CLOSE Variations */
    FUZI_Q_ITEM("conn_close_reserved_err", test_frame_conn_close_reserved_err),
    FUZI_Q_ITEM("conn_close_ft_non_canon", test_frame_conn_close_ft_non_canon),
    FUZI_Q_ITEM("conn_close_app_rlen_non_canon", test_frame_conn_close_app_rlen_non_canon),
    /* HANDSHAKE_DONE Variations */
    FUZI_Q_ITEM("hsd_type_non_canon", test_frame_hsd_type_non_canon),
    /* Newly added frames for non-canonical encodings (Task D20231116_154018) */
    FUZI_Q_ITEM("retire_cid_seq_non_canon_new", test_frame_retire_cid_seq_non_canon), /* Name adjusted to avoid conflict if already present elsewhere */
    FUZI_Q_ITEM("conn_close_reserved_err_new", test_frame_conn_close_reserved_err),
    FUZI_Q_ITEM("conn_close_ft_non_canon_new", test_frame_conn_close_ft_non_canon),
    FUZI_Q_ITEM("conn_close_app_rlen_non_canon_new", test_frame_conn_close_app_rlen_non_canon),
    FUZI_Q_ITEM("hsd_type_non_canon_new", test_frame_hsd_type_non_canon),
    /* Newly added test frames (Task D20231116_160216) */
    FUZI_Q_ITEM("ack_invalid_gap_1", test_frame_ack_invalid_gap_1),
    FUZI_Q_ITEM("stream_len_decl_short_actual_long", test_frame_stream_len_shorter_than_data),
    FUZI_Q_ITEM("stream_len_decl_long_actual_short", test_frame_stream_len_longer_than_data),
    FUZI_Q_ITEM("ncid_retire_current_dcid", test_frame_type_retire_connection_id),
    FUZI_Q_ITEM("connection_close_frame_encoding_error", test_frame_connection_close_frame_encoding_error),
    FUZI_Q_ITEM("stream_type_very_long_encoding", test_frame_stream_type_long_encoding),
    /* Newly added DATAGRAM test frames (Task D20231121_101010) */
    FUZI_Q_ITEM("datagram_with_len_empty", test_frame_datagram_with_len_empty),
    FUZI_Q_ITEM("datagram_len_non_canon", test_frame_datagram_len_non_canon),
    FUZI_Q_ITEM("datagram_very_large", test_frame_datagram_very_large),
    /* HTTP/3 Frame Payloads */
    FUZI_Q_ITEM("h3_data_payload", test_h3_frame_data_payload),
    FUZI_Q_ITEM("h3_headers_simple", test_h3_frame_headers_payload_simple),
    FUZI_Q_ITEM("h3_settings_empty", test_h3_frame_settings_payload_empty),
    FUZI_Q_ITEM("h3_settings_one", test_h3_frame_settings_payload_one_setting),
    FUZI_Q_ITEM("h3_goaway", test_h3_frame_goaway_payload),
    FUZI_Q_ITEM("h3_max_push_id", test_h3_frame_max_push_id_payload),
    FUZI_Q_ITEM("h3_cancel_push", test_h3_frame_cancel_push_payload),
    FUZI_Q_ITEM("h3_push_promise_simple", test_h3_frame_push_promise_payload_simple),
    FUZI_Q_ITEM("h3_origin_val_0x0c", test_frame_h3_origin_val_0x0c),
    FUZI_Q_ITEM("h3_priority_update_val_0xf0700", test_frame_h3_priority_update_val_0xf0700),
    FUZI_Q_ITEM("h3_origin_payload", test_h3_frame_origin_payload),
    FUZI_Q_ITEM("h3_priority_update_request_payload", test_h3_frame_priority_update_request_payload),
    FUZI_Q_ITEM("h3_priority_update_placeholder_payload", test_h3_frame_priority_update_placeholder_payload),
    /* Additional H3 Frame Payload Variations */
    FUZI_Q_ITEM("h3_data_empty", test_h3_frame_data_empty),
    FUZI_Q_ITEM("h3_data_len_non_canon", test_h3_frame_data_len_non_canon),
    FUZI_Q_ITEM("h3_settings_max_field_section_size_zero", test_h3_settings_max_field_section_size_zero),
    FUZI_Q_ITEM("h3_settings_max_field_section_size_large", test_h3_settings_max_field_section_size_large),
    FUZI_Q_ITEM("h3_settings_multiple", test_h3_settings_multiple),
    FUZI_Q_ITEM("h3_settings_id_non_canon", test_h3_settings_id_non_canon),
    FUZI_Q_ITEM("h3_settings_val_non_canon", test_h3_settings_val_non_canon),
	FUZI_Q_ITEM("h3_origin_payload", test_h3_frame_origin_payload),
    FUZI_Q_ITEM("h3_priority_update_placeholder_payload", test_h3_frame_priority_update_placeholder_payload),
    FUZI_Q_ITEM("h3_priority_update_request_payload", test_h3_frame_priority_update_request_payload),
    FUZI_Q_ITEM("h3_goaway_max_id", test_h3_goaway_max_id),
    FUZI_Q_ITEM("h3_goaway_id_non_canon", test_h3_goaway_id_non_canon),
    FUZI_Q_ITEM("h3_max_push_id_zero", test_h3_max_push_id_zero),
    FUZI_Q_ITEM("h3_max_push_id_non_canon", test_h3_max_push_id_non_canon),
    FUZI_Q_ITEM("h3_cancel_push_max_id", test_h3_cancel_push_max_id),
    FUZI_Q_ITEM("h3_cancel_push_id_non_canon", test_h3_cancel_push_id_non_canon),
    /* DoQ Payload */
    FUZI_Q_ITEM("doq_dns_query_payload", test_doq_dns_query_payload),

    /* RFC 9113 (HTTP/2) Frame Types */
    FUZI_Q_ITEM("h2_data_val_0x0", test_frame_h2_data_val_0x0),
    FUZI_Q_ITEM("h2_headers_val_0x1", test_frame_h2_headers_val_0x1),
    FUZI_Q_ITEM("h2_priority_val_0x2", test_frame_h2_priority_val_0x2),
    FUZI_Q_ITEM("h2_rst_stream_val_0x3", test_frame_h2_rst_stream_val_0x3),
    FUZI_Q_ITEM("h2_settings_val_0x4", test_frame_h2_settings_val_0x4),
    FUZI_Q_ITEM("h2_push_promise_val_0x5", test_frame_h2_push_promise_val_0x5),
    FUZI_Q_ITEM("h2_ping_val_0x6", test_frame_h2_ping_val_0x6),
    FUZI_Q_ITEM("h2_goaway_val_0x7", test_frame_h2_goaway_val_0x7),
    FUZI_Q_ITEM("h2_window_update_val_0x8", test_frame_h2_window_update_val_0x8),
    FUZI_Q_ITEM("h2_continuation_val_0x9", test_frame_h2_continuation_val_0x9),
    FUZI_Q_ITEM("h2_altsvc_val_0xa", test_frame_h2_altsvc_val_0xa),

    /* RFC 6455 (WebSocket) Frame Types */
    FUZI_Q_ITEM("ws_continuation_val_0x0", test_frame_ws_continuation_val_0x0),
    FUZI_Q_ITEM("ws_text_val_0x1", test_frame_ws_text_val_0x1),
    FUZI_Q_ITEM("ws_binary_val_0x2", test_frame_ws_binary_val_0x2),
    FUZI_Q_ITEM("ws_connection_close_val_0x8", test_frame_ws_connection_close_val_0x8),
    FUZI_Q_ITEM("ws_ping_val_0x9", test_frame_ws_ping_val_0x9),
    FUZI_Q_ITEM("ws_pong_val_0xa", test_frame_ws_pong_val_0xa),

    /* STREAM Frame Variations (RFC 9000, Section 19.8) */
    FUZI_Q_ITEM("stream_0x08_minimal", test_stream_0x08_minimal),
    FUZI_Q_ITEM("stream_0x08_sid_non_canon", test_stream_0x08_sid_non_canon),
    FUZI_Q_ITEM("stream_0x08_data_long", test_stream_0x08_data_long),
    FUZI_Q_ITEM("stream_0x09_minimal", test_stream_0x09_minimal),
    FUZI_Q_ITEM("stream_0x09_sid_non_canon", test_stream_0x09_sid_non_canon),
    FUZI_Q_ITEM("stream_0x0A_len_zero_no_data", test_stream_0x0A_len_zero_no_data),
    FUZI_Q_ITEM("stream_0x0A_len_zero_with_data", test_stream_0x0A_len_zero_with_data),
    FUZI_Q_ITEM("stream_0x0A_len_small", test_stream_0x0A_len_small),
    FUZI_Q_ITEM("stream_0x0A_len_large", test_stream_0x0A_len_large),
    FUZI_Q_ITEM("stream_0x0A_sid_non_canon", test_stream_0x0A_sid_non_canon),
    FUZI_Q_ITEM("stream_0x0A_len_non_canon", test_stream_0x0A_len_non_canon),
    FUZI_Q_ITEM("stream_0x0B_len_zero_no_data_fin", test_stream_0x0B_len_zero_no_data_fin),
    FUZI_Q_ITEM("stream_0x0B_len_non_canon_fin", test_stream_0x0B_len_non_canon_fin),
    FUZI_Q_ITEM("stream_0x0C_offset_zero", test_stream_0x0C_offset_zero),
    FUZI_Q_ITEM("stream_0x0C_offset_large", test_stream_0x0C_offset_large),
    FUZI_Q_ITEM("stream_0x0C_sid_non_canon", test_stream_0x0C_sid_non_canon),
    FUZI_Q_ITEM("stream_0x0C_offset_non_canon", test_stream_0x0C_offset_non_canon),
    FUZI_Q_ITEM("stream_0x0D_offset_zero_fin", test_stream_0x0D_offset_zero_fin),
    FUZI_Q_ITEM("stream_0x0D_offset_non_canon_fin", test_stream_0x0D_offset_non_canon_fin),
    FUZI_Q_ITEM("stream_0x0E_all_fields_present", test_stream_0x0E_all_fields_present),
    FUZI_Q_ITEM("stream_0x0E_all_non_canon", test_stream_0x0E_all_non_canon),
    FUZI_Q_ITEM("stream_0x0F_all_fields_fin", test_stream_0x0F_all_fields_fin),
    FUZI_Q_ITEM("stream_0x0F_all_non_canon_fin", test_stream_0x0F_all_non_canon_fin),
    /* ACK, RESET_STREAM, STOP_SENDING Frame Variations (RFC 9000) */
    FUZI_Q_ITEM("ack_ecn_ect0_large", test_frame_ack_ecn_ect0_large),
    FUZI_Q_ITEM("ack_ecn_ect1_large", test_frame_ack_ecn_ect1_large),
    FUZI_Q_ITEM("ack_ecn_ce_large", test_frame_ack_ecn_ce_large),
    FUZI_Q_ITEM("ack_ecn_all_large", test_frame_ack_ecn_all_large),
    FUZI_Q_ITEM("ack_delay_non_canon", test_frame_ack_delay_non_canon),
    FUZI_Q_ITEM("ack_range_count_non_canon", test_frame_ack_range_count_non_canon),
    FUZI_Q_ITEM("ack_first_ack_range_non_canon", test_frame_ack_first_ack_range_non_canon),
    FUZI_Q_ITEM("ack_gap_non_canon", test_frame_ack_gap_non_canon),
    FUZI_Q_ITEM("reset_stream_app_err_non_canon", test_frame_reset_stream_app_err_non_canon),
    FUZI_Q_ITEM("reset_stream_final_size_non_canon_8byte", test_frame_reset_stream_final_size_non_canon_8byte),
    FUZI_Q_ITEM("stop_sending_app_err_non_canon", test_frame_stop_sending_app_err_non_canon),
    /* Non-Canonical Field Encodings (RFC 9000) */
    FUZI_Q_ITEM("crypto_offset_non_canon_4byte", test_frame_crypto_offset_non_canon_4byte),
    FUZI_Q_ITEM("crypto_len_non_canon_4byte", test_frame_crypto_len_non_canon_4byte),
    FUZI_Q_ITEM("new_token_len_non_canon_4byte", test_frame_new_token_len_non_canon_4byte),
    FUZI_Q_ITEM("max_data_non_canon_8byte", test_frame_max_data_non_canon_8byte),
    FUZI_Q_ITEM("max_stream_data_sid_non_canon_2byte", test_frame_max_stream_data_sid_non_canon_2byte),
    FUZI_Q_ITEM("max_stream_data_val_non_canon_4byte", test_frame_max_stream_data_val_non_canon_4byte),
    FUZI_Q_ITEM("max_streams_bidi_non_canon_2byte", test_frame_max_streams_bidi_non_canon_2byte),
    FUZI_Q_ITEM("max_streams_bidi_non_canon_8byte", test_frame_max_streams_bidi_non_canon_8byte),
    FUZI_Q_ITEM("max_streams_uni_non_canon_4byte", test_frame_max_streams_uni_non_canon_4byte),
    /* DATA_BLOCKED, STREAM_DATA_BLOCKED, STREAMS_BLOCKED (non-canonical) */
    FUZI_Q_ITEM("data_blocked_val_non_canon_2byte", test_frame_data_blocked_val_non_canon_2byte),
    FUZI_Q_ITEM("sdb_sid_non_canon_4byte", test_frame_sdb_sid_non_canon_4byte),
    FUZI_Q_ITEM("sdb_val_non_canon_8byte", test_frame_sdb_val_non_canon_8byte),
    FUZI_Q_ITEM("streams_blocked_bidi_non_canon_8byte", test_frame_streams_blocked_bidi_non_canon_8byte),
    FUZI_Q_ITEM("streams_blocked_uni_non_canon_2byte", test_frame_streams_blocked_uni_non_canon_2byte),
    /* NEW_CONNECTION_ID (non-canonical) */
    FUZI_Q_ITEM("ncid_seq_non_canon_2byte", test_frame_ncid_seq_non_canon_2byte),
    FUZI_Q_ITEM("ncid_ret_non_canon_4byte", test_frame_ncid_ret_non_canon_4byte),
    /* RETIRE_CONNECTION_ID (non-canonical) */
    FUZI_Q_ITEM("retire_cid_seq_non_canon_4byte", test_frame_retire_cid_seq_non_canon_4byte),
    /* CONNECTION_CLOSE (non-canonical) */
    FUZI_Q_ITEM("conn_close_ec_non_canon", test_frame_conn_close_ec_non_canon),
    FUZI_Q_ITEM("conn_close_rlen_non_canon", test_frame_conn_close_rlen_non_canon),
    FUZI_Q_ITEM("conn_close_app_ec_non_canon", test_frame_conn_close_app_ec_non_canon),
    FUZI_Q_ITEM("conn_close_app_rlen_non_canon_2byte", test_frame_conn_close_app_rlen_non_canon_2byte),
    /* Added from Plan - Step 4 */
    /* RFC 9000, Sec 19.8, 4.5 - STREAM with explicit non-zero len, no data, FIN */
    FUZI_Q_ITEM("stream_len_set_explicit_length_no_data_fin", test_stream_len_set_explicit_length_no_data_fin),
    /* RFC 9000, Sec 19.8, 4.5 - STREAM with offset+length near max final size */
    FUZI_Q_ITEM("stream_off_len_fin_offset_plus_length_almost_max", test_stream_off_len_fin_offset_plus_length_almost_max),
    /* RFC 9000, Sec 19.3 - ACK+ECN, RangeCount=0, FirstRange set, ECN counts present */
    FUZI_Q_ITEM("ack_ecn_range_count_zero_first_range_set_with_counts", test_ack_ecn_range_count_zero_first_range_set_with_counts),
    /* RFC 9000, Sec 19.19 - CONNECTION_CLOSE (transport) minimal fields */
    FUZI_Q_ITEM("connection_close_transport_min_fields", test_connection_close_transport_min_fields),
    /* RFC 9000, Sec 19.10 - MAX_STREAM_DATA with max StreamID and max Value */
    FUZI_Q_ITEM("max_stream_data_id_max_val_max", test_max_stream_data_id_max_val_max),
    /* --- Batch 1 of New Edge Case Test Variants --- */
    /* RFC 9000, Sec 19.8, 4.5 - STREAM (Type 0x0D) with max offset, 1 byte data. Expected: FINAL_SIZE_ERROR. */
    FUZI_Q_ITEM("stream_implicit_len_max_offset_with_data", test_stream_implicit_len_max_offset_with_data),
    /* RFC 9000, Sec 19.3 - ACK Type 0x02 (no ECN) with trailing ECN-like data. Expected: Ignore or FRAME_ENCODING_ERROR. */
    FUZI_Q_ITEM("ack_type02_with_trailing_ecn_like_data", test_ack_type02_with_trailing_ecn_like_data),
    /* RFC 9000, Sec 19.15 - NEW_CONNECTION_ID with truncated CID. Expected: FRAME_ENCODING_ERROR. */
    FUZI_Q_ITEM("new_connection_id_truncated_cid", test_new_connection_id_truncated_cid),
    /* RFC 9000, Sec 19.15 - NEW_CONNECTION_ID with truncated Stateless Reset Token. Expected: FRAME_ENCODING_ERROR. */
    FUZI_Q_ITEM("new_connection_id_truncated_token", test_new_connection_id_truncated_token),
    /* RFC 9000, Sec 19.15 - NEW_CONNECTION_ID with CID data longer than Length field. Parser should use Length. */
    FUZI_Q_ITEM("new_connection_id_cid_overrun_length_field", test_new_connection_id_cid_overrun_length_field),
    /* --- Batch 2 of New Edge Case Test Variants (Flow Control) --- */
    /* RFC 9000, Sec 19.12 - DATA_BLOCKED with max value */
    FUZI_Q_ITEM("test_data_blocked_max_value", test_data_blocked_max_value),
    /* RFC 9000, Sec 19.13 - STREAM_DATA_BLOCKED with max StreamID and max Value */
    FUZI_Q_ITEM("test_stream_data_blocked_max_id_max_value", test_stream_data_blocked_max_id_max_value),
    /* --- Batch 3 of New Edge Case Test Variants (Stream Limit Frames) --- */
    /* RFC 9000, Sec 19.14 - STREAMS_BLOCKED (bidi) with Maximum Streams over 2^60 limit */
    FUZI_Q_ITEM("test_streams_blocked_bidi_over_limit", test_streams_blocked_bidi_over_limit),
    /* RFC 9000, Sec 19.14 - STREAMS_BLOCKED (uni) with Maximum Streams over 2^60 limit */
    FUZI_Q_ITEM("test_streams_blocked_uni_over_limit", test_streams_blocked_uni_over_limit),
    /* --- Batch 4 of New Edge Case Test Variants (Path Validation Frames) --- */
    /* RFC 9000, Sec 19.17 - PATH_CHALLENGE with all ones data */
    FUZI_Q_ITEM("test_path_challenge_all_ones", test_path_challenge_all_ones),
    /* RFC 9000, Sec 19.18 - PATH_RESPONSE with 0xAA pattern data */
    FUZI_Q_ITEM("test_path_response_alt_bits_AA", test_path_response_alt_bits_AA),
    /* RFC 9000, Sec 19.17 - PATH_CHALLENGE truncated (4 of 8 data bytes) */
    FUZI_Q_ITEM("test_path_challenge_truncated_4bytes", test_path_challenge_truncated_4bytes),
    /* RFC 9000, Sec 19.18 - PATH_RESPONSE truncated (0 of 8 data bytes) */
    FUZI_Q_ITEM("test_path_response_truncated_0bytes", test_path_response_truncated_0bytes),
    /* --- Batch 5 of New Edge Case Test Variants (Other Control Frames) --- */
    /* RFC 9000, Sec 19.5 - STOP_SENDING with max StreamID and max App Error Code */
    FUZI_Q_ITEM("test_stop_sending_max_id_max_error", test_stop_sending_max_id_max_error),
    /* RFC 9000, Sec 19.16 - RETIRE_CONNECTION_ID with max Sequence Number */
    FUZI_Q_ITEM("test_retire_connection_id_max_sequence", test_retire_connection_id_max_sequence),
    /* RFC 9000, Sec 19.7 - NEW_TOKEN with Token Length > 0, truncated before token data */
    FUZI_Q_ITEM("test_new_token_len_gt_zero_no_token_data_truncated", test_new_token_len_gt_zero_no_token_data_truncated),
    /* RFC 9000, Sec 19.4 - RESET_STREAM with StreamID, App Error, and Final Size all max */
    FUZI_Q_ITEM("test_reset_stream_all_fields_max_value", test_reset_stream_all_fields_max_value),
    /* --- Batch 6 of New Edge Case Test Variants (CRYPTO, DATAGRAM, PADDING) --- */
    /* RFC 9000, Sec 19.6 - CRYPTO, Len > 0, truncated before data */
    FUZI_Q_ITEM("test_crypto_len_gt_zero_no_data_truncated", test_crypto_len_gt_zero_no_data_truncated),
    /* RFC 9221, Sec 4 - DATAGRAM (Type 0x30) empty, truncated after type */
    FUZI_Q_ITEM("test_datagram_type0x30_empty_truncated", test_datagram_type0x30_empty_truncated),
    /* RFC 9221, Sec 4 - DATAGRAM (Type 0x30) one byte data */
    FUZI_Q_ITEM("test_datagram_type0x30_one_byte", test_datagram_type0x30_one_byte),
    /* RFC 9221, Sec 4 - DATAGRAM (Type 0x31) max Length field, minimal actual data */
    FUZI_Q_ITEM("test_datagram_type0x31_maxlength_field_min_data", test_datagram_type0x31_maxlength_field_min_data),
    /* RFC 9221, Sec 4 - DATAGRAM (Type 0x31) Len > 0, truncated before data */
    FUZI_Q_ITEM("test_datagram_type0x31_len_gt_zero_no_data_truncated", test_datagram_type0x31_len_gt_zero_no_data_truncated),
    /* RFC 9000, Sec 19.1, 12.4 - PADDING type non-canonically encoded (2 bytes) */
    FUZI_Q_ITEM("test_padding_type_non_canonical_2byte", test_padding_type_non_canonical_2byte),

    /* RFC 9204 QPACK Instructions */
    FUZI_Q_ITEM("qpack_enc_set_dynamic_table_capacity", test_qpack_enc_set_dynamic_table_capacity),
    FUZI_Q_ITEM("qpack_enc_insert_with_name_ref", test_qpack_enc_insert_with_name_ref),
    FUZI_Q_ITEM("qpack_enc_insert_without_name_ref", test_qpack_enc_insert_without_name_ref), /* Corresponds to "Insert with Literal Name" */
    FUZI_Q_ITEM("qpack_enc_duplicate", test_qpack_enc_duplicate),
    FUZI_Q_ITEM("qpack_dec_header_block_ack", test_qpack_dec_header_block_ack),
    FUZI_Q_ITEM("qpack_dec_stream_cancellation", test_qpack_dec_stream_cancellation),
    FUZI_Q_ITEM("qpack_dec_insert_count_increment", test_qpack_dec_insert_count_increment),
    FUZI_Q_ITEM("qpack_enc_set_dynamic_table_capacity_alt", test_qpack_dec_set_dynamic_table_capacity),
    /* WebSocket Frame Types */
    FUZI_Q_ITEM("test_ws_frame_pong", test_ws_frame_pong),
    FUZI_Q_ITEM("test_ws_frame_ping", test_ws_frame_ping),
    FUZI_Q_ITEM("test_ws_frame_connection_close", test_ws_frame_connection_close),
    FUZI_Q_ITEM("test_ws_frame_binary", test_ws_frame_binary),
    FUZI_Q_ITEM("test_ws_frame_text", test_ws_frame_text),
    FUZI_Q_ITEM("test_ws_frame_continuation", test_ws_frame_continuation),

    /* START OF JULES ADDED FUZI_Q_ITEM ENTRIES (BATCHES 1-8) */

    /* --- Batch 1: Unknown or Unassigned Frame Types --- */
    FUZI_Q_ITEM("quic_unknown_frame_0x20", test_frame_quic_unknown_0x20),
    FUZI_Q_ITEM("quic_unknown_0x3f_payload", test_frame_quic_unknown_0x3f_payload),
    FUZI_Q_ITEM("quic_unknown_greased_0x402a", test_frame_quic_unknown_greased_0x402a),
    FUZI_Q_ITEM("h3_reserved_frame_0x02", test_frame_h3_reserved_0x02),
    FUZI_Q_ITEM("h3_reserved_frame_0x06", test_frame_h3_reserved_0x06),
    FUZI_Q_ITEM("h3_unassigned_extension_0x21", test_frame_h3_unassigned_extension_0x21),

    /* --- Batch 1: Malformed Frame Lengths --- */
    FUZI_Q_ITEM("quic_stream_len0_with_data", test_frame_quic_stream_len0_with_data),
    FUZI_Q_ITEM("quic_stream_len_gt_data", test_frame_quic_stream_len_gt_data),
    FUZI_Q_ITEM("quic_stream_len_lt_data", test_frame_quic_stream_len_lt_data),
    FUZI_Q_ITEM("quic_crypto_len0_with_data", test_frame_quic_crypto_len0_with_data),
    FUZI_Q_ITEM("quic_new_token_len_gt_data", test_frame_quic_new_token_len_gt_data),
    FUZI_Q_ITEM("quic_conn_close_reason_len_gt_data", test_frame_quic_conn_close_reason_len_gt_data),

    /* --- Batch 1: Invalid Frame Field Values --- */
    FUZI_Q_ITEM("quic_max_streams_bidi_value0", test_frame_quic_max_streams_bidi_value0),
    FUZI_Q_ITEM("quic_stop_sending_large_error", test_frame_quic_stop_sending_large_error),
    FUZI_Q_ITEM("quic_max_data_value0_b1", test_frame_quic_max_data_value0_b1),
    FUZI_Q_ITEM("quic_ack_largest0_delay0_1range0_b1", test_frame_quic_ack_largest0_delay0_1range0_b1),
    FUZI_Q_ITEM("quic_ncid_retire_gt_seq_b1", test_frame_quic_ncid_retire_gt_seq_b1),

    /* --- Batch 2: More Invalid Frame Field Values --- */
    FUZI_Q_ITEM("quic_max_data_value0", test_frame_quic_max_data_value0),
    FUZI_Q_ITEM("quic_ack_largest0_delay0_1range0", test_frame_quic_ack_largest0_delay0_1range0),
    FUZI_Q_ITEM("quic_ack_range_count0_first_range_set", test_frame_quic_ack_range_count0_first_range_set),
    FUZI_Q_ITEM("h3_settings_unknown_id", test_frame_h3_settings_unknown_id),
    FUZI_Q_ITEM("h3_settings_max_field_section_size0", test_frame_h3_settings_max_field_section_size0),
    FUZI_Q_ITEM("quic_max_stream_data_value0", test_frame_quic_max_stream_data_value0),
    FUZI_Q_ITEM("quic_conn_close_reserved_error", test_frame_quic_conn_close_reserved_error),
    FUZI_Q_ITEM("quic_new_token_zero_len_invalid", test_frame_quic_new_token_zero_len_invalid),

    /* --- Batch 2: Padding Fuzzing --- */
    FUZI_Q_ITEM("quic_padding_excessive_70bytes", test_frame_quic_padding_excessive_70bytes),
    FUZI_Q_ITEM("quic_ping_then_many_padding", test_frame_quic_ping_then_many_padding),

    /* --- Batch 2: Stream ID Fuzzing (static part) --- */
    FUZI_Q_ITEM("quic_stream_id0", test_frame_quic_stream_id0),
    FUZI_Q_ITEM("quic_max_stream_data_server_uni", test_frame_quic_max_stream_data_server_uni),
    FUZI_Q_ITEM("quic_reset_stream_client_uni", test_frame_quic_reset_stream_client_uni),
    FUZI_Q_ITEM("quic_stop_sending_large_stream_id", test_frame_quic_stop_sending_large_stream_id),
    FUZI_Q_ITEM("quic_stream_client_uses_server_id", test_frame_quic_stream_client_uses_server_id),

    /* --- Batch 3: User Prioritized Frames (Part 1 - DATAGRAM) --- */
    FUZI_Q_ITEM("datagram_type30_with_len_data_error", test_frame_datagram_type30_with_len_data_error),
    FUZI_Q_ITEM("datagram_type31_missing_len_error", test_frame_datagram_type31_missing_len_error),
    FUZI_Q_ITEM("datagram_type31_len_zero_with_data_error", test_frame_datagram_type31_len_zero_with_data_error),
    FUZI_Q_ITEM("datagram_type31_len_huge_data_small", test_frame_datagram_type31_len_huge_data_small),
    FUZI_Q_ITEM("datagram_type30_empty_valid", test_frame_datagram_type30_empty_valid),
    FUZI_Q_ITEM("datagram_type31_len0_empty_valid", test_frame_datagram_type31_len0_empty_valid),

    /* --- Batch 3: User Prioritized Frames (Part 1 - H3 SETTINGS) --- */
    FUZI_Q_ITEM("h3_settings_unknown_id_b3", test_h3_settings_unknown_id_b3),
    FUZI_Q_ITEM("h3_settings_duplicate_id", test_h3_settings_duplicate_id),
    FUZI_Q_ITEM("h3_settings_invalid_value_for_id", test_h3_settings_invalid_value_for_id),

    /* --- Batch 3: User Prioritized Frames (Part 2 - H3 ORIGIN & QUIC STREAM) --- */
    FUZI_Q_ITEM("h3_origin_unnegotiated", test_h3_origin_unnegotiated),
    FUZI_Q_ITEM("h3_origin_multiple_entries", test_h3_origin_multiple_entries),
    FUZI_Q_ITEM("h3_origin_empty_entry", test_h3_origin_empty_entry),
    FUZI_Q_ITEM("stream_len_bit_no_len_field", test_stream_len_bit_no_len_field),
    FUZI_Q_ITEM("stream_off_bit_no_off_field", test_stream_off_bit_no_off_field),
    FUZI_Q_ITEM("stream_len_fin_zero_len_with_data", test_stream_len_fin_zero_len_with_data),
    FUZI_Q_ITEM("stream_type08_empty_implicit_len", test_stream_type08_empty_implicit_len),
    FUZI_Q_ITEM("stream_type0C_offset_empty_implicit_len", test_stream_type0C_offset_empty_implicit_len),

    /* --- Batch 3: User Prioritized Frames (Part 3 - QUIC STREAM type range & WebSocket) --- */
    FUZI_Q_ITEM("type_stream_range_just_below", test_frame_type_stream_range_just_below),
    FUZI_Q_ITEM("type_padding_as_stream", test_frame_type_padding_as_stream),
    FUZI_Q_ITEM("type_stream_range_lower_bound", test_frame_type_stream_range_lower_bound),
    FUZI_Q_ITEM("type_stream_range_upper_bound", test_frame_type_stream_range_upper_bound),
    FUZI_Q_ITEM("type_stream_range_just_above", test_frame_type_stream_range_just_above),
    FUZI_Q_ITEM("ws_control_frame_fin_zero_invalid", test_ws_control_frame_fin_zero_invalid),
    FUZI_Q_ITEM("ws_text_frame_rsv1_set_invalid", test_ws_text_frame_rsv1_set_invalid),
    FUZI_Q_ITEM("ws_text_fin0_then_text_continuation_part1", test_ws_text_fin0_then_text_continuation_part1),
    FUZI_Q_ITEM("ws_text_fin0_then_text_continuation_part2_invalid", test_ws_text_fin0_then_text_continuation_part2_invalid),
    FUZI_Q_ITEM("ws_len126_data_truncated", test_ws_len126_data_truncated),
    FUZI_Q_ITEM("ws_len127_data_truncated", test_ws_len127_data_truncated),

    /* --- Batch 4: More Static Frames --- */
    FUZI_Q_ITEM("quic_unknown_frame_high_value", test_frame_quic_unknown_frame_high_value),
    FUZI_Q_ITEM("h3_reserved_frame_0x08", test_frame_h3_reserved_frame_0x08),
    FUZI_Q_ITEM("h3_unassigned_type_0x4040", test_frame_h3_unassigned_type_0x4040),
    FUZI_Q_ITEM("ws_reserved_control_0x0B", test_frame_ws_reserved_control_0x0B),
    FUZI_Q_ITEM("ws_reserved_non_control_0x03", test_frame_ws_reserved_non_control_0x03),
    FUZI_Q_ITEM("h3_headers_incomplete_qpack", test_frame_h3_headers_incomplete_qpack),
    FUZI_Q_ITEM("ws_ping_payload_gt_125", test_frame_ws_ping_payload_gt_125),
    FUZI_Q_ITEM("quic_max_streams_uni_value0", test_frame_quic_max_streams_uni_value0),
    FUZI_Q_ITEM("quic_ncid_short_token", test_frame_quic_ncid_short_token),
    FUZI_Q_ITEM("quic_ncid_zero_len_cid", test_frame_quic_ncid_zero_len_cid),
    FUZI_Q_ITEM("quic_path_challenge_all_zero_data_b4", test_frame_quic_path_challenge_all_zero_data_b4),
    FUZI_Q_ITEM("quic_path_response_mismatch_data_b4", test_frame_quic_path_response_mismatch_data_b4),

    /* --- Batch 5: Further Static Frames --- */
    FUZI_Q_ITEM("quic_unknown_frame_grease_0x2A", test_frame_quic_unknown_frame_grease_0x2A),
    FUZI_Q_ITEM("h3_reserved_frame_0x09", test_frame_h3_reserved_frame_0x09),
    FUZI_Q_ITEM("ws_control_frame_0x0C_invalid", test_frame_ws_control_frame_0x0C_invalid),
    FUZI_Q_ITEM("quic_crypto_len_gt_data_b5", test_frame_quic_crypto_len_gt_data_b5),
    FUZI_Q_ITEM("h3_push_promise_incomplete_payload", test_frame_h3_push_promise_incomplete_payload),
    FUZI_Q_ITEM("quic_retire_connection_id_large_seq", test_frame_quic_retire_connection_id_large_seq),
    FUZI_Q_ITEM("h3_goaway_large_id", test_frame_h3_goaway_large_id),
    FUZI_Q_ITEM("quic_ncid_retire_gt_seq_b5", test_frame_quic_ncid_retire_gt_seq_b5),
    FUZI_Q_ITEM("quic_path_challenge_empty", test_frame_quic_path_challenge_empty),
    FUZI_Q_ITEM("quic_path_response_empty", test_frame_quic_path_response_empty),
    FUZI_Q_ITEM("quic_ack_delay_max_varint", test_frame_quic_ack_delay_max_varint),
    FUZI_Q_ITEM("quic_stream_all_fields_max_varint", test_frame_quic_stream_all_fields_max_varint),
    FUZI_Q_ITEM("h3_data_len0_with_payload", test_frame_h3_data_len0_with_payload),
    FUZI_Q_ITEM("ws_close_invalid_code", test_frame_ws_close_invalid_code),

    /* --- Batch 8: Combined Set (original Batch 6/7 + 4 new from user) --- */
    FUZI_Q_ITEM("h2_window_update_increment0_b7", test_frame_h2_window_update_increment0_b7),
    FUZI_Q_ITEM("quic_conn_close_transport_app_err_code_b7", test_frame_quic_conn_close_transport_app_err_code_b7),
    FUZI_Q_ITEM("h3_max_push_id_value0_b7", test_frame_h3_max_push_id_value0_b7),
    FUZI_Q_ITEM("quic_ncid_cid_len_gt_pico_max_b7", test_frame_quic_ncid_cid_len_gt_pico_max_b7),
    FUZI_Q_ITEM("ws_text_rsv2_set", test_frame_ws_text_rsv2_set),
    FUZI_Q_ITEM("ws_text_rsv3_set", test_frame_ws_text_rsv3_set),
    FUZI_Q_ITEM("quic_ack_non_ecn_with_ecn_counts_b7", test_frame_quic_ack_non_ecn_with_ecn_counts_b7),
    FUZI_Q_ITEM("quic_greased_type_0x5BEE_with_payload", test_frame_quic_greased_type_0x5BEE_with_payload),
    FUZI_Q_ITEM("h3_reserved_type_4byte_varint", test_frame_h3_reserved_type_4byte_varint),
    FUZI_Q_ITEM("ws_continuation_fin1_with_payload", test_frame_ws_continuation_fin1_with_payload),
    FUZI_Q_ITEM("quic_ncid_large_retire_small_seq", test_frame_quic_ncid_large_retire_small_seq),
    FUZI_Q_ITEM("quic_extension_0x21", test_frame_quic_extension_0x21),
    FUZI_Q_ITEM("h3_extension_0x2F", test_frame_h3_extension_0x2F),
    FUZI_Q_ITEM("quic_ack_double_zero_range", test_frame_quic_ack_double_zero_range),
    FUZI_Q_ITEM("ws_all_rsv_set", test_frame_ws_all_rsv_set),

    /* HTTP/2 and HPACK Frame Types */
    FUZI_Q_ITEM("test_h2_frame_type_altsvc", test_h2_frame_type_altsvc),
    FUZI_Q_ITEM("test_hpack_dynamic_table_size_update", test_hpack_dynamic_table_size_update),
    FUZI_Q_ITEM("test_hpack_literal_never_indexed", test_hpack_literal_never_indexed),
    FUZI_Q_ITEM("test_hpack_literal_no_indexing", test_hpack_literal_no_indexing),
    FUZI_Q_ITEM("test_hpack_literal_inc_indexing", test_hpack_literal_inc_indexing),
    FUZI_Q_ITEM("test_hpack_indexed_header_field", test_hpack_indexed_header_field),
    FUZI_Q_ITEM("test_h2_frame_type_continuation", test_h2_frame_type_continuation),
    FUZI_Q_ITEM("test_h2_frame_type_window_update", test_h2_frame_type_window_update),
    FUZI_Q_ITEM("test_h2_frame_type_goaway", test_h2_frame_type_goaway),
    FUZI_Q_ITEM("test_h2_frame_type_ping", test_h2_frame_type_ping),
    FUZI_Q_ITEM("test_h2_frame_type_push_promise", test_h2_frame_type_push_promise),
    FUZI_Q_ITEM("test_h2_frame_type_settings", test_h2_frame_type_settings),
    FUZI_Q_ITEM("test_h2_frame_type_rst_stream", test_h2_frame_type_rst_stream),
    FUZI_Q_ITEM("test_h2_frame_type_priority", test_h2_frame_type_priority),
    FUZI_Q_ITEM("test_h2_frame_type_headers", test_h2_frame_type_headers),
    FUZI_Q_ITEM("test_h2_frame_type_data", test_h2_frame_type_data),

    /* START OF JULES ADDED FUZI_Q_ITEM ENTRIES (BATCHES 1-8) */

    /* --- Batch 1: Unknown or Unassigned Frame Types --- */
    FUZI_Q_ITEM("quic_unknown_frame_0x20", test_frame_quic_unknown_0x20),
    FUZI_Q_ITEM("h3_reserved_frame_0x02", test_frame_h3_reserved_0x02),
    FUZI_Q_ITEM("h3_reserved_frame_0x06", test_frame_h3_reserved_0x06),

    /* --- Batch 1: Malformed Frame Lengths --- */
    FUZI_Q_ITEM("quic_stream_len0_with_data", test_frame_quic_stream_len0_with_data),
    FUZI_Q_ITEM("quic_stream_len_gt_data", test_frame_quic_stream_len_gt_data),
    FUZI_Q_ITEM("quic_stream_len_lt_data", test_frame_quic_stream_len_lt_data),

    /* --- Batch 1: Invalid Frame Field Values --- */
    FUZI_Q_ITEM("quic_max_streams_bidi_value0", test_frame_quic_max_streams_bidi_value0),
    FUZI_Q_ITEM("quic_stop_sending_large_error", test_frame_quic_stop_sending_large_error),

    /* --- Batch 2: More Invalid Frame Field Values --- */
    FUZI_Q_ITEM("quic_max_data_value0", test_frame_quic_max_data_value0),
    FUZI_Q_ITEM("quic_ack_largest0_delay0_1range0", test_frame_quic_ack_largest0_delay0_1range0),
    FUZI_Q_ITEM("quic_ack_range_count0_first_range_set", test_frame_quic_ack_range_count0_first_range_set),
    FUZI_Q_ITEM("h3_settings_unknown_id", test_frame_h3_settings_unknown_id),
    FUZI_Q_ITEM("h3_settings_max_field_section_size0", test_frame_h3_settings_max_field_section_size0),

    /* --- Batch 2: Padding Fuzzing --- */
    FUZI_Q_ITEM("quic_padding_excessive_70bytes", test_frame_quic_padding_excessive_70bytes),

    /* --- Batch 2: Stream ID Fuzzing (static part) --- */
    FUZI_Q_ITEM("quic_stream_id0", test_frame_quic_stream_id0),

    /* --- Batch 3: User Prioritized Frames (Part 1 - DATAGRAM & H3 SETTINGS) --- */
    FUZI_Q_ITEM("datagram_type30_with_len_data_error", test_frame_datagram_type30_with_len_data_error),
    FUZI_Q_ITEM("datagram_type31_missing_len_error", test_frame_datagram_type31_missing_len_error),
    FUZI_Q_ITEM("datagram_type31_len_zero_with_data_error", test_frame_datagram_type31_len_zero_with_data_error),
    FUZI_Q_ITEM("h3_settings_excessive_pairs", test_h3_settings_excessive_pairs),

    /* --- Batch 3: User Prioritized Frames (Part 2 - H3 ORIGIN & QUIC STREAM) --- */
    FUZI_Q_ITEM("h3_origin_unnegotiated", test_h3_origin_unnegotiated),
    FUZI_Q_ITEM("stream_len_bit_no_len_field", test_stream_len_bit_no_len_field),
    FUZI_Q_ITEM("stream_off_bit_no_off_field", test_stream_off_bit_no_off_field),
    FUZI_Q_ITEM("stream_len_fin_zero_len_with_data", test_stream_len_fin_zero_len_with_data),

    /* --- Batch 3: User Prioritized Frames (Part 3 - QUIC STREAM type range & WebSocket) --- */
    FUZI_Q_ITEM("type_stream_range_just_below", test_frame_type_stream_range_just_below),
    FUZI_Q_ITEM("type_stream_range_lower_bound", test_frame_type_stream_range_lower_bound),
    FUZI_Q_ITEM("type_stream_range_upper_bound", test_frame_type_stream_range_upper_bound),
    FUZI_Q_ITEM("type_stream_range_just_above", test_frame_type_stream_range_just_above),
    FUZI_Q_ITEM("ws_control_frame_fin_zero_invalid", test_ws_control_frame_fin_zero_invalid),
    FUZI_Q_ITEM("ws_text_fin0_then_text_continuation_part1", test_ws_text_fin0_then_text_continuation_part1),
    FUZI_Q_ITEM("ws_text_fin0_then_text_continuation_part2_invalid", test_ws_text_fin0_then_text_continuation_part2_invalid),

    /* --- Batch 4: More Static Frames --- */
    FUZI_Q_ITEM("quic_unknown_frame_high_value", test_frame_quic_unknown_frame_high_value),
    FUZI_Q_ITEM("h3_reserved_frame_0x08", test_frame_h3_reserved_frame_0x08),
    FUZI_Q_ITEM("h3_unassigned_type_0x4040", test_frame_h3_unassigned_type_0x4040),
    FUZI_Q_ITEM("ws_reserved_control_0x0B", test_frame_ws_reserved_control_0x0B),
    FUZI_Q_ITEM("ws_reserved_non_control_0x03", test_frame_ws_reserved_non_control_0x03),
    FUZI_Q_ITEM("h3_headers_incomplete_qpack", test_frame_h3_headers_incomplete_qpack),
    FUZI_Q_ITEM("ws_ping_payload_gt_125", test_frame_ws_ping_payload_gt_125),
    FUZI_Q_ITEM("quic_max_streams_uni_value0", test_frame_quic_max_streams_uni_value0),
    FUZI_Q_ITEM("quic_ncid_short_token", test_frame_quic_ncid_short_token),
    FUZI_Q_ITEM("quic_ncid_zero_len_cid", test_frame_quic_ncid_zero_len_cid),

    /* --- Batch 5: Further Static Frames --- */
    FUZI_Q_ITEM("quic_unknown_frame_grease_0x2A", test_frame_quic_unknown_frame_grease_0x2A),
    FUZI_Q_ITEM("h3_reserved_frame_0x09", test_frame_h3_reserved_frame_0x09),
    FUZI_Q_ITEM("ws_control_frame_0x0C_invalid", test_frame_ws_control_frame_0x0C_invalid),
    FUZI_Q_ITEM("h3_push_promise_incomplete_payload", test_frame_h3_push_promise_incomplete_payload),
    FUZI_Q_ITEM("quic_retire_connection_id_large_seq", test_frame_quic_retire_connection_id_large_seq),
    FUZI_Q_ITEM("h3_goaway_large_id", test_frame_h3_goaway_large_id),
    FUZI_Q_ITEM("quic_path_challenge_empty", test_frame_quic_path_challenge_empty),
    FUZI_Q_ITEM("quic_path_response_empty", test_frame_quic_path_response_empty),

    /* --- Batch 8: Combined Set (original Batch 6/7 + 4 new from user) --- */
    FUZI_Q_ITEM("h2_window_update_increment0_b7", test_frame_h2_window_update_increment0_b7),
    FUZI_Q_ITEM("quic_conn_close_transport_app_err_code_b7", test_frame_quic_conn_close_transport_app_err_code_b7),
    FUZI_Q_ITEM("h3_max_push_id_value0_b7", test_frame_h3_max_push_id_value0_b7),
    FUZI_Q_ITEM("quic_ncid_cid_len_gt_pico_max_b7", test_frame_quic_ncid_cid_len_gt_pico_max_b7),
    FUZI_Q_ITEM("ws_text_rsv2_set", test_frame_ws_text_rsv2_set),
    FUZI_Q_ITEM("ws_text_rsv3_set", test_frame_ws_text_rsv3_set),
    FUZI_Q_ITEM("quic_ack_non_ecn_with_ecn_counts_b7", test_frame_quic_ack_non_ecn_with_ecn_counts_b7),
    FUZI_Q_ITEM("quic_greased_type_0x5BEE_with_payload", test_frame_quic_greased_type_0x5BEE_with_payload),
    FUZI_Q_ITEM("h3_reserved_type_4byte_varint", test_frame_h3_reserved_type_4byte_varint),
    FUZI_Q_ITEM("ws_continuation_fin1_with_payload", test_frame_ws_continuation_fin1_with_payload),
    FUZI_Q_ITEM("quic_ncid_large_retire_small_seq", test_frame_quic_ncid_large_retire_small_seq),

    /* New QUIC negative test cases */
    FUZI_Q_ITEM("quic_conn_close_missing_error", test_quic_conn_close_missing_error),
    FUZI_Q_ITEM("quic_ack_bad_range", test_quic_ack_bad_range),
    FUZI_Q_ITEM("quic_reset_zero_error", test_quic_reset_zero_error),
    FUZI_Q_ITEM("quic_crypto_big_offset", test_quic_crypto_big_offset),
    FUZI_Q_ITEM("quic_new_token_empty", test_quic_new_token_empty),
    FUZI_Q_ITEM("quic_stream_id_zero", test_quic_stream_id_zero),
    FUZI_Q_ITEM("quic_max_data_zero", test_quic_max_data_zero),
    FUZI_Q_ITEM("quic_max_streams_huge", test_quic_max_streams_huge),
    FUZI_Q_ITEM("quic_ncid_bad_seq", test_quic_ncid_bad_seq),
    FUZI_Q_ITEM("quic_retire_seq_zero", test_quic_retire_seq_zero),
    FUZI_Q_ITEM("quic_path_challenge_predictable", test_quic_path_challenge_predictable),
    FUZI_Q_ITEM("quic_reserved_frame_type", test_quic_reserved_frame_type),
    FUZI_Q_ITEM("quic_stream_len_mismatch", test_quic_stream_len_mismatch),
    FUZI_Q_ITEM("quic_ack_future", test_quic_ack_future),
    FUZI_Q_ITEM("quic_datagram_bad_len", test_quic_datagram_bad_len),
    FUZI_Q_ITEM("quic_stream_noncanon_varint", test_quic_stream_noncanon_varint),
    FUZI_Q_ITEM("quic_conn_close_bad_frame_ref", test_quic_conn_close_bad_frame_ref),

    /* Additional QUIC Negative Test Cases */
    FUZI_Q_ITEM("quic_crypto_offset_max", test_frame_quic_crypto_offset_max),
    FUZI_Q_ITEM("quic_stream_invalid_final_size", test_frame_quic_stream_invalid_final_size),
    FUZI_Q_ITEM("quic_ack_pkt_overflow", test_frame_quic_ack_pkt_overflow),
    FUZI_Q_ITEM("quic_handshake_done_invalid", test_frame_quic_handshake_done_invalid),
    FUZI_Q_ITEM("quic_multiple_handshake_done", test_frame_quic_multiple_handshake_done),
    FUZI_Q_ITEM("quic_stream_id_maximum", test_frame_quic_stream_id_maximum),
    FUZI_Q_ITEM("quic_ping_invalid_context", test_frame_quic_ping_invalid_context),
    FUZI_Q_ITEM("quic_conn_close_max_err", test_frame_quic_conn_close_max_err),
    FUZI_Q_ITEM("quic_reset_after_fin_violation", test_frame_quic_reset_after_fin_violation),

    /* === COMPREHENSIVE NEGATIVE TEST CASES FUZI_Q_ITEM ENTRIES === */
    
    /* Frame Type Boundary Testing */
    FUZI_Q_ITEM("frame_type_boundary_0x3F", test_frame_type_boundary_0x3F),
    FUZI_Q_ITEM("frame_type_boundary_0x4000", test_frame_type_boundary_0x4000),
    FUZI_Q_ITEM("frame_type_boundary_0x7FFF", test_frame_type_boundary_0x7FFF),
    FUZI_Q_ITEM("frame_type_boundary_0x80000000", test_frame_type_boundary_0x80000000),
    FUZI_Q_ITEM("frame_type_boundary_0xBFFFFFFF", test_frame_type_boundary_0xBFFFFFFF),
    
    /* Stream State Violations */
    FUZI_Q_ITEM("stream_after_reset_violation", test_stream_after_reset_violation),
    FUZI_Q_ITEM("stop_sending_after_fin_violation", test_stop_sending_after_fin_violation),
    FUZI_Q_ITEM("max_stream_data_closed_stream", test_max_stream_data_closed_stream),
    
    /* Flow Control Edge Cases */
    FUZI_Q_ITEM("max_data_regression", test_max_data_regression),
    FUZI_Q_ITEM("max_stream_data_regression", test_max_stream_data_regression),
    FUZI_Q_ITEM("stream_exceed_max_data", test_stream_exceed_max_data),
    
    /* Connection ID Management Violations */
    FUZI_Q_ITEM("new_cid_seq_regression", test_new_cid_seq_regression),
    FUZI_Q_ITEM("retire_cid_nonexistent", test_retire_cid_nonexistent),
    FUZI_Q_ITEM("new_cid_duplicate_cid", test_new_cid_duplicate_cid),
    
    /* Frame Fragmentation Attacks */
    FUZI_Q_ITEM("frame_partial_stream", test_frame_partial_stream),
    FUZI_Q_ITEM("frame_partial_varint", test_frame_partial_varint),
    FUZI_Q_ITEM("frame_missing_fields", test_frame_missing_fields),
    
    /* Varint Encoding Attacks */
    FUZI_Q_ITEM("varint_excessive_zeros", test_varint_excessive_zeros),
    FUZI_Q_ITEM("varint_boundary_63", test_varint_boundary_63),
    FUZI_Q_ITEM("varint_boundary_64", test_varint_boundary_64),
    
    /* Timing Attack Vectors */
    FUZI_Q_ITEM("ack_timing_pattern", test_ack_timing_pattern),
    FUZI_Q_ITEM("path_challenge_timing", test_path_challenge_timing),
    
    /* Resource Exhaustion Patterns */
    FUZI_Q_ITEM("stream_fragment_spam1", test_stream_fragment_spam1),
    FUZI_Q_ITEM("stream_fragment_spam2", test_stream_fragment_spam2),
    FUZI_Q_ITEM("stream_fragment_spam3", test_stream_fragment_spam3),
    FUZI_Q_ITEM("rapid_new_cid1", test_rapid_new_cid1),
    FUZI_Q_ITEM("rapid_new_cid2", test_rapid_new_cid2),
    
    /* Protocol State Machine Violations */
    FUZI_Q_ITEM("handshake_done_wrong_space", test_handshake_done_wrong_space),
    FUZI_Q_ITEM("crypto_post_handshake", test_crypto_post_handshake),
    FUZI_Q_ITEM("ack_frequency_early", test_ack_frequency_early),
    
    /* Frame Size Manipulation */
    FUZI_Q_ITEM("frame_size_bomb", test_frame_size_bomb),
    FUZI_Q_ITEM("frame_zero_size_claim", test_frame_zero_size_claim),
    
    /* Cross-Protocol Confusion */
    FUZI_Q_ITEM("h2_in_quic_stream", test_h2_in_quic_stream),
    FUZI_Q_ITEM("ws_in_quic_stream", test_ws_in_quic_stream),
    FUZI_Q_ITEM("tls_record_pattern", test_tls_record_pattern),
    
    /* Integer Overflow Attempts */
    FUZI_Q_ITEM("overflow_offset_plus_len", test_overflow_offset_plus_len),
    FUZI_Q_ITEM("overflow_ack_range", test_overflow_ack_range),
    
    /* Extension Frame Spoofing */
    FUZI_Q_ITEM("fake_extension_frame", test_fake_extension_frame),
    FUZI_Q_ITEM("malicious_grease", test_malicious_grease),
    
    /* Path Validation Exploits */
    FUZI_Q_ITEM("path_challenge_identical", test_path_challenge_identical),
    FUZI_Q_ITEM("path_response_wrong", test_path_response_wrong),
    
    /* Token Management Attacks */
    FUZI_Q_ITEM("new_token_malformed", test_new_token_malformed),
    FUZI_Q_ITEM("new_token_null_bytes", test_new_token_null_bytes),
    
    /* Stream Limit Boundary Testing */
    FUZI_Q_ITEM("stream_boundary_client", test_stream_boundary_client),
    FUZI_Q_ITEM("stream_boundary_server", test_stream_boundary_server),
    FUZI_Q_ITEM("bidi_ops_on_uni", test_bidi_ops_on_uni),
    
    /* Congestion Control Attacks */
    FUZI_Q_ITEM("rapid_max_data_increase", test_rapid_max_data_increase),
    FUZI_Q_ITEM("suspicious_data_blocked", test_suspicious_data_blocked),
    
    /* Frame Ordering Violations */
    FUZI_Q_ITEM("ack_future_packets", test_ack_future_packets),
    FUZI_Q_ITEM("crypto_reorder", test_crypto_reorder),
    
    /* Padding Pattern Analysis */
    FUZI_Q_ITEM("padding_covert_channel", test_padding_covert_channel),
    FUZI_Q_ITEM("padding_frame_mix", test_padding_frame_mix),
    
    /* Memory Exhaustion Patterns */
    FUZI_Q_ITEM("overlap_fragment1", test_overlap_fragment1),
    FUZI_Q_ITEM("overlap_fragment2", test_overlap_fragment2),
    FUZI_Q_ITEM("overlap_fragment3", test_overlap_fragment3),
    
    /* Version Negotiation Confusion */
    FUZI_Q_ITEM("version_confusion", test_version_confusion),
    
    /* Error Code Enumeration */
    FUZI_Q_ITEM("conn_close_enum_error", test_conn_close_enum_error),
    FUZI_Q_ITEM("quic_unknown_type_0x40", test_frame_quic_unknown_type_0x40),
    FUZI_Q_ITEM("quic_unknown_type_0x41", test_frame_quic_unknown_type_0x41),
    FUZI_Q_ITEM("quic_unknown_type_0x42", test_frame_quic_unknown_type_0x42),
    FUZI_Q_ITEM("quic_path_response_incorrect", test_frame_quic_path_response_incorrect),
    FUZI_Q_ITEM("quic_stream_flow_violation", test_frame_quic_stream_flow_violation),
    FUZI_Q_ITEM("quic_crypto_0rtt_invalid", test_frame_quic_crypto_0rtt_invalid),
    FUZI_Q_ITEM("quic_ack_0rtt_invalid", test_frame_quic_ack_0rtt_invalid),
    FUZI_Q_ITEM("quic_ncid_flood_seq1", test_frame_quic_ncid_flood_seq1),
    FUZI_Q_ITEM("quic_ncid_flood_seq2", test_frame_quic_ncid_flood_seq2),
    FUZI_Q_ITEM("quic_max_streams_rapid1", test_frame_quic_max_streams_rapid1),
    FUZI_Q_ITEM("quic_max_streams_rapid2", test_frame_quic_max_streams_rapid2),
    FUZI_Q_ITEM("quic_stream_zero_len_explicit", test_frame_quic_stream_zero_len_explicit),
    FUZI_Q_ITEM("quic_path_challenge_replay", test_frame_quic_path_challenge_replay),
    FUZI_Q_ITEM("quic_max_stream_data_decrease", test_frame_quic_max_stream_data_decrease),
    FUZI_Q_ITEM("quic_streams_blocked_invalid_limit", test_frame_quic_streams_blocked_invalid_limit),
    FUZI_Q_ITEM("quic_invalid_varint", test_frame_quic_invalid_varint),
    FUZI_Q_ITEM("quic_ack_malformed", test_frame_quic_ack_malformed),
    FUZI_Q_ITEM("quic_multiple_path_challenge", test_frame_quic_multiple_path_challenge),
    FUZI_Q_ITEM("quic_stream_fragment1", test_frame_quic_stream_fragment1),
    FUZI_Q_ITEM("quic_stream_fragment2", test_frame_quic_stream_fragment2),
    FUZI_Q_ITEM("quic_ack_many_ranges", test_frame_quic_ack_many_ranges),
    FUZI_Q_ITEM("quic_ncid_duplicate", test_frame_quic_ncid_duplicate),
    FUZI_Q_ITEM("quic_ncid_max_len", test_frame_quic_ncid_max_len),
    FUZI_Q_ITEM("quic_reset_flood1", test_frame_quic_reset_flood1),
    FUZI_Q_ITEM("quic_reset_flood2", test_frame_quic_reset_flood2),
    FUZI_Q_ITEM("quic_crypto_overflow", test_frame_quic_crypto_overflow),
    FUZI_Q_ITEM("quic_new_token_overflow", test_frame_quic_new_token_overflow),
    FUZI_Q_ITEM("quic_ack_timing_suspicious", test_frame_quic_ack_timing_suspicious),

    /* Additional Advanced Protocol Violation Test Cases */
    
    /* HTTP/3 Protocol Violations */
    FUZI_Q_ITEM("h3_settings_frame_on_request_stream", test_frame_h3_settings_frame_on_request_stream),
    FUZI_Q_ITEM("h3_data_frame_without_headers", test_frame_h3_data_frame_without_headers),
    FUZI_Q_ITEM("h3_headers_after_trailers", test_frame_h3_headers_after_trailers),
    FUZI_Q_ITEM("h3_push_promise_on_unidirectional", test_frame_h3_push_promise_on_unidirectional),
    FUZI_Q_ITEM("h3_goaway_with_invalid_id", test_frame_h3_goaway_with_invalid_id),
    FUZI_Q_ITEM("h3_max_push_id_decrease", test_frame_h3_max_push_id_decrease),
    FUZI_Q_ITEM("h3_cancel_push_nonexistent", test_frame_h3_cancel_push_nonexistent),
    FUZI_Q_ITEM("h3_duplicate_settings", test_frame_h3_duplicate_settings),
    FUZI_Q_ITEM("h3_reserved_setting_values", test_frame_h3_reserved_setting_values),
    FUZI_Q_ITEM("h3_qpack_encoder_stream_wrong_type", test_frame_h3_qpack_encoder_stream_wrong_type),
    
    /* WebSocket Protocol Violations */
    FUZI_Q_ITEM("ws_continuation_without_start", test_frame_ws_continuation_without_start),
    FUZI_Q_ITEM("ws_text_after_binary_start", test_frame_ws_text_after_binary_start),
    FUZI_Q_ITEM("ws_control_frame_fragmented", test_frame_ws_control_frame_fragmented),
    FUZI_Q_ITEM("ws_close_after_close", test_frame_ws_close_after_close),
    FUZI_Q_ITEM("ws_invalid_utf8_text", test_frame_ws_invalid_utf8_text),
    FUZI_Q_ITEM("ws_mask_bit_server_to_client", test_frame_ws_mask_bit_server_to_client),
    FUZI_Q_ITEM("ws_unmask_bit_client_to_server", test_frame_ws_unmask_bit_client_to_server),
    FUZI_Q_ITEM("ws_invalid_close_code_1005", test_frame_ws_invalid_close_code_1005),
    FUZI_Q_ITEM("ws_close_reason_without_code", test_frame_ws_close_reason_without_code),
    FUZI_Q_ITEM("ws_pong_without_ping", test_frame_ws_pong_without_ping),
    
    /* QUIC Connection Migration Attacks */
    FUZI_Q_ITEM("quic_path_challenge_wrong_dcid", test_frame_quic_path_challenge_wrong_dcid),
    FUZI_Q_ITEM("quic_path_response_replay_attack", test_frame_quic_path_response_replay_attack),
    FUZI_Q_ITEM("quic_new_cid_migration_attack", test_frame_quic_new_cid_migration_attack),
    FUZI_Q_ITEM("quic_retire_cid_active_path", test_frame_quic_retire_cid_active_path),
    FUZI_Q_ITEM("quic_path_validation_amplification", test_frame_quic_path_validation_amplification),
    FUZI_Q_ITEM("quic_connection_migration_flood", test_frame_quic_connection_migration_flood),
    
    /* QUIC Cryptographic Attacks */
    FUZI_Q_ITEM("quic_crypto_frame_reordering", test_frame_quic_crypto_frame_reordering),
    FUZI_Q_ITEM("quic_crypto_duplicate_offset", test_frame_quic_crypto_duplicate_offset),
    FUZI_Q_ITEM("quic_crypto_gap_attack", test_frame_quic_crypto_gap_attack),
    FUZI_Q_ITEM("quic_handshake_replay", test_frame_quic_handshake_replay),
    FUZI_Q_ITEM("quic_crypto_downgrade_attack", test_frame_quic_crypto_downgrade_attack),
    FUZI_Q_ITEM("quic_early_data_replay", test_frame_quic_early_data_replay),
    
    /* QUIC Flow Control Attacks */
    FUZI_Q_ITEM("quic_flow_control_bypass", test_frame_quic_flow_control_bypass),
    FUZI_Q_ITEM("quic_max_data_oscillation", test_frame_quic_max_data_oscillation),
    FUZI_Q_ITEM("quic_stream_data_blocked_lie", test_frame_quic_stream_data_blocked_lie),
    FUZI_Q_ITEM("quic_data_blocked_premature", test_frame_quic_data_blocked_premature),
    FUZI_Q_ITEM("quic_max_streams_exhaustion", test_frame_quic_max_streams_exhaustion),
    FUZI_Q_ITEM("quic_stream_limit_bypass", test_frame_quic_stream_limit_bypass),
    
    /* QUIC Packet Number Space Violations */
    FUZI_Q_ITEM("quic_ack_wrong_pn_space", test_frame_quic_ack_wrong_pn_space),
    FUZI_Q_ITEM("quic_crypto_in_app_space", test_frame_quic_crypto_in_app_space),
    FUZI_Q_ITEM("quic_handshake_done_early", test_frame_quic_handshake_done_early),
    FUZI_Q_ITEM("quic_0rtt_in_handshake_pn", test_frame_quic_0rtt_in_handshake_pn),
    FUZI_Q_ITEM("quic_stream_in_initial_pn", test_frame_quic_stream_in_initial_pn),
    
    /* Advanced Varint Fuzzing */
    FUZI_Q_ITEM("quic_varint_canonical_violation", test_frame_quic_varint_canonical_violation),
    FUZI_Q_ITEM("quic_varint_length_mismatch", test_frame_quic_varint_length_mismatch),
    FUZI_Q_ITEM("quic_varint_reserved_bits", test_frame_quic_varint_reserved_bits),
    FUZI_Q_ITEM("quic_varint_maximum_plus_one", test_frame_quic_varint_maximum_plus_one),
    FUZI_Q_ITEM("quic_varint_underflow", test_frame_quic_varint_underflow),
    
    /* DoS and Resource Exhaustion */
    FUZI_Q_ITEM("quic_memory_exhaustion_stream_ids", test_frame_quic_memory_exhaustion_stream_ids),
    FUZI_Q_ITEM("quic_cpu_exhaustion_ack_ranges", test_frame_quic_cpu_exhaustion_ack_ranges),
    FUZI_Q_ITEM("quic_bandwidth_exhaustion_padding", test_frame_quic_bandwidth_exhaustion_padding),
    FUZI_Q_ITEM("quic_connection_table_exhaustion", test_frame_quic_connection_table_exhaustion),
    FUZI_Q_ITEM("quic_token_cache_pollution", test_frame_quic_token_cache_pollution),
    
    /* State Machine Confusion */
    FUZI_Q_ITEM("quic_stream_after_connection_close", test_frame_quic_stream_after_connection_close),
    FUZI_Q_ITEM("quic_ack_after_connection_close", test_frame_quic_ack_after_connection_close),
    FUZI_Q_ITEM("quic_new_token_after_migration", test_frame_quic_new_token_after_migration),
    FUZI_Q_ITEM("quic_path_challenge_after_close", test_frame_quic_path_challenge_after_close),
    FUZI_Q_ITEM("quic_handshake_done_twice", test_frame_quic_handshake_done_twice),
    
    /* Covert Channel Attacks */
    FUZI_Q_ITEM("quic_timing_channel_ack_delay", test_frame_quic_timing_channel_ack_delay),
    FUZI_Q_ITEM("quic_padding_pattern_channel", test_frame_quic_padding_pattern_channel),
    FUZI_Q_ITEM("quic_stream_id_pattern_channel", test_frame_quic_stream_id_pattern_channel),
    FUZI_Q_ITEM("quic_error_code_channel", test_frame_quic_error_code_channel),
    FUZI_Q_ITEM("quic_frame_ordering_channel", test_frame_quic_frame_ordering_channel),
    
    /* Protocol Downgrade Attacks */
    FUZI_Q_ITEM("quic_version_downgrade_mitm", test_frame_quic_version_downgrade_mitm),
    FUZI_Q_ITEM("quic_transport_parameter_downgrade", test_frame_quic_transport_parameter_downgrade),
    FUZI_Q_ITEM("quic_extension_downgrade", test_frame_quic_extension_downgrade),
    FUZI_Q_ITEM("quic_cipher_suite_downgrade", test_frame_quic_cipher_suite_downgrade),
    
    /* Side Channel Attacks */
    FUZI_Q_ITEM("quic_cache_timing_attack", test_frame_quic_cache_timing_attack),
    FUZI_Q_ITEM("quic_branch_prediction_attack", test_frame_quic_branch_prediction_attack),
    FUZI_Q_ITEM("quic_memory_access_pattern", test_frame_quic_memory_access_pattern),
    FUZI_Q_ITEM("quic_power_analysis_resistant", test_frame_quic_power_analysis_resistant),
    
    /* Implementation-Specific Edge Cases */
    FUZI_Q_ITEM("quic_buffer_boundary_edge", test_frame_quic_buffer_boundary_edge),
    FUZI_Q_ITEM("quic_alignment_requirement_violation", test_frame_quic_alignment_requirement_violation),
    FUZI_Q_ITEM("quic_endianness_confusion", test_frame_quic_endianness_confusion),
    FUZI_Q_ITEM("quic_stack_overflow_trigger", test_frame_quic_stack_overflow_trigger),
    FUZI_Q_ITEM("quic_heap_overflow_trigger", test_frame_quic_heap_overflow_trigger),
    
    /* === ADDITIONAL ADVANCED ATTACK VECTORS FUZI_Q_ITEM ENTRIES === */
    
    /* HTTP/2 Specific Violations */
    FUZI_Q_ITEM("h2_headers_invalid_padding", test_frame_h2_headers_invalid_padding),
    FUZI_Q_ITEM("h2_data_invalid_padding_len", test_frame_h2_data_invalid_padding_len),
    FUZI_Q_ITEM("h2_priority_self_dependency", test_frame_h2_priority_self_dependency),
    FUZI_Q_ITEM("h2_window_update_zero_increment", test_frame_h2_window_update_zero_increment),
    FUZI_Q_ITEM("h2_settings_ack_with_payload", test_frame_h2_settings_ack_with_payload),
    FUZI_Q_ITEM("h2_goaway_invalid_last_stream", test_frame_h2_goaway_invalid_last_stream),
    FUZI_Q_ITEM("h2_rst_stream_invalid_error", test_frame_h2_rst_stream_invalid_error),
    FUZI_Q_ITEM("h2_push_promise_invalid_id", test_frame_h2_push_promise_invalid_id),
    FUZI_Q_ITEM("h2_continuation_without_headers", test_frame_h2_continuation_without_headers),
    FUZI_Q_ITEM("h2_reserved_flags_set", test_frame_h2_reserved_flags_set),
    
    /* QPACK Specific Attacks */
    FUZI_Q_ITEM("qpack_encoder_invalid_instruction", test_frame_qpack_encoder_invalid_instruction),
    FUZI_Q_ITEM("qpack_decoder_malformed_ack", test_frame_qpack_decoder_malformed_ack),
    FUZI_Q_ITEM("qpack_table_size_overflow", test_frame_qpack_table_size_overflow),
    FUZI_Q_ITEM("qpack_invalid_name_index", test_frame_qpack_invalid_name_index),
    FUZI_Q_ITEM("qpack_duplicate_invalid_index", test_frame_qpack_duplicate_invalid_index),
    FUZI_Q_ITEM("qpack_circular_reference", test_frame_qpack_circular_reference),
    FUZI_Q_ITEM("qpack_cancellation_out_of_order", test_frame_qpack_cancellation_out_of_order),
    FUZI_Q_ITEM("qpack_insert_count_overflow", test_frame_qpack_insert_count_overflow),
    
    /* Multi-Protocol Confusion Attacks */
    FUZI_Q_ITEM("tls_alert_in_crypto", test_frame_tls_alert_in_crypto),
    FUZI_Q_ITEM("http1_in_quic_stream", test_frame_http1_in_quic_stream),
    FUZI_Q_ITEM("smtp_in_quic_stream", test_frame_smtp_in_quic_stream),
    FUZI_Q_ITEM("dns_in_datagram", test_frame_dns_in_datagram),
    FUZI_Q_ITEM("ftp_in_stream", test_frame_ftp_in_stream),
    FUZI_Q_ITEM("rtsp_in_stream", test_frame_rtsp_in_stream),
    FUZI_Q_ITEM("sip_in_stream", test_frame_sip_in_stream),
    
    /* Advanced WebSocket Edge Cases */
    FUZI_Q_ITEM("ws_invalid_payload_len_encoding", test_frame_ws_invalid_payload_len_encoding),
    FUZI_Q_ITEM("ws_ping_oversized", test_frame_ws_ping_oversized),
    FUZI_Q_ITEM("ws_close_truncated_reason", test_frame_ws_close_truncated_reason),
    FUZI_Q_ITEM("ws_mask_key_all_zeros", test_frame_ws_mask_key_all_zeros),
    FUZI_Q_ITEM("ws_predictable_mask", test_frame_ws_predictable_mask),
    FUZI_Q_ITEM("ws_binary_text_content", test_frame_ws_binary_text_content),
    FUZI_Q_ITEM("ws_text_binary_content", test_frame_ws_text_binary_content),
    
    /* Packet Fragmentation and Reassembly Attacks */
    FUZI_Q_ITEM("stream_overlapping_ranges", test_frame_stream_overlapping_ranges),
    FUZI_Q_ITEM("crypto_gap_in_sequence", test_frame_crypto_gap_in_sequence),
    FUZI_Q_ITEM("stream_data_beyond_final", test_frame_stream_data_beyond_final),
    FUZI_Q_ITEM("stream_duplicate_offset", test_frame_stream_duplicate_offset),
    FUZI_Q_ITEM("stream_zero_len_nonzero_offset", test_frame_stream_zero_len_nonzero_offset),
    
    /* Version Negotiation Attacks */
    FUZI_Q_ITEM("version_negotiation_invalid", test_frame_version_negotiation_invalid),
    FUZI_Q_ITEM("retry_invalid_version", test_frame_retry_invalid_version),
    FUZI_Q_ITEM("version_downgrade", test_frame_version_downgrade),
    FUZI_Q_ITEM("version_duplicates", test_frame_version_duplicates),
    
    /* Transport Parameter Manipulation */
    FUZI_Q_ITEM("invalid_transport_param", test_frame_invalid_transport_param),
    FUZI_Q_ITEM("transport_param_invalid_len", test_frame_transport_param_invalid_len),
    FUZI_Q_ITEM("duplicate_transport_param", test_frame_duplicate_transport_param),
    FUZI_Q_ITEM("reserved_transport_param", test_frame_reserved_transport_param),
    
    /* Key Update Attacks */
    FUZI_Q_ITEM("premature_key_update", test_frame_premature_key_update),
    FUZI_Q_ITEM("excessive_key_updates", test_frame_excessive_key_updates),
    FUZI_Q_ITEM("key_update_old_key", test_frame_key_update_old_key),
    FUZI_Q_ITEM("key_update_rollback", test_frame_key_update_rollback),
    
    /* Connection ID Rotation Attacks */
    FUZI_Q_ITEM("cid_predictable_sequence", test_frame_cid_predictable_sequence),
    FUZI_Q_ITEM("cid_rotation_dos", test_frame_cid_rotation_dos),
    FUZI_Q_ITEM("retire_cid_flood", test_frame_retire_cid_flood),
    FUZI_Q_ITEM("cid_collision_attack", test_frame_cid_collision_attack),
    
    /* Token Validation Attacks */
    FUZI_Q_ITEM("token_expired", test_frame_token_expired),
    FUZI_Q_ITEM("token_invalid_signature", test_frame_token_invalid_signature),
    FUZI_Q_ITEM("token_replay", test_frame_token_replay),
    FUZI_Q_ITEM("token_malformed_structure", test_frame_token_malformed_structure),
    
    /* Congestion Control Attacks */
    FUZI_Q_ITEM("ack_manipulated_ecn", test_frame_ack_manipulated_ecn),
    FUZI_Q_ITEM("false_congestion_signal", test_frame_false_congestion_signal),
    FUZI_Q_ITEM("cwnd_probing_attack", test_frame_cwnd_probing_attack),
    FUZI_Q_ITEM("loss_detection_manipulation", test_frame_loss_detection_manipulation),
    
    /* Advanced Timing Attacks */
    FUZI_Q_ITEM("ack_delay_timing_inference", test_frame_ack_delay_timing_inference),
    FUZI_Q_ITEM("ping_timing_correlation", test_frame_ping_timing_correlation),
    FUZI_Q_ITEM("path_challenge_timing_sidechannel", test_frame_path_challenge_timing_sidechannel),
    FUZI_Q_ITEM("connection_close_timing", test_frame_connection_close_timing),
    
    /* Memory Layout Attacks */
    FUZI_Q_ITEM("memory_alignment_attack", test_frame_memory_alignment_attack),
    FUZI_Q_ITEM("pointer_like_values", test_frame_pointer_like_values),
    FUZI_Q_ITEM("memory_region_targeting", test_frame_memory_region_targeting),
    FUZI_Q_ITEM("return_address_pattern", test_frame_return_address_pattern),
    
    /* === SPECIALIZED ATTACK VECTORS FUZI_Q_ITEM ENTRIES === */
    
    /* DNS over QUIC (DoQ) Attacks */
    FUZI_Q_ITEM("doq_malformed_query", test_frame_doq_malformed_query),
    FUZI_Q_ITEM("doq_amplification_attack", test_frame_doq_amplification_attack),
    FUZI_Q_ITEM("doq_cache_poisoning", test_frame_doq_cache_poisoning),
    
    /* WebTransport Attacks */
    FUZI_Q_ITEM("webtransport_invalid_session", test_frame_webtransport_invalid_session),
    FUZI_Q_ITEM("webtransport_stream_hijack", test_frame_webtransport_stream_hijack),
    FUZI_Q_ITEM("webtransport_capsule_bomb", test_frame_webtransport_capsule_bomb),
    
    /* MASQUE Proxy Attacks */
    FUZI_Q_ITEM("masque_connect_udp_spoof", test_frame_masque_connect_udp_spoof),
    FUZI_Q_ITEM("masque_ip_spoofing", test_frame_masque_ip_spoofing),
    FUZI_Q_ITEM("masque_proxy_loop", test_frame_masque_proxy_loop),
    
    /* ECN Marking Attacks */
    FUZI_Q_ITEM("ecn_bleaching_attack", test_frame_ecn_bleaching_attack),
    FUZI_Q_ITEM("ecn_remarking_attack", test_frame_ecn_remarking_attack),
    FUZI_Q_ITEM("ecn_reflection_attack", test_frame_ecn_reflection_attack),
    
    /* Multipath QUIC Attacks */
    FUZI_Q_ITEM("mp_quic_path_scheduling_attack", test_frame_mp_quic_path_scheduling_attack),
    FUZI_Q_ITEM("mp_quic_reinjection_attack", test_frame_mp_quic_reinjection_attack),
    FUZI_Q_ITEM("mp_quic_path_confusion", test_frame_mp_quic_path_confusion),
    
    /* Session Resumption Attacks */
    FUZI_Q_ITEM("session_ticket_forge", test_frame_session_ticket_forge),
    FUZI_Q_ITEM("psk_confusion_attack", test_frame_psk_confusion_attack),
    FUZI_Q_ITEM("resumption_replay", test_frame_resumption_replay),
    
    /* Post-Quantum Crypto Attacks */
    FUZI_Q_ITEM("pqc_hybrid_downgrade", test_frame_pqc_hybrid_downgrade),
    FUZI_Q_ITEM("pqc_kyber_malleability", test_frame_pqc_kyber_malleability),
    FUZI_Q_ITEM("pqc_dilithium_forge", test_frame_pqc_dilithium_forge),
    
    /* Anti-Forensics Techniques */
    FUZI_Q_ITEM("forensics_metadata_scrub", test_frame_forensics_metadata_scrub),
    FUZI_Q_ITEM("forensics_traffic_shaping", test_frame_forensics_traffic_shaping),
    FUZI_Q_ITEM("forensics_flow_correlation", test_frame_forensics_flow_correlation),
    
    /* Hardware-Specific Attacks */
    FUZI_Q_ITEM("cpu_cache_eviction", test_frame_cpu_cache_eviction),
    FUZI_Q_ITEM("branch_predictor_poison", test_frame_branch_predictor_poison),
    FUZI_Q_ITEM("speculative_execution", test_frame_speculative_execution),
    
    /* ML Evasion Techniques */
    FUZI_Q_ITEM("ml_adversarial_padding", test_frame_ml_adversarial_padding),
    FUZI_Q_ITEM("ml_feature_poisoning", test_frame_ml_feature_poisoning),
    FUZI_Q_ITEM("ml_model_inversion", test_frame_ml_model_inversion),
    
    /* === MAXIMUM COVERAGE ATTACK VECTORS FUZI_Q_ITEM ENTRIES === */
    
    /* Binary Exploitation Patterns */
    FUZI_Q_ITEM("format_string_attack", test_frame_format_string_attack),
    FUZI_Q_ITEM("integer_wraparound", test_frame_integer_wraparound),
    FUZI_Q_ITEM("off_by_one_trigger", test_frame_off_by_one_trigger),
    FUZI_Q_ITEM("use_after_free_pattern", test_frame_use_after_free_pattern),
    FUZI_Q_ITEM("double_free_trigger", test_frame_double_free_trigger),
    
    /* SQL Injection Patterns */
    FUZI_Q_ITEM("sql_injection_basic", test_frame_sql_injection_basic),
    FUZI_Q_ITEM("sql_union_attack", test_frame_sql_union_attack),
    FUZI_Q_ITEM("sql_blind_injection", test_frame_sql_blind_injection),
    
    /* XSS Payloads */
    FUZI_Q_ITEM("xss_script_tag", test_frame_xss_script_tag),
    FUZI_Q_ITEM("xss_img_onerror", test_frame_xss_img_onerror),
    
    /* Command Injection */
    FUZI_Q_ITEM("cmd_injection_pipe", test_frame_cmd_injection_pipe),
    FUZI_Q_ITEM("cmd_injection_backtick", test_frame_cmd_injection_backtick),
    
    /* Path Traversal */
    FUZI_Q_ITEM("path_traversal_basic", test_frame_path_traversal_basic),
    FUZI_Q_ITEM("path_traversal_encoded", test_frame_path_traversal_encoded),
    
    /* LDAP Injection */
    FUZI_Q_ITEM("ldap_injection", test_frame_ldap_injection),
    
    /* SSRF Attacks */
    FUZI_Q_ITEM("ssrf_localhost", test_frame_ssrf_localhost),
    FUZI_Q_ITEM("ssrf_metadata", test_frame_ssrf_metadata),
    
    /* Crypto Oracle Attacks */
    FUZI_Q_ITEM("padding_oracle_attack", test_frame_padding_oracle_attack),
    FUZI_Q_ITEM("timing_oracle_crypto", test_frame_timing_oracle_crypto),
    
    /* IoT Attacks */
    FUZI_Q_ITEM("iot_coap_attack", test_frame_iot_coap_attack),
    FUZI_Q_ITEM("iot_mqtt_hijack", test_frame_iot_mqtt_hijack),
    
    /* Container Escape */
    FUZI_Q_ITEM("docker_escape", test_frame_docker_escape),
    FUZI_Q_ITEM("k8s_privilege_escalation", test_frame_k8s_privilege_escalation),
    
    /* === EXTENDED MAXIMUM COVERAGE ATTACK VECTORS FUZI_Q_ITEM ENTRIES === */
    
    /* NoSQL Injection Patterns */
    FUZI_Q_ITEM("nosql_mongodb_injection", test_frame_nosql_mongodb_injection),
    FUZI_Q_ITEM("nosql_couchdb_injection", test_frame_nosql_couchdb_injection),
    FUZI_Q_ITEM("nosql_redis_injection", test_frame_nosql_redis_injection),
    
    /* Template Injection Attacks */
    FUZI_Q_ITEM("template_jinja2_injection", test_frame_template_jinja2_injection),
    FUZI_Q_ITEM("template_twig_injection", test_frame_template_twig_injection),
    FUZI_Q_ITEM("template_freemarker_injection", test_frame_template_freemarker_injection),
    
    /* Race Condition Triggers */
    FUZI_Q_ITEM("race_condition_toctou", test_frame_race_condition_toctou),
    FUZI_Q_ITEM("race_condition_double_fetch", test_frame_race_condition_double_fetch),
    FUZI_Q_ITEM("race_condition_atomic_violation", test_frame_race_condition_atomic_violation),
    
    /* Deserialization Attacks (Extended) */
    FUZI_Q_ITEM("deserial_java_commons", test_frame_deserial_java_commons),
    FUZI_Q_ITEM("deserial_python_pickle", test_frame_deserial_python_pickle),
    FUZI_Q_ITEM("deserial_php_unserialize", test_frame_deserial_php_unserialize),
    FUZI_Q_ITEM("deserial_dotnet_binaryformatter", test_frame_deserial_dotnet_binaryformatter),
    
    /* Blockchain/DeFi Attacks (Extended) */
    FUZI_Q_ITEM("blockchain_reentrancy", test_frame_blockchain_reentrancy),
    FUZI_Q_ITEM("blockchain_flashloan", test_frame_blockchain_flashloan),
    FUZI_Q_ITEM("blockchain_mev_sandwich", test_frame_blockchain_mev_sandwich),
    FUZI_Q_ITEM("blockchain_oracle_manipulation", test_frame_blockchain_oracle_manipulation),
    
    /* AI/ML Model Attacks (Extended) */
    FUZI_Q_ITEM("ai_model_extraction", test_frame_ai_model_extraction),
    FUZI_Q_ITEM("ai_membership_inference", test_frame_ai_membership_inference),
    FUZI_Q_ITEM("ai_backdoor_trigger", test_frame_ai_backdoor_trigger),
    FUZI_Q_ITEM("ai_prompt_injection", test_frame_ai_prompt_injection),
    
    /* Supply Chain Attacks (Extended) */
    FUZI_Q_ITEM("supply_dependency_confusion", test_frame_supply_dependency_confusion),
    FUZI_Q_ITEM("supply_typosquatting", test_frame_supply_typosquatting),
    FUZI_Q_ITEM("supply_malicious_package", test_frame_supply_malicious_package),
    FUZI_Q_ITEM("supply_compromised_repo", test_frame_supply_compromised_repo),
    
    /* 5G/Edge Computing Attacks (Extended) */
    FUZI_Q_ITEM("5g_slice_isolation_bypass", test_frame_5g_slice_isolation_bypass),
    FUZI_Q_ITEM("5g_compute_escape", test_frame_5g_compute_escape),
    FUZI_Q_ITEM("5g_network_slicing_attack", test_frame_5g_network_slicing_attack),
    FUZI_Q_ITEM("edge_function_escape", test_frame_edge_function_escape),
    
    /* Advanced Binary Exploitation */
    FUZI_Q_ITEM("binary_rop_chain", test_frame_binary_rop_chain),
    FUZI_Q_ITEM("binary_jop_chain", test_frame_binary_jop_chain),
    FUZI_Q_ITEM("binary_stack_pivot", test_frame_binary_stack_pivot),
    FUZI_Q_ITEM("binary_heap_spray", test_frame_binary_heap_spray),
    
    /* Advanced Container/Orchestration Attacks */
    FUZI_Q_ITEM("container_runtime_escape", test_frame_container_runtime_escape),
    FUZI_Q_ITEM("k8s_rbac_bypass", test_frame_k8s_rbac_bypass),
    FUZI_Q_ITEM("k8s_admission_bypass", test_frame_k8s_admission_bypass),
    FUZI_Q_ITEM("k8s_pod_escape", test_frame_k8s_pod_escape),
    
    /* Advanced Firmware/Hardware Attacks */
    FUZI_Q_ITEM("firmware_dump_attack", test_frame_firmware_dump_attack),
    FUZI_Q_ITEM("uefi_bootkit", test_frame_uefi_bootkit),
    FUZI_Q_ITEM("smc_vulnerability", test_frame_smc_vulnerability),
    FUZI_Q_ITEM("tpm_bypass", test_frame_tpm_bypass),
    
    /* Cloud Native Security Attacks */
    FUZI_Q_ITEM("serverless_cold_start", test_frame_serverless_cold_start),
    FUZI_Q_ITEM("serverless_injection", test_frame_serverless_injection),
    FUZI_Q_ITEM("api_gateway_bypass", test_frame_api_gateway_bypass),
    FUZI_Q_ITEM("service_mesh_attack", test_frame_service_mesh_attack),
    
    /* === ULTRA ADVANCED ATTACK VECTORS FUZI_Q_ITEM ENTRIES === */
    
    /* Advanced Cryptographic Attacks */
    FUZI_Q_ITEM("lattice_attack", test_frame_lattice_attack),
    FUZI_Q_ITEM("bleichenbacher_attack", test_frame_bleichenbacher_attack),
    FUZI_Q_ITEM("invalid_curve_attack", test_frame_invalid_curve_attack),
    FUZI_Q_ITEM("twist_attack", test_frame_twist_attack),
    FUZI_Q_ITEM("fault_injection", test_frame_fault_injection),
    
    /* Zero-Day Exploitation Patterns */
    FUZI_Q_ITEM("cve_2024_pattern", test_frame_cve_2024_pattern),
    FUZI_Q_ITEM("nday_exploitation", test_frame_nday_exploitation),
    FUZI_Q_ITEM("vulnerability_chaining", test_frame_vulnerability_chaining),
    FUZI_Q_ITEM("exploit_mitigation_bypass", test_frame_exploit_mitigation_bypass),
    
    /* Advanced Network Attacks */
    FUZI_Q_ITEM("bgp_hijacking", test_frame_bgp_hijacking),
    FUZI_Q_ITEM("dns_cache_poisoning", test_frame_dns_cache_poisoning),
    FUZI_Q_ITEM("arp_spoofing", test_frame_arp_spoofing),
    FUZI_Q_ITEM("dhcp_starvation", test_frame_dhcp_starvation),
    FUZI_Q_ITEM("icmp_redirect", test_frame_icmp_redirect),
    
    /* Database-Specific Attacks */
    FUZI_Q_ITEM("oracle_injection", test_frame_oracle_injection),
    FUZI_Q_ITEM("mssql_injection", test_frame_mssql_injection),
    FUZI_Q_ITEM("postgresql_injection", test_frame_postgresql_injection),
    FUZI_Q_ITEM("elasticsearch_injection", test_frame_elasticsearch_injection),
    FUZI_Q_ITEM("cassandra_injection", test_frame_cassandra_injection),
    
    /* Advanced Web Application Attacks */
    FUZI_Q_ITEM("xxe_attack", test_frame_xxe_attack),
    FUZI_Q_ITEM("csrf_attack", test_frame_csrf_attack),
    FUZI_Q_ITEM("clickjacking", test_frame_clickjacking),
    FUZI_Q_ITEM("dom_clobbering", test_frame_dom_clobbering),
    FUZI_Q_ITEM("prototype_pollution", test_frame_prototype_pollution),
    
    /* Mobile Security Attacks */
    FUZI_Q_ITEM("android_intent_hijack", test_frame_android_intent_hijack),
    FUZI_Q_ITEM("ios_url_scheme", test_frame_ios_url_scheme),
    FUZI_Q_ITEM("mobile_ssl_pinning_bypass", test_frame_mobile_ssl_pinning_bypass),
    FUZI_Q_ITEM("mobile_root_detection_bypass", test_frame_mobile_root_detection_bypass),
    
    /* Industrial Control System Attacks */
    FUZI_Q_ITEM("modbus_attack", test_frame_modbus_attack),
    FUZI_Q_ITEM("scada_attack", test_frame_scada_attack),
    FUZI_Q_ITEM("dnp3_attack", test_frame_dnp3_attack),
    FUZI_Q_ITEM("iec104_attack", test_frame_iec104_attack),
    
    /* Advanced Memory Corruption */
    FUZI_Q_ITEM("vtable_hijacking", test_frame_vtable_hijacking),
    FUZI_Q_ITEM("coop_attack", test_frame_coop_attack),
    FUZI_Q_ITEM("brop_attack", test_frame_brop_attack),
    FUZI_Q_ITEM("type_confusion", test_frame_type_confusion),
    
    /* Advanced Persistence Techniques */
    FUZI_Q_ITEM("dll_hijacking", test_frame_dll_hijacking),
    FUZI_Q_ITEM("com_hijacking", test_frame_com_hijacking),
    FUZI_Q_ITEM("registry_persistence", test_frame_registry_persistence),
    FUZI_Q_ITEM("scheduled_task_abuse", test_frame_scheduled_task_abuse),
    
    /* Advanced Evasion Techniques */
    FUZI_Q_ITEM("sandbox_evasion", test_frame_sandbox_evasion),
    FUZI_Q_ITEM("av_evasion", test_frame_av_evasion),
    FUZI_Q_ITEM("edr_evasion", test_frame_edr_evasion),
    FUZI_Q_ITEM("behavioral_evasion", test_frame_behavioral_evasion),
    
    /* Quantum Computing Attacks */
    FUZI_Q_ITEM("shor_algorithm", test_frame_shor_algorithm),
    FUZI_Q_ITEM("grover_algorithm", test_frame_grover_algorithm),
    FUZI_Q_ITEM("quantum_key_recovery", test_frame_quantum_key_recovery),
    FUZI_Q_ITEM("post_quantum_downgrade", test_frame_post_quantum_downgrade),
    
    /* === APEX TIER ATTACK VECTORS FUZI_Q_ITEM ENTRIES === */
    
    /* Nation-State APT Techniques */
    FUZI_Q_ITEM("apt_living_off_land", test_frame_apt_living_off_land),
    FUZI_Q_ITEM("apt_supply_chain", test_frame_apt_supply_chain),
    FUZI_Q_ITEM("apt_zero_click", test_frame_apt_zero_click),
    FUZI_Q_ITEM("apt_watering_hole", test_frame_apt_watering_hole),
    
    /* Advanced Ransomware Techniques */
    FUZI_Q_ITEM("ransomware_double_extortion", test_frame_ransomware_double_extortion),
    FUZI_Q_ITEM("ransomware_triple_extortion", test_frame_ransomware_triple_extortion),
    FUZI_Q_ITEM("ransomware_as_a_service", test_frame_ransomware_as_a_service),
    FUZI_Q_ITEM("ransomware_vm_escape", test_frame_ransomware_vm_escape),
    
    /* AI-Powered Cyber Attacks */
    FUZI_Q_ITEM("ai_deepfake_voice", test_frame_ai_deepfake_voice),
    FUZI_Q_ITEM("ai_deepfake_video", test_frame_ai_deepfake_video),
    FUZI_Q_ITEM("ai_automated_spearphish", test_frame_ai_automated_spearphish),
    FUZI_Q_ITEM("ai_vulnerability_discovery", test_frame_ai_vulnerability_discovery),
    
    /* Advanced Satellite/Space Attacks */
    FUZI_Q_ITEM("satellite_jamming", test_frame_satellite_jamming),
    FUZI_Q_ITEM("satellite_spoofing", test_frame_satellite_spoofing),
    FUZI_Q_ITEM("gps_spoofing", test_frame_gps_spoofing),
    FUZI_Q_ITEM("starlink_attack", test_frame_starlink_attack),
    
    /* Biometric Security Attacks */
    FUZI_Q_ITEM("fingerprint_spoofing", test_frame_fingerprint_spoofing),
    FUZI_Q_ITEM("face_recognition_bypass", test_frame_face_recognition_bypass),
    FUZI_Q_ITEM("iris_scan_bypass", test_frame_iris_scan_bypass),
    FUZI_Q_ITEM("voice_recognition_bypass", test_frame_voice_recognition_bypass),
    
    /* Advanced Social Engineering */
    FUZI_Q_ITEM("vishing_attack", test_frame_vishing_attack),
    FUZI_Q_ITEM("smishing_attack", test_frame_smishing_attack),
    FUZI_Q_ITEM("pretexting_attack", test_frame_pretexting_attack),
    FUZI_Q_ITEM("business_email_compromise", test_frame_business_email_compromise),
    
    /* Critical Infrastructure Attacks */
    FUZI_Q_ITEM("power_grid_attack", test_frame_power_grid_attack),
    FUZI_Q_ITEM("water_system_attack", test_frame_water_system_attack),
    FUZI_Q_ITEM("transportation_attack", test_frame_transportation_attack),
    FUZI_Q_ITEM("healthcare_attack", test_frame_healthcare_attack),
    
    /* Emerging Technology Attacks */
    FUZI_Q_ITEM("metaverse_attack", test_frame_metaverse_attack),
    FUZI_Q_ITEM("nft_smart_contract_exploit", test_frame_nft_smart_contract_exploit),
    FUZI_Q_ITEM("autonomous_vehicle_hack", test_frame_autonomous_vehicle_hack),
    FUZI_Q_ITEM("drone_hijacking", test_frame_drone_hijacking),
    
    /* Advanced Steganography */
    FUZI_Q_ITEM("image_steganography", test_frame_image_steganography),
    FUZI_Q_ITEM("audio_steganography", test_frame_audio_steganography),
    FUZI_Q_ITEM("video_steganography", test_frame_video_steganography),
    FUZI_Q_ITEM("network_steganography", test_frame_network_steganography),
    
    /* === NEXT-GENERATION ATTACK VECTORS FUZI_Q_ITEM ENTRIES === */
    
    /* Advanced IoT Ecosystem Attacks */
    FUZI_Q_ITEM("iot_mesh_takeover", test_frame_iot_mesh_takeover),
    FUZI_Q_ITEM("iot_swarm_botnet", test_frame_iot_swarm_botnet),
    FUZI_Q_ITEM("iot_sensor_spoofing", test_frame_iot_sensor_spoofing),
    FUZI_Q_ITEM("iot_firmware_backdoor", test_frame_iot_firmware_backdoor),
    
    /* Advanced Cloud-Native Attacks */
    FUZI_Q_ITEM("multicloud_pivot", test_frame_multicloud_pivot),
    FUZI_Q_ITEM("cloud_workload_injection", test_frame_cloud_workload_injection),
    FUZI_Q_ITEM("iac_poisoning", test_frame_iac_poisoning),
    FUZI_Q_ITEM("cloud_metadata_abuse", test_frame_cloud_metadata_abuse),
    
    /* Financial Technology Attacks */
    FUZI_Q_ITEM("cbdc_attack", test_frame_cbdc_attack),
    FUZI_Q_ITEM("defi_liquidation", test_frame_defi_liquidation),
    FUZI_Q_ITEM("payment_rail_hijack", test_frame_payment_rail_hijack),
    FUZI_Q_ITEM("regulatory_arbitrage", test_frame_regulatory_arbitrage),
    
    /* Advanced Automotive Attacks */
    FUZI_Q_ITEM("v2x_manipulation", test_frame_v2x_manipulation),
    FUZI_Q_ITEM("can_bus_injection", test_frame_can_bus_injection),
    FUZI_Q_ITEM("adas_sensor_attack", test_frame_adas_sensor_attack),
    FUZI_Q_ITEM("vehicle_swarm_attack", test_frame_vehicle_swarm_attack),
    
    /* Medical Device Security Attacks */
    FUZI_Q_ITEM("pacemaker_attack", test_frame_pacemaker_attack),
    FUZI_Q_ITEM("insulin_pump_hijack", test_frame_insulin_pump_hijack),
    FUZI_Q_ITEM("mri_manipulation", test_frame_mri_manipulation),
    FUZI_Q_ITEM("surgical_robot_hack", test_frame_surgical_robot_hack),
    
    /* Gaming and Virtual World Attacks */
    FUZI_Q_ITEM("game_engine_exploit", test_frame_game_engine_exploit),
    FUZI_Q_ITEM("virtual_economy_manipulation", test_frame_virtual_economy_manipulation),
    FUZI_Q_ITEM("esports_match_fixing", test_frame_esports_match_fixing),
    FUZI_Q_ITEM("nft_gaming_exploit", test_frame_nft_gaming_exploit),
    
    /* Augmented/Virtual Reality Attacks */
    FUZI_Q_ITEM("ar_overlay_hijack", test_frame_ar_overlay_hijack),
    FUZI_Q_ITEM("vr_presence_hijack", test_frame_vr_presence_hijack),
    FUZI_Q_ITEM("haptic_feedback_attack", test_frame_haptic_feedback_attack),
    FUZI_Q_ITEM("mixed_reality_confusion", test_frame_mixed_reality_confusion),
    
    /* Advanced Quantum Technology Attacks */
    FUZI_Q_ITEM("quantum_entanglement_break", test_frame_quantum_entanglement_break),
    FUZI_Q_ITEM("quantum_teleportation_hijack", test_frame_quantum_teleportation_hijack),
    FUZI_Q_ITEM("quantum_supremacy_abuse", test_frame_quantum_supremacy_abuse),
    FUZI_Q_ITEM("quantum_error_injection", test_frame_quantum_error_injection),
    
    /* Space Technology Warfare */
    FUZI_Q_ITEM("orbital_debris_weaponization", test_frame_orbital_debris_weaponization),
    FUZI_Q_ITEM("space_elevator_sabotage", test_frame_space_elevator_sabotage),
    FUZI_Q_ITEM("mars_colony_attack", test_frame_mars_colony_attack),
    FUZI_Q_ITEM("asteroid_mining_hijack", test_frame_asteroid_mining_hijack),
    
    /* Biotechnology Attacks */
    FUZI_Q_ITEM("dna_sequencing_attack", test_frame_dna_sequencing_attack),
    FUZI_Q_ITEM("crispr_hijack", test_frame_crispr_hijack),
    FUZI_Q_ITEM("synthetic_biology_weapon", test_frame_synthetic_biology_weapon),
    FUZI_Q_ITEM("biometric_dna_forge", test_frame_biometric_dna_forge),
    
    /* Nanotechnology Attacks */
    FUZI_Q_ITEM("nanobot_swarm_attack", test_frame_nanobot_swarm_attack),
    FUZI_Q_ITEM("molecular_assembly_hijack", test_frame_molecular_assembly_hijack),
    FUZI_Q_ITEM("nano_scale_espionage", test_frame_nano_scale_espionage),
    FUZI_Q_ITEM("quantum_dot_manipulation", test_frame_quantum_dot_manipulation),
    
    /* Neurotechnology Attacks */
    FUZI_Q_ITEM("brain_computer_hijack", test_frame_brain_computer_hijack),
    FUZI_Q_ITEM("neural_implant_attack", test_frame_neural_implant_attack),
    FUZI_Q_ITEM("memory_manipulation", test_frame_memory_manipulation),
    FUZI_Q_ITEM("thought_pattern_hijack", test_frame_thought_pattern_hijack),
    
    /* Advanced Robotics Attacks */
    FUZI_Q_ITEM("robot_swarm_coordination", test_frame_robot_swarm_coordination),
    FUZI_Q_ITEM("humanoid_impersonation", test_frame_humanoid_impersonation),
    FUZI_Q_ITEM("industrial_robot_weaponization", test_frame_industrial_robot_weaponization),
    FUZI_Q_ITEM("ai_ethics_bypass", test_frame_ai_ethics_bypass),
    
    /* === RFC-SPECIFIC ATTACK VECTORS FUZI_Q_ITEM ENTRIES === */
    
    /* RFC 8999 - Version-Independent Properties of QUIC */
    FUZI_Q_ITEM("rfc8999_version_independent_violation", test_frame_rfc8999_version_independent_violation),
    FUZI_Q_ITEM("rfc8999_fixed_bit_clear", test_frame_rfc8999_fixed_bit_clear),
    FUZI_Q_ITEM("rfc8999_connection_id_length_violation", test_frame_rfc8999_connection_id_length_violation),
    
    /* RFC 9000 - QUIC Core Transport */
    FUZI_Q_ITEM("rfc9000_packet_number_encoding_error", test_frame_rfc9000_packet_number_encoding_error),
    FUZI_Q_ITEM("rfc9000_varint_overflow", test_frame_rfc9000_varint_overflow),
    FUZI_Q_ITEM("rfc9000_frame_type_reserved", test_frame_rfc9000_frame_type_reserved),
    FUZI_Q_ITEM("rfc9000_transport_param_duplicate", test_frame_rfc9000_transport_param_duplicate),
    FUZI_Q_ITEM("rfc9000_connection_migration_violation", test_frame_rfc9000_connection_migration_violation),
    
    /* RFC 9001 - QUIC TLS Integration */
    FUZI_Q_ITEM("rfc9001_tls_handshake_tampering", test_frame_rfc9001_tls_handshake_tampering),
    FUZI_Q_ITEM("rfc9001_key_update_premature", test_frame_rfc9001_key_update_premature),
    FUZI_Q_ITEM("rfc9001_crypto_frame_ordering", test_frame_rfc9001_crypto_frame_ordering),
    FUZI_Q_ITEM("rfc9001_protected_packet_manipulation", test_frame_rfc9001_protected_packet_manipulation),
    
    /* RFC 9002 - Loss Detection and Congestion Control */
    FUZI_Q_ITEM("rfc9002_ack_delay_manipulation", test_frame_rfc9002_ack_delay_manipulation),
    FUZI_Q_ITEM("rfc9002_rtt_manipulation", test_frame_rfc9002_rtt_manipulation),
    FUZI_Q_ITEM("rfc9002_congestion_window_attack", test_frame_rfc9002_congestion_window_attack),
    FUZI_Q_ITEM("rfc9002_loss_detection_bypass", test_frame_rfc9002_loss_detection_bypass),
    
    /* RFC 9221 - Unreliable Datagram Extension */
    FUZI_Q_ITEM("rfc9221_datagram_length_violation", test_frame_rfc9221_datagram_length_violation),
    FUZI_Q_ITEM("rfc9221_datagram_in_0rtt", test_frame_rfc9221_datagram_in_0rtt),
    FUZI_Q_ITEM("rfc9221_datagram_fragmentation", test_frame_rfc9221_datagram_fragmentation),
    
    /* RFC 9287 - Greasing the QUIC Bit */
    FUZI_Q_ITEM("rfc9287_grease_bit_violation", test_frame_rfc9287_grease_bit_violation),
    FUZI_Q_ITEM("rfc9287_reserved_bit_dependency", test_frame_rfc9287_reserved_bit_dependency),
    
    /* RFC 9368 - Compatible Version Negotiation */
    FUZI_Q_ITEM("rfc9368_version_negotiation_downgrade", test_frame_rfc9368_version_negotiation_downgrade),
    FUZI_Q_ITEM("rfc9368_compatible_version_confusion", test_frame_rfc9368_compatible_version_confusion),
    
    /* RFC 9369 - QUIC Version 2 */
    FUZI_Q_ITEM("rfc9369_v2_frame_type_confusion", test_frame_rfc9369_v2_frame_type_confusion),
    FUZI_Q_ITEM("rfc9369_v2_packet_protection_bypass", test_frame_rfc9369_v2_packet_protection_bypass),
    
    /* RFC 9114 - HTTP/3 */
    FUZI_Q_ITEM("rfc9114_h3_frame_length_overflow", test_frame_rfc9114_h3_frame_length_overflow),
    FUZI_Q_ITEM("rfc9114_h3_settings_duplicate", test_frame_rfc9114_h3_settings_duplicate),
    FUZI_Q_ITEM("rfc9114_h3_push_promise_violation", test_frame_rfc9114_h3_push_promise_violation),
    FUZI_Q_ITEM("rfc9114_h3_goaway_invalid_stream", test_frame_rfc9114_h3_goaway_invalid_stream),
    FUZI_Q_ITEM("rfc9114_h3_max_push_id_regression", test_frame_rfc9114_h3_max_push_id_regression),
    
    /* RFC 9204 - QPACK Field Compression */
    FUZI_Q_ITEM("rfc9204_qpack_encoder_stream_corruption", test_frame_rfc9204_qpack_encoder_stream_corruption),
    FUZI_Q_ITEM("rfc9204_qpack_decoder_stream_overflow", test_frame_rfc9204_qpack_decoder_stream_overflow),
    FUZI_Q_ITEM("rfc9204_qpack_dynamic_table_corruption", test_frame_rfc9204_qpack_dynamic_table_corruption),
    FUZI_Q_ITEM("rfc9204_qpack_header_block_dependency", test_frame_rfc9204_qpack_header_block_dependency),
    
    /* RFC 9220 - Bootstrapping WebSockets with HTTP/3 */
    FUZI_Q_ITEM("rfc9220_websocket_upgrade_injection", test_frame_rfc9220_websocket_upgrade_injection),
    FUZI_Q_ITEM("rfc9220_websocket_key_manipulation", test_frame_rfc9220_websocket_key_manipulation),
    FUZI_Q_ITEM("rfc9220_websocket_protocol_confusion", test_frame_rfc9220_websocket_protocol_confusion),
    
    /* RFC 9412 - ORIGIN Extension in HTTP/3 */
    FUZI_Q_ITEM("rfc9412_origin_frame_spoofing", test_frame_rfc9412_origin_frame_spoofing),
    FUZI_Q_ITEM("rfc9412_origin_authority_bypass", test_frame_rfc9412_origin_authority_bypass),
    
    /* RFC 9250 - DNS over QUIC (DoQ) */
    FUZI_Q_ITEM("rfc9250_doq_malformed_query", test_frame_rfc9250_doq_malformed_query),
    FUZI_Q_ITEM("rfc9250_doq_response_amplification", test_frame_rfc9250_doq_response_amplification),
    FUZI_Q_ITEM("rfc9250_doq_cache_poisoning", test_frame_rfc9250_doq_cache_poisoning),
    FUZI_Q_ITEM("rfc9250_doq_stream_reuse_violation", test_frame_rfc9250_doq_stream_reuse_violation),
    
    /* RFC 8484 - DNS over HTTPS (DoH) */
    FUZI_Q_ITEM("rfc8484_doh_get_parameter_injection", test_frame_rfc8484_doh_get_parameter_injection),
    FUZI_Q_ITEM("rfc8484_doh_post_content_type_bypass", test_frame_rfc8484_doh_post_content_type_bypass),
    
    /* RFC 8446 - TLS 1.3 Integration Issues */
    FUZI_Q_ITEM("rfc8446_tls13_early_data_replay", test_frame_rfc8446_tls13_early_data_replay),
    FUZI_Q_ITEM("rfc8446_tls13_certificate_transparency_bypass", test_frame_rfc8446_tls13_certificate_transparency_bypass),
    
    /* RFC 9110/9111/9112/9113 - HTTP Semantics Violations */
    FUZI_Q_ITEM("rfc9110_http_method_smuggling", test_frame_rfc9110_http_method_smuggling),
    FUZI_Q_ITEM("rfc9111_cache_poisoning_via_vary", test_frame_rfc9111_cache_poisoning_via_vary),
    FUZI_Q_ITEM("rfc9113_h2_frame_injection", test_frame_rfc9113_h2_frame_injection),
    
    /* RFC 7541 - HPACK vs QPACK Confusion */
    FUZI_Q_ITEM("rfc7541_hpack_in_qpack_context", test_frame_rfc7541_hpack_in_qpack_context),
    FUZI_Q_ITEM("rfc7541_hpack_huffman_bomb", test_frame_rfc7541_hpack_huffman_bomb),
    
    /* RFC 7838 - HTTP Alternative Services Abuse */
    FUZI_Q_ITEM("rfc7838_alt_svc_redirection_attack", test_frame_rfc7838_alt_svc_redirection_attack),
    FUZI_Q_ITEM("rfc7838_alt_svc_downgrade_attack", test_frame_rfc7838_alt_svc_downgrade_attack),
    
    /* RFC 9218 - Extensible Prioritization Scheme */
    FUZI_Q_ITEM("rfc9218_priority_update_overflow", test_frame_rfc9218_priority_update_overflow),
    FUZI_Q_ITEM("rfc9218_priority_dependency_loop", test_frame_rfc9218_priority_dependency_loop),
    
    /* RFC 9297 - HTTP Datagrams Integration Issues */
    FUZI_Q_ITEM("rfc9297_http_datagram_context_confusion", test_frame_rfc9297_http_datagram_context_confusion),
    FUZI_Q_ITEM("rfc9297_datagram_flow_id_collision", test_frame_rfc9297_datagram_flow_id_collision),
    
    /* === EXTENDED RFC-SPECIFIC ATTACK VECTORS FUZI_Q_ITEM ENTRIES === */
    
    /* RFC 2119/8174 - Requirement Level Violations */
    FUZI_Q_ITEM("rfc2119_must_violation", test_frame_rfc2119_must_violation),
    FUZI_Q_ITEM("rfc8174_should_not_ignore", test_frame_rfc8174_should_not_ignore),
    FUZI_Q_ITEM("rfc2119_may_abuse", test_frame_rfc2119_may_abuse),
    
    /* RFC 768 - UDP Integration Issues */
    FUZI_Q_ITEM("rfc768_udp_length_mismatch", test_frame_rfc768_udp_length_mismatch),
    FUZI_Q_ITEM("rfc768_udp_checksum_zero", test_frame_rfc768_udp_checksum_zero),
    FUZI_Q_ITEM("rfc768_udp_port_zero", test_frame_rfc768_udp_port_zero),
    
    /* RFC 6455 - WebSocket Protocol Deeper Violations */
    FUZI_Q_ITEM("rfc6455_ws_upgrade_downgrade", test_frame_rfc6455_ws_upgrade_downgrade),
    FUZI_Q_ITEM("rfc6455_ws_sec_key_collision", test_frame_rfc6455_ws_sec_key_collision),
    FUZI_Q_ITEM("rfc6455_ws_version_mismatch", test_frame_rfc6455_ws_version_mismatch),
    FUZI_Q_ITEM("rfc6455_ws_extension_hijack", test_frame_rfc6455_ws_extension_hijack),
    
    /* RFC 8441 - HTTP/2 over QUIC Violations */
    FUZI_Q_ITEM("rfc8441_h2_over_quic_settings", test_frame_rfc8441_h2_over_quic_settings),
    FUZI_Q_ITEM("rfc8441_h2_quic_stream_mapping", test_frame_rfc8441_h2_quic_stream_mapping),
    FUZI_Q_ITEM("rfc8441_extended_connect_abuse", test_frame_rfc8441_extended_connect_abuse),
    
    /* Advanced RFC 9000 Core Protocol Edge Cases */
    FUZI_Q_ITEM("rfc9000_initial_packet_corruption", test_frame_rfc9000_initial_packet_corruption),
    FUZI_Q_ITEM("rfc9000_handshake_packet_replay", test_frame_rfc9000_handshake_packet_replay),
    FUZI_Q_ITEM("rfc9000_application_data_leak", test_frame_rfc9000_application_data_leak),
    FUZI_Q_ITEM("rfc9000_stateless_reset_forge", test_frame_rfc9000_stateless_reset_forge),
    FUZI_Q_ITEM("rfc9000_retry_token_reuse", test_frame_rfc9000_retry_token_reuse),
    
    /* Advanced RFC 9001 TLS Integration Attacks */
    FUZI_Q_ITEM("rfc9001_tls_alert_injection", test_frame_rfc9001_tls_alert_injection),
    FUZI_Q_ITEM("rfc9001_early_data_confusion", test_frame_rfc9001_early_data_confusion),
    FUZI_Q_ITEM("rfc9001_certificate_verify_bypass", test_frame_rfc9001_certificate_verify_bypass),
    FUZI_Q_ITEM("rfc9001_finished_message_forge", test_frame_rfc9001_finished_message_forge),
    
    /* Advanced RFC 9002 Loss Detection Exploits */
    FUZI_Q_ITEM("rfc9002_probe_timeout_manipulation", test_frame_rfc9002_probe_timeout_manipulation),
    FUZI_Q_ITEM("rfc9002_persistent_congestion_force", test_frame_rfc9002_persistent_congestion_force),
    FUZI_Q_ITEM("rfc9002_bandwidth_estimation_poison", test_frame_rfc9002_bandwidth_estimation_poison),
    FUZI_Q_ITEM("rfc9002_loss_detection_evasion", test_frame_rfc9002_loss_detection_evasion),
    
    /* Advanced RFC 9114 HTTP/3 Frame Attacks */
    FUZI_Q_ITEM("rfc9114_h3_cancel_push_invalid", test_frame_rfc9114_h3_cancel_push_invalid),
    FUZI_Q_ITEM("rfc9114_h3_headers_after_trailers", test_frame_rfc9114_h3_headers_after_trailers),
    FUZI_Q_ITEM("rfc9114_h3_data_after_fin", test_frame_rfc9114_h3_data_after_fin),
    FUZI_Q_ITEM("rfc9114_h3_unknown_frame_critical", test_frame_rfc9114_h3_unknown_frame_critical),
    FUZI_Q_ITEM("rfc9114_h3_settings_after_request", test_frame_rfc9114_h3_settings_after_request),
    
    /* Advanced RFC 9204 QPACK Compression Attacks */
    FUZI_Q_ITEM("rfc9204_qpack_table_update_race", test_frame_rfc9204_qpack_table_update_race),
    FUZI_Q_ITEM("rfc9204_qpack_name_reference_oob", test_frame_rfc9204_qpack_name_reference_oob),
    FUZI_Q_ITEM("rfc9204_qpack_huffman_bomb_extended", test_frame_rfc9204_qpack_huffman_bomb_extended),
    FUZI_Q_ITEM("rfc9204_qpack_post_base_index", test_frame_rfc9204_qpack_post_base_index),
    
    /* Advanced RFC 9221 Datagram Extension Exploits */
    FUZI_Q_ITEM("rfc9221_datagram_id_reuse", test_frame_rfc9221_datagram_id_reuse),
    FUZI_Q_ITEM("rfc9221_datagram_ordering_violation", test_frame_rfc9221_datagram_ordering_violation),
    FUZI_Q_ITEM("rfc9221_datagram_ack_elicitation", test_frame_rfc9221_datagram_ack_elicitation),
    
    /* Advanced RFC 9250 DoQ Protocol Violations */
    FUZI_Q_ITEM("rfc9250_doq_transaction_id_reuse", test_frame_rfc9250_doq_transaction_id_reuse),
    FUZI_Q_ITEM("rfc9250_doq_stream_multiplexing_abuse", test_frame_rfc9250_doq_stream_multiplexing_abuse),
    FUZI_Q_ITEM("rfc9250_doq_early_close_attack", test_frame_rfc9250_doq_early_close_attack),
    FUZI_Q_ITEM("rfc9250_doq_padding_analysis", test_frame_rfc9250_doq_padding_analysis),
    
    /* Cross-RFC Integration Attacks */
    FUZI_Q_ITEM("cross_rfc_h3_quic_version_confusion", test_frame_cross_rfc_h3_quic_version_confusion),
    FUZI_Q_ITEM("cross_rfc_tls_quic_key_mismatch", test_frame_cross_rfc_tls_quic_key_mismatch),
    FUZI_Q_ITEM("cross_rfc_http_quic_stream_leak", test_frame_cross_rfc_http_quic_stream_leak),
    FUZI_Q_ITEM("cross_rfc_qpack_hpack_confusion", test_frame_cross_rfc_qpack_hpack_confusion),
    
    /* === EXTENDED RFC-SPECIFIC ATTACK VECTORS FUZI_Q_ITEM ENTRIES === */
    
    /* RFC 1035 - DNS Protocol Violations */
    FUZI_Q_ITEM("rfc1035_dns_compression_bomb", test_frame_rfc1035_dns_compression_bomb),
    FUZI_Q_ITEM("rfc1035_dns_label_overflow", test_frame_rfc1035_dns_label_overflow),
    FUZI_Q_ITEM("rfc1035_dns_type_confusion", test_frame_rfc1035_dns_type_confusion),
    
    /* RFC 1123 - Host Requirements Violations */
    FUZI_Q_ITEM("rfc1123_invalid_hostname", test_frame_rfc1123_invalid_hostname),
    FUZI_Q_ITEM("rfc1123_hostname_length_overflow", test_frame_rfc1123_hostname_length_overflow),
    FUZI_Q_ITEM("rfc1123_numeric_only_hostname", test_frame_rfc1123_numeric_only_hostname),
    
    /* RFC 2131 - DHCP Protocol Violations */
    FUZI_Q_ITEM("rfc2131_dhcp_option_overflow", test_frame_rfc2131_dhcp_option_overflow),
    FUZI_Q_ITEM("rfc2131_dhcp_malformed_packet", test_frame_rfc2131_dhcp_malformed_packet),
    FUZI_Q_ITEM("rfc2131_dhcp_invalid_message_type", test_frame_rfc2131_dhcp_invalid_message_type),
    
    /* RFC 2818 - HTTP Over TLS Violations */
    FUZI_Q_ITEM("rfc2818_https_redirect_attack", test_frame_rfc2818_https_redirect_attack),
    FUZI_Q_ITEM("rfc2818_mixed_content_attack", test_frame_rfc2818_mixed_content_attack),
    FUZI_Q_ITEM("rfc2818_certificate_pinning_bypass", test_frame_rfc2818_certificate_pinning_bypass),
    
    /* RFC 3280 - Certificate and CRL Profile Violations */
    FUZI_Q_ITEM("rfc3280_certificate_chain_attack", test_frame_rfc3280_certificate_chain_attack),
    FUZI_Q_ITEM("rfc3280_crl_poisoning", test_frame_rfc3280_crl_poisoning),
    FUZI_Q_ITEM("rfc3280_invalid_extension", test_frame_rfc3280_invalid_extension),
    
    /* RFC 3492 - Punycode Implementation Attacks */
    FUZI_Q_ITEM("rfc3492_punycode_overflow", test_frame_rfc3492_punycode_overflow),
    FUZI_Q_ITEM("rfc3492_punycode_homograph", test_frame_rfc3492_punycode_homograph),
    FUZI_Q_ITEM("rfc3492_punycode_mixed_script", test_frame_rfc3492_punycode_mixed_script),
    
    /* RFC 4291 - IPv6 Addressing Architecture Violations */
    FUZI_Q_ITEM("rfc4291_ipv6_header_manipulation", test_frame_rfc4291_ipv6_header_manipulation),
    FUZI_Q_ITEM("rfc4291_ipv6_extension_header_bomb", test_frame_rfc4291_ipv6_extension_header_bomb),
    FUZI_Q_ITEM("rfc4291_ipv6_address_spoofing", test_frame_rfc4291_ipv6_address_spoofing),
    
    /* RFC 5246 - TLS 1.2 Legacy Protocol Violations */
    FUZI_Q_ITEM("rfc5246_tls12_downgrade_attack", test_frame_rfc5246_tls12_downgrade_attack),
    FUZI_Q_ITEM("rfc5246_tls12_cipher_suite_confusion", test_frame_rfc5246_tls12_cipher_suite_confusion),
    FUZI_Q_ITEM("rfc5246_tls12_renegotiation_attack", test_frame_rfc5246_tls12_renegotiation_attack),
    
    /* RFC 5321 - SMTP Enhanced Violations */
    FUZI_Q_ITEM("rfc5321_smtp_pipeline_injection", test_frame_rfc5321_smtp_pipeline_injection),
    FUZI_Q_ITEM("rfc5321_smtp_header_injection", test_frame_rfc5321_smtp_header_injection),
    FUZI_Q_ITEM("rfc5321_smtp_size_limit_bypass", test_frame_rfc5321_smtp_size_limit_bypass),
    
    /* RFC 6066 - TLS Extensions Abuse */
    FUZI_Q_ITEM("rfc6066_sni_spoofing", test_frame_rfc6066_sni_spoofing),
    FUZI_Q_ITEM("rfc6066_max_fragment_length_attack", test_frame_rfc6066_max_fragment_length_attack),
    FUZI_Q_ITEM("rfc6066_server_name_overflow", test_frame_rfc6066_server_name_overflow),
    
    /* RFC 6520 - TLS/DTLS Heartbeat Extension Attacks */
    FUZI_Q_ITEM("rfc6520_heartbleed_attack", test_frame_rfc6520_heartbleed_attack),
    FUZI_Q_ITEM("rfc6520_heartbeat_overflow", test_frame_rfc6520_heartbeat_overflow),
    FUZI_Q_ITEM("rfc6520_heartbeat_response_spoofing", test_frame_rfc6520_heartbeat_response_spoofing),
    
    /* RFC 7301 - ALPN Extension Violations */
    FUZI_Q_ITEM("rfc7301_alpn_protocol_confusion", test_frame_rfc7301_alpn_protocol_confusion),
    FUZI_Q_ITEM("rfc7301_alpn_downgrade_attack", test_frame_rfc7301_alpn_downgrade_attack),
    FUZI_Q_ITEM("rfc7301_alpn_protocol_injection", test_frame_rfc7301_alpn_protocol_injection),
    
    /* RFC 7633 - X.509v3 TLS Feature Extension Attacks */
    FUZI_Q_ITEM("rfc7633_tls_feature_bypass", test_frame_rfc7633_tls_feature_bypass),
    FUZI_Q_ITEM("rfc7633_must_staple_violation", test_frame_rfc7633_must_staple_violation),
    
    /* RFC 8446 - TLS 1.3 Advanced Violations */
    FUZI_Q_ITEM("rfc8446_tls13_psk_binder_confusion", test_frame_rfc8446_tls13_psk_binder_confusion),
    FUZI_Q_ITEM("rfc8446_tls13_hello_retry_confusion", test_frame_rfc8446_tls13_hello_retry_confusion),
    FUZI_Q_ITEM("rfc8446_tls13_key_share_manipulation", test_frame_rfc8446_tls13_key_share_manipulation),
    
    /* RFC 8879 - TLS Certificate Compression Attacks */
    FUZI_Q_ITEM("rfc8879_cert_compression_bomb", test_frame_rfc8879_cert_compression_bomb),
    FUZI_Q_ITEM("rfc8879_cert_decompression_attack", test_frame_rfc8879_cert_decompression_attack),
    
    /* RFC 8998 - ShangMi Cipher Suites Attacks */
    FUZI_Q_ITEM("rfc8998_shangmi_downgrade", test_frame_rfc8998_shangmi_downgrade),
    FUZI_Q_ITEM("rfc8998_shangmi_key_confusion", test_frame_rfc8998_shangmi_key_confusion),
    
    /* RFC 9001 - Enhanced QUIC TLS Integration Attacks */
    FUZI_Q_ITEM("rfc9001_transport_param_encryption_bypass", test_frame_rfc9001_transport_param_encryption_bypass),
    FUZI_Q_ITEM("rfc9001_quic_tls_version_mismatch", test_frame_rfc9001_quic_tls_version_mismatch),
    FUZI_Q_ITEM("rfc9001_connection_id_confusion", test_frame_rfc9001_connection_id_confusion),
    
    /* === FOUNDATIONAL NETWORKING PROTOCOLS FUZI_Q_ITEM ENTRIES === */
    
    /* RFC 791 - Internet Protocol (IPv4) Violations */
    FUZI_Q_ITEM("rfc791_ipv4_fragment_overlap", test_frame_rfc791_ipv4_fragment_overlap),
    FUZI_Q_ITEM("rfc791_ipv4_option_overflow", test_frame_rfc791_ipv4_option_overflow),
    FUZI_Q_ITEM("rfc791_ipv4_ttl_manipulation", test_frame_rfc791_ipv4_ttl_manipulation),
    
    /* RFC 793 - Transmission Control Protocol (TCP) Violations */
    FUZI_Q_ITEM("rfc793_tcp_sequence_wraparound", test_frame_rfc793_tcp_sequence_wraparound),
    FUZI_Q_ITEM("rfc793_tcp_window_scale_attack", test_frame_rfc793_tcp_window_scale_attack),
    FUZI_Q_ITEM("rfc793_tcp_urgent_pointer_abuse", test_frame_rfc793_tcp_urgent_pointer_abuse),
    
    /* RFC 826 - Address Resolution Protocol (ARP) Violations */
    FUZI_Q_ITEM("rfc826_arp_spoofing_attack", test_frame_rfc826_arp_spoofing_attack),
    FUZI_Q_ITEM("rfc826_arp_cache_poisoning", test_frame_rfc826_arp_cache_poisoning),
    FUZI_Q_ITEM("rfc826_arp_gratuitous_flood", test_frame_rfc826_arp_gratuitous_flood),
    
    /* RFC 1058 - Routing Information Protocol (RIP) Violations */
    FUZI_Q_ITEM("rfc1058_rip_metric_infinity_attack", test_frame_rfc1058_rip_metric_infinity_attack),
    FUZI_Q_ITEM("rfc1058_rip_route_poisoning", test_frame_rfc1058_rip_route_poisoning),
    FUZI_Q_ITEM("rfc1058_rip_authentication_bypass", test_frame_rfc1058_rip_authentication_bypass),
    
    /* RFC 1112 - Internet Group Management Protocol (IGMP) Violations */
    FUZI_Q_ITEM("rfc1112_igmp_membership_flood", test_frame_rfc1112_igmp_membership_flood),
    FUZI_Q_ITEM("rfc1112_igmp_leave_group_spoof", test_frame_rfc1112_igmp_leave_group_spoof),
    FUZI_Q_ITEM("rfc1112_igmp_query_amplification", test_frame_rfc1112_igmp_query_amplification),
    
    /* RFC 1321 - MD5 Message-Digest Algorithm Attacks */
    FUZI_Q_ITEM("rfc1321_md5_collision_attack", test_frame_rfc1321_md5_collision_attack),
    FUZI_Q_ITEM("rfc1321_md5_length_extension", test_frame_rfc1321_md5_length_extension),
    FUZI_Q_ITEM("rfc1321_md5_preimage_attack", test_frame_rfc1321_md5_preimage_attack),
    
    /* RFC 1519 - Classless Inter-Domain Routing (CIDR) Violations */
    FUZI_Q_ITEM("rfc1519_cidr_route_aggregation_attack", test_frame_rfc1519_cidr_route_aggregation_attack),
    FUZI_Q_ITEM("rfc1519_cidr_supernet_hijack", test_frame_rfc1519_cidr_supernet_hijack),
    FUZI_Q_ITEM("rfc1519_cidr_prefix_length_manipulation", test_frame_rfc1519_cidr_prefix_length_manipulation),
    
    /* RFC 1631 - Network Address Translation (NAT) Violations */
    FUZI_Q_ITEM("rfc1631_nat_port_exhaustion", test_frame_rfc1631_nat_port_exhaustion),
    FUZI_Q_ITEM("rfc1631_nat_hairpinning_attack", test_frame_rfc1631_nat_hairpinning_attack),
    FUZI_Q_ITEM("rfc1631_nat_translation_bypass", test_frame_rfc1631_nat_translation_bypass),
    
    /* RFC 1918 - Private Internet Address Space Violations */
    FUZI_Q_ITEM("rfc1918_private_ip_leak", test_frame_rfc1918_private_ip_leak),
    FUZI_Q_ITEM("rfc1918_private_routing_attack", test_frame_rfc1918_private_routing_attack),
    FUZI_Q_ITEM("rfc1918_reserved_address_abuse", test_frame_rfc1918_reserved_address_abuse),
    
    /* RFC 2104 - HMAC Keyed-Hashing Violations */
    FUZI_Q_ITEM("rfc2104_hmac_key_recovery", test_frame_rfc2104_hmac_key_recovery),
    FUZI_Q_ITEM("rfc2104_hmac_timing_attack", test_frame_rfc2104_hmac_timing_attack),
    FUZI_Q_ITEM("rfc2104_hmac_length_extension", test_frame_rfc2104_hmac_length_extension),
    
    /* RFC 2205 - Resource Reservation Protocol (RSVP) Violations */
    FUZI_Q_ITEM("rfc2205_rsvp_path_message_spoof", test_frame_rfc2205_rsvp_path_message_spoof),
    FUZI_Q_ITEM("rfc2205_rsvp_reservation_hijack", test_frame_rfc2205_rsvp_reservation_hijack),
    FUZI_Q_ITEM("rfc2205_rsvp_teardown_attack", test_frame_rfc2205_rsvp_teardown_attack),
    
    /* RFC 2284 - PPP Extensible Authentication Protocol (EAP) Violations */
    FUZI_Q_ITEM("rfc2284_eap_identity_spoofing", test_frame_rfc2284_eap_identity_spoofing),
    FUZI_Q_ITEM("rfc2284_eap_method_downgrade", test_frame_rfc2284_eap_method_downgrade),
    FUZI_Q_ITEM("rfc2284_eap_success_injection", test_frame_rfc2284_eap_success_injection),
    
    /* RFC 2328 - Open Shortest Path First (OSPF) Violations */
    FUZI_Q_ITEM("rfc2328_ospf_hello_flood", test_frame_rfc2328_ospf_hello_flood),
    FUZI_Q_ITEM("rfc2328_ospf_lsa_poisoning", test_frame_rfc2328_ospf_lsa_poisoning),
    FUZI_Q_ITEM("rfc2328_ospf_area_hijack", test_frame_rfc2328_ospf_area_hijack),
    
    /* RFC 2401 - Security Architecture for IP (IPsec) Violations */
    FUZI_Q_ITEM("rfc2401_ipsec_esp_replay", test_frame_rfc2401_ipsec_esp_replay),
    FUZI_Q_ITEM("rfc2401_ipsec_ah_truncation", test_frame_rfc2401_ipsec_ah_truncation),
    FUZI_Q_ITEM("rfc2401_ipsec_sa_confusion", test_frame_rfc2401_ipsec_sa_confusion),
    
    /* === ADVANCED NETWORKING PROTOCOLS FUZI_Q_ITEM ENTRIES === */
    
    /* RFC 2616 - HTTP/1.1 Protocol Violations */
    FUZI_Q_ITEM("rfc2616_http11_request_smuggling", test_frame_rfc2616_http11_request_smuggling),
    FUZI_Q_ITEM("rfc2616_http11_header_injection", test_frame_rfc2616_http11_header_injection),
    FUZI_Q_ITEM("rfc2616_http11_response_splitting", test_frame_rfc2616_http11_response_splitting),
    
    /* RFC 2865 - Remote Authentication Dial In User Service (RADIUS) Violations */
    FUZI_Q_ITEM("rfc2865_radius_shared_secret_attack", test_frame_rfc2865_radius_shared_secret_attack),
    FUZI_Q_ITEM("rfc2865_radius_attribute_overflow", test_frame_rfc2865_radius_attribute_overflow),
    FUZI_Q_ITEM("rfc2865_radius_message_authenticator_bypass", test_frame_rfc2865_radius_message_authenticator_bypass),
    
    /* RFC 3164 - Syslog Protocol Violations */
    FUZI_Q_ITEM("rfc3164_syslog_format_injection", test_frame_rfc3164_syslog_format_injection),
    FUZI_Q_ITEM("rfc3164_syslog_priority_manipulation", test_frame_rfc3164_syslog_priority_manipulation),
    FUZI_Q_ITEM("rfc3164_syslog_timestamp_confusion", test_frame_rfc3164_syslog_timestamp_confusion),
    
    /* RFC 3411 - SNMP Architecture Violations */
    FUZI_Q_ITEM("rfc3411_snmp_community_brute_force", test_frame_rfc3411_snmp_community_brute_force),
    FUZI_Q_ITEM("rfc3411_snmp_version_downgrade", test_frame_rfc3411_snmp_version_downgrade),
    FUZI_Q_ITEM("rfc3411_snmp_oid_traversal", test_frame_rfc3411_snmp_oid_traversal),
    
    /* RFC 3550 - Real-time Transport Protocol (RTP) Violations */
    FUZI_Q_ITEM("rfc3550_rtp_sequence_prediction", test_frame_rfc3550_rtp_sequence_prediction),
    FUZI_Q_ITEM("rfc3550_rtp_timestamp_manipulation", test_frame_rfc3550_rtp_timestamp_manipulation),
    FUZI_Q_ITEM("rfc3550_rtp_ssrc_collision", test_frame_rfc3550_rtp_ssrc_collision),
    
    /* RFC 3748 - Extensible Authentication Protocol (EAP) Enhanced Violations */
    FUZI_Q_ITEM("rfc3748_eap_tls_fragment_bomb", test_frame_rfc3748_eap_tls_fragment_bomb),
    FUZI_Q_ITEM("rfc3748_eap_method_chaining_attack", test_frame_rfc3748_eap_method_chaining_attack),
    FUZI_Q_ITEM("rfc3748_eap_identity_disclosure", test_frame_rfc3748_eap_identity_disclosure),
    
    /* RFC 4271 - Border Gateway Protocol (BGP-4) Violations */
    FUZI_Q_ITEM("rfc4271_bgp_route_hijack", test_frame_rfc4271_bgp_route_hijack),
    FUZI_Q_ITEM("rfc4271_bgp_path_attribute_manipulation", test_frame_rfc4271_bgp_path_attribute_manipulation),
    FUZI_Q_ITEM("rfc4271_bgp_as_path_prepending_attack", test_frame_rfc4271_bgp_as_path_prepending_attack),
    
    /* RFC 4347 - Datagram Transport Layer Security (DTLS) Violations */
    FUZI_Q_ITEM("rfc4347_dtls_replay_attack", test_frame_rfc4347_dtls_replay_attack),
    FUZI_Q_ITEM("rfc4347_dtls_fragmentation_attack", test_frame_rfc4347_dtls_fragmentation_attack),
    FUZI_Q_ITEM("rfc4347_dtls_cookie_manipulation", test_frame_rfc4347_dtls_cookie_manipulation),
    
    /* RFC 4456 - BGP Route Reflection Violations */
    FUZI_Q_ITEM("rfc4456_bgp_route_reflection_loop", test_frame_rfc4456_bgp_route_reflection_loop),
    FUZI_Q_ITEM("rfc4456_bgp_cluster_id_spoof", test_frame_rfc4456_bgp_cluster_id_spoof),
    FUZI_Q_ITEM("rfc4456_bgp_originator_id_manipulation", test_frame_rfc4456_bgp_originator_id_manipulation),
    
    /* RFC 5321 - Enhanced SMTP Protocol Violations */
    FUZI_Q_ITEM("rfc5321_smtp_command_injection_enhanced", test_frame_rfc5321_smtp_command_injection_enhanced),
    FUZI_Q_ITEM("rfc5321_smtp_data_smuggling", test_frame_rfc5321_smtp_data_smuggling),
    FUZI_Q_ITEM("rfc5321_smtp_auth_bypass", test_frame_rfc5321_smtp_auth_bypass),
    
    /* RFC 5389 - Session Traversal Utilities for NAT (STUN) Violations */
    FUZI_Q_ITEM("rfc5389_stun_message_integrity_bypass", test_frame_rfc5389_stun_message_integrity_bypass),
    FUZI_Q_ITEM("rfc5389_stun_attribute_overflow", test_frame_rfc5389_stun_attribute_overflow),
    FUZI_Q_ITEM("rfc5389_stun_xor_mapped_address_confusion", test_frame_rfc5389_stun_xor_mapped_address_confusion),
    
    /* END OF JULES ADDED FUZI_Q_ITEM ENTRIES */
};

size_t nb_fuzi_q_frame_list = sizeof(fuzi_q_frame_list) / sizeof(fuzi_q_frames_t);
