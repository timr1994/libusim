/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file uiim.h
 * @author Tim Riemann (tim.riemann@sit.fraunhofer.de)
 * @brief
 * @version 0.1
 * @date 2020-01-13
 *
 * @copyright Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information
 * Technology SIT. All rights reserved.
 *
 * @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 * BSD-3-Clause).
 */
#ifndef _UIIM_H_
#define _UIIM_H_

#include "hash_message_cbor.h"
#include "help_functions.h"
#include <mbedtls/platform.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha512.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>                                                      

#define MAX_SIZE_RECV 329


#define SIZE_OF_INIT_MESSAGE(ctx) (sizeof(uint16_t)*8 + strlen(ctx->producer))
#define SIZE_OF_INIT_MESSAGE_payload(ctx) (sizeof(uint16_t)*4 + strlen(ctx->producer))
#define SIZE_OF_MESSAGE_HEADER (sizeof(uint16_t)*2+sizeof(uint32_t))
#define SIZE_OF_ANSWER_HEADER (sizeof(uint16_t)+sizeof(IN_RC))

#define FLAG_ERROR                0x0000000000000001
#define FLAG_RSA                  0x0000000000000002
#define FLAG_TDES                 0x0000000000000004
#define FLAG_SHA                  0x0000000000000008
#define FLAG_SHA1                 0x0000000000000010
#define FLAG_HMAC                 0x0000000000000020
#define FLAG_AES                  0x0000000000000040
#define FLAG_MGF1                 0x0000000000000080
#define FLAG_KEYEDHASH            0x0000000000000100
#define FLAG_XOR                  0x0000000000000200
#define FLAG_SHA256               0x0000000000000400
#define FLAG_SHA384               0x0000000000000800
#define FLAG_SHA512               0x0000000000001000
#define FLAG_NULL                 0x0000000000002000
#define FLAG_SM3_256              0x0000000000004000
#define FLAG_SM4                  0x0000000000008000
#define FLAG_RSASSA               0x0000000000010000
#define FLAG_RSAES                0x0000000000020000
#define FLAG_RSAPSS               0x0000000000040000
#define FLAG_OAEP                 0x0000000000080000
#define FLAG_ECDSA                0x0000000000100000
#define FLAG_ECDH                 0x0000000000200000
#define FLAG_ECDAA                0x0000000000400000
#define FLAG_SM2                  0x0000000000800000
#define FLAG_ECSCHNORR            0x0000000001000000
#define FLAG_ECMQV                0x0000000002000000
#define FLAG_KDF1_SP800_56A       0x0000000004000000
#define FLAG_KDF2                 0x0000000008000000
#define FLAG_KDF1_SP800_108       0x0000000010000000
#define FLAG_ECC                  0x0000000020000000
#define FLAG_SYMCIPHER            0x0000000040000000
#define FLAG_CAMELLIA             0x0000000080000000
#define FLAG_CMAC                 0x0000000100000000
#define FLAG_CTR                  0x0000000200000000
#define FLAG_SHA3_256             0x0000000400000000
#define FLAG_SHA3_384             0x0000000800000000
#define FLAG_SHA3_512             0x0000001000000000
#define FLAG_OFB                  0x0000002000000000
#define FLAG_CBC                  0x0000004000000000
#define FLAG_CFB                  0x0000008000000000
#define FLAG_ECB                  0x0000010000000000
#define FLAG_FIRST                0x0000020000000000
#define FLAG_LAST                 0x0000040000000000

typedef struct uiimctx {
    uint8_t flags;
    uint8_t pcr;
    char *producer;
    uint16_t sl_algs_len;
    uint16_t *sl_algs;
    uint16_t sessionId;
    uint16_t seqNum;
    int socket;
} uiimctx;

typedef enum {
    TPM_LOG_SERVICE_LOCAL_FILE,
    TPM_LOG_SERVICE_LOCAL_UNIX, // UNIX Domain Sockets
    TPM_LOG_SERVICE_REMOTE_ALS_TCP, // ALS: App Log Service
} tpm_log_service_type;

typedef struct {
    /* inputs */
    FILE log_file_name;
    /* state variables */
    int fd; // file descriptor
} tpm_log_service_local_file;

typedef struct {
    /* inputs */
    int socket;
    /* state variables */
} tpm_log_service_local_unix;

typedef struct {
    /* inputs */
    char* host;
    uint8_t host_len;
    int port;
    char* producer;
    char* producer_len;
    uint8_t* log_id;
    uint8_t log_id_len;
    /* state variables */
} tpm_log_service_remote_als_tcp;

typedef union {
    tpm_log_service_local_file local_file;
    tpm_log_service_local_unix local_unix;
    tpm_log_service_remote_als_tcp remote_als_tcp;
} tpm_log_service;

typedef struct {
    tpm_log_service_type type;
    tpm_log_service service;
    uint8_t flags; // bitmask with flags: NO_DUPLICATES, LOG_MULTIPLE_RECORDS_AS_ONE
} tpm_log_service_ctx;

typedef struct answer {
    uint16_t seqNum; //
    IN_RC rc;
} Answer;

#ifdef __cplusplus
extern "C" {
#endif
    IN_RC uiim_init(uiimctx *ctx, uint8_t pcr, const char *producer, const char *host, uint16_t port, uint8_t flags);
    IN_RC uiim_init_unix(uiimctx *ctx, uint8_t pcr, const char *producer, int socket, uint8_t flags);
    IN_RC uiim_add_alg_id(uiimctx *ctx, TPM2_ALG_ID id);
    uint16_t uiim_add_event_own_hashes(uiimctx *ctx, const char* eventid, const unsigned char* event, unsigned int eventlength, hash_payload *hp, uint8_t hp_count);
    uint16_t uiim_add_event(uiimctx *ctx, const char* eventid, const unsigned char* event, unsigned int eventlength);
    Answer *uiim_finish_all(uiimctx *ctx, uint16_t count);
    Answer *uiim_finish_one(uiimctx *ctx);
    IN_RC uiim_free_ctx(uiimctx *ctx);

    uint8_t *answer_marshalling(uint16_t seqNum, IN_RC rc);
    uint8_t *answer_marshalling_an(Answer *an);
    Answer *answer_unmarshalling(uint8_t *buf);

#ifdef __cplusplus
}
#endif
#endif
