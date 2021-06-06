/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file uiim.c
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
#include "uiim.h"
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdlib.h>

#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>

#define BUF 1024
#define UDS_FILE "/tmp/sock.uds"

volatile uint16_t seq_num = 1;

uint8_t *answer_marshalling(uint16_t seqNum, IN_RC rc) {
    uint8_t *ansBuf = malloc(sizeof (seqNum) + sizeof (rc));
    memset(ansBuf, 0, sizeof (seqNum) + sizeof (rc));
    uint16_t pos = 0;
    seqNum = htons(seqNum);
    rc = htonl(rc);
    memcpy(ansBuf + pos, &seqNum, sizeof (seqNum));
    pos += sizeof (seqNum);
    memcpy(ansBuf + pos, &rc, sizeof (rc));
    //pos += sizeof (rc); if extension is needed.
    return ansBuf;
}

uint8_t *answer_marshalling_an(Answer *an) {
    return answer_marshalling(an->seqNum, an->rc);
}

Answer *answer_unmarshalling(uint8_t *buf) {
    Answer *ans = malloc(sizeof (Answer));
    uint16_t pos = 0;
    memcpy(&ans->seqNum, buf + pos, sizeof (ans->seqNum));
    pos += sizeof (ans->seqNum);
    memcpy(&ans->rc, buf + pos, sizeof (ans->rc));
    //pos += sizeof (ans->rc);if extension is needed.
    ans->rc = ntohl(ans->rc);
    ans->seqNum = ntohs(ans->seqNum);
    return ans;
}

void init_sendfd(uiimctx *ctx, uint16_t port, const char *host) {
    int sockfd = 0;
    int portno;
    struct sockaddr_in serv_addr;
    struct hostent *server;

    portno = port;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("ERROR opening socket");
        exit(1);
    }

    server = gethostbyname(host);

    if (server == NULL) {
        fprintf(stderr, "ERROR, no such host\n");
        exit(0);
    }

    bzero((char *) &serv_addr, sizeof (serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *) server->h_addr_list[0], (char *) &serv_addr.sin_addr.s_addr, server->h_length);
    serv_addr.sin_port = htons(portno);

    /* Now connect to the server */
    if (connect(sockfd, (struct sockaddr*) &serv_addr, sizeof (serv_addr)) < 0) {
        perror("ERROR connecting");
        exit(1);
    }
    ctx->socket = sockfd;
}

IN_RC service_init(uiimctx *ctx) {

    uint8_t *buf = malloc(SIZE_OF_INIT_MESSAGE(ctx));
    memset(buf, 0, SIZE_OF_INIT_MESSAGE(ctx));
    size_t pos = 0;
    uint16_t sesIdNO = htons(ctx->sessionId);
    memcpy(buf + pos, &sesIdNO, sizeof (sesIdNO));
    pos += sizeof (sesIdNO);
    uint16_t seqNumNO = htons(ctx->seqNum);
    memcpy(buf + pos, &seqNumNO, sizeof (seqNumNO));
    pos += sizeof (seqNumNO);
    uint32_t payloadSizeNO = htonl(SIZE_OF_INIT_MESSAGE_payload(ctx));
    memcpy(buf + pos, &payloadSizeNO, sizeof (payloadSizeNO));
    pos += sizeof (payloadSizeNO);
    memcpy(buf + pos, &ctx->pcr, sizeof (ctx->pcr));
    pos += sizeof (ctx->pcr);
    //skip 2
    pos += 2;
    memcpy(buf + pos, &ctx->flags, sizeof (ctx->flags));
    pos += sizeof (ctx->flags);
    uint32_t prod_len = htonl(strlen(ctx->producer));
    memcpy(buf + pos, &prod_len, sizeof (prod_len));
    pos += sizeof (prod_len);
    memcpy(buf + pos, ctx->producer, ntohl(prod_len));
    IN_RC rc;
    ssize_t writen = full_write(ctx->socket, buf, SIZE_OF_INIT_MESSAGE(ctx));
    if (writen <= 0) {
        return SIF;
    }
    int readed = full_read(ctx->socket, &ctx->sessionId, sizeof (ctx->sessionId));
    if (readed <= 0) {
        return SIF;
    }
    ctx->sessionId = ntohs(ctx->sessionId);
    readed = full_read(ctx->socket, &rc, sizeof (rc));
    if (readed <= 0) {
        return SIF;
    }
    rc = ntohl(rc);
    return rc;
}

/**
 * @brief Calculate hash on base of filebuffer
 * 
 * @param[out] output will be filled with hash data
 * @param[in] filebuffer 
 * @param[in] bufferlength
 * @return 0 on sucess, 1 on error
 */
int set_sha1_hash(uint8_t *output, const unsigned char* filebuffer, unsigned int bufferlength) {
    mbedtls_sha1_context ctx;
    mbedtls_sha1_init(&ctx);
    mbedtls_sha1_starts_ret(&ctx);
    mbedtls_sha1_update_ret(&ctx, filebuffer, bufferlength);
    mbedtls_sha1_finish_ret(&ctx, output);
    mbedtls_sha1_free(&ctx);
    return 0;
}

/**
 * @brief Calculate hash on base of filebuffer
 * 
 * @param[out] output will be filled with hash data
 * @param[in] filebuffer 
 * @param[in] bufferlength
 * @return 0 on sucess, 1 on error
 */
int set_sha256_hash(uint8_t *output, const unsigned char* filebuffer, unsigned int bufferlength) {
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts_ret(&ctx, 0); /* 0 here means use the full SHA-256, not the SHA-224 variant */
    mbedtls_sha256_update_ret(&ctx, filebuffer, bufferlength);
    mbedtls_sha256_finish_ret(&ctx, output);
    mbedtls_sha256_free(&ctx);
    return 0;
}

/**
 * @brief Calculate hash on base of filebuffer
 * 
 * @param[out] output will be filled with hash data
 * @param[in] filebuffer 
 * @param[in] bufferlength
 * @param[in] is384
 * @return 0 on sucess, 1 on error
 */
int set_sha512_hash_(uint8_t *output, const unsigned char* filebuffer, unsigned int bufferlength, int is384) {
    mbedtls_sha512_context ctx;
    mbedtls_sha512_init(&ctx);
    mbedtls_sha512_starts_ret(&ctx, is384);
    mbedtls_sha512_update_ret(&ctx, filebuffer, bufferlength);
    mbedtls_sha512_finish_ret(&ctx, output);
    mbedtls_sha512_free(&ctx);
    return 0;
}

/**
 * @brief Calculate hash on base of filebuffer
 * 
 * @param[out] output will be filled with hash data
 * @param[in] filebuffer 
 * @param[in] bufferlength
 * @return 0 on sucess, 1 on error
 */
int set_sha512_hash(uint8_t *output, const unsigned char* filebuffer, unsigned int bufferlength) {
    return set_sha512_hash_(output, filebuffer, bufferlength, 0);
}

/**
 * @brief Calculate hash on base of filebuffer
 * 
 * @param[out] output will be filled with hash data
 * @param[in] filebuffer 
 * @param[in] bufferlength
 * @return 0 on sucess, 1 on error
 */
int set_sha384_hash(uint8_t *output, const unsigned char* filebuffer, unsigned int bufferlength) {
    return set_sha512_hash_(output, filebuffer, bufferlength, 1);
}

uint16_t send_hash_message(uiimctx *ctx, HASH_MESSAGE *hm) {
    uint8_t *bufHM = marshalling(hm);
    size_t hmSize = get_size_of_hash_message(hm);
    uint8_t *buf = malloc(hmSize + SIZE_OF_MESSAGE_HEADER);
    memset(buf, 0, hmSize + SIZE_OF_MESSAGE_HEADER);
    size_t pos = 0;
    uint16_t sesIdNO = htons(ctx->sessionId);
    memcpy(buf + pos, &sesIdNO, sizeof (sesIdNO));
    pos += sizeof (sesIdNO);
    uint16_t seqNumNO = htons(ctx->seqNum++);
    memcpy(buf + pos, &seqNumNO, sizeof (seqNumNO));
    pos += sizeof (seqNumNO);
    uint32_t sizePayload = htonl(hmSize);
    memcpy(buf + pos, &sizePayload, sizeof (sizePayload));
    pos += sizeof (sizePayload);
    memcpy(buf + pos, bufHM, hmSize);
    full_write(ctx->socket, buf, hmSize + SIZE_OF_MESSAGE_HEADER);
    return ntohs(seqNumNO);
}

IN_RC uiim_init(uiimctx *ctx, uint8_t pcr, const char *producer, const char *host, uint16_t port, uint8_t flags) {

    ctx->seqNum = 1;
    ctx->sessionId = 0;
    ctx->flags = flags;
    ctx->pcr = pcr;
    ctx->producer = strcpy(malloc(strlen(producer) + 1), producer);
    ctx->sl_algs_len = 0;
    ctx->sl_algs = NULL;
    init_sendfd(ctx, port, host);
    service_init(ctx);
}

IN_RC uiim_init_unix(uiimctx *ctx, uint8_t pcr, const char *producer, int socket, uint8_t flags) {
    ctx->seqNum = 1;
    ctx->sessionId = 0;
    ctx->flags = flags;
    ctx->pcr = pcr;
    ctx->producer = strcpy(malloc(strlen(producer) + 1), producer);
    ctx->sl_algs_len = 0;
    ctx->sl_algs = NULL;
    ctx->socket = socket;
    service_init(ctx);
}

IN_RC uiim_add_alg_id(uiimctx *ctx, TPM2_ALG_ID id) {
    ctx->sl_algs_len++;
    ctx->sl_algs = realloc(ctx->sl_algs, ctx->sl_algs_len * sizeof (TPM2_ALG_ID));
    ctx->sl_algs[ctx->sl_algs_len - 1] = id;
}

uint16_t uiim_add_event_own_hashes(uiimctx *ctx, const char* eventid, const unsigned char* event, unsigned int eventlength, hash_payload *hp, uint8_t hp_count) {
    HASH_MESSAGE hm;
    hm.event_id_length = strlen(eventid);
    hm.h_payload_size = hp_count;
    size_t hp_size = 0;
    for (uint8_t i = 0; i < hm.h_payload_size; i++) {
        hp_size += get_hash_data_size_by_alg_name(hp[i].alg_name);
    }
    hm.h_payload = memcpy(malloc(hp_size), hp, hp_size);
    hm.event_length = eventlength;
    hm.event = memcpy(malloc(eventlength), event, eventlength);
    hm.event_id = strcpy(malloc(hm.event_id_length + 1), eventid);

    return send_hash_message(ctx, &hm);
}

uint16_t uiim_add_event(uiimctx *ctx, const char* eventid, const unsigned char* event, unsigned int eventlength) {
    if (ctx->sl_algs_len == 0) {
        return NoHashAlgDefined;
    }
    hash_payload hp[ctx->sl_algs_len];
    for (uint16_t i = 0; i < ctx->sl_algs_len; i++) {
        switch (ctx->sl_algs[i]) {
            case TPM2_ALG_SHA1:
                hp[i].alg_name = ctx->sl_algs[i];
                hp[i].hash_data = calloc(get_hash_data_size_by_alg_name(ctx->sl_algs[i]), sizeof (uint8_t));
                set_sha1_hash(hp[i].hash_data, event, eventlength);
                break;
            case TPM2_ALG_SHA256:
                hp[i].alg_name = ctx->sl_algs[i];
                hp[i].hash_data = calloc(get_hash_data_size_by_alg_name(ctx->sl_algs[i]), sizeof (uint8_t));
                set_sha256_hash(hp[i].hash_data, event, eventlength);
                break;
            case TPM2_ALG_SHA384:
                hp[i].alg_name = ctx->sl_algs[i];
                hp[i].hash_data = calloc(get_hash_data_size_by_alg_name(ctx->sl_algs[i]), sizeof (uint8_t));
                set_sha384_hash(hp[i].hash_data, event, eventlength);
                break;
            case TPM2_ALG_SHA512:
                hp[i].alg_name = ctx->sl_algs[i];
                hp[i].hash_data = calloc(get_hash_data_size_by_alg_name(ctx->sl_algs[i]), sizeof (uint8_t));
                set_sha512_hash(hp[i].hash_data, event, eventlength);
                break;
            default:
                // not implemented
                break;
        }
    }
    return uiim_add_event_own_hashes(ctx, eventid, event, eventlength, hp, ctx->sl_algs_len);

}

/**
 * Tries to get the Answers for all events or until count is reached.
 * @param ctx 
 * @param count
 * @return An Answer array with the length of count. If count higher than the real replies, the others Answers data a set to 0.
 */
Answer *uiim_finish_all(uiimctx *ctx, uint16_t count) {
    Answer *replies = calloc(count, sizeof (Answer));
    memset(replies, 0, sizeof (Answer) * count);
    for (uint16_t i = 0; i < count; i++) {
        uint8_t buf[SIZE_OF_ANSWER_HEADER];
        ssize_t rc = full_read(ctx->socket, buf, sizeof (buf));
        if (rc == 0) {
            break;
        }
        Answer *ans = answer_unmarshalling(buf);
        replies[i].rc = ans->rc;
        replies[i].seqNum = ans->seqNum;
        free(ans);
    }
    return replies;

}

Answer *uiim_finish_one(uiimctx *ctx) {
    return uiim_finish_all(ctx, 1);
}

IN_RC uiim_free_ctx(uiimctx *ctx) {
    uint8_t *buf = malloc(SIZE_OF_MESSAGE_HEADER);
    memset(buf, 0, SIZE_OF_MESSAGE_HEADER);
    uint16_t sesIdNO = htons(ctx->sessionId);
    memcpy(buf, &sesIdNO, sizeof (sesIdNO));
    int writen = full_write(ctx->socket, buf, SIZE_OF_MESSAGE_HEADER);
    if (writen <= 0) {
        free(buf);
        return SendFailed;
    }
    close(ctx->socket);
    free(buf);
    return SessionEnd;
}



