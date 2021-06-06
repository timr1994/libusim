/* SPDX-License-Identifier: BSD-3-Clause  */
/*  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  * 
 *  Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information Technology SIT.
 *  All rights reserved.
 *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  */

/*
 * 
 *  @file hash_message_cbor.c
 *  @author Tim Riemann <tim.riemann@sit.fraunhofer.de>
 *  @date 2020-02-04
 *  
 *  @copyright Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information
 *  Technology SIT. All rights reserved.
 * 
 *  @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 *  BSD-3-Clause)
 * 
 */

#include "hash_message_cbor.h"
#include <limits.h>

HASH_MESSAGE *unmarshalling(uint8_t *data, size_t data_length) {
    HASH_MESSAGE *hm = malloc(sizeof (struct HASH_MESSAGE));
    unmarshalling_fill(data, data_length, hm);
    return hm;
}

void unmarshalling_fill(uint8_t *data, size_t data_length, HASH_MESSAGE *hm) {
    QCBORDecodeContext DCtx;
    UsefulBufC buf;
    QCBORItem item;
    buf.len = data_length;
    buf.ptr = data;
    QCBORDecode_Init(&DCtx, buf, QCBOR_DECODE_MODE_NORMAL);
    QCBORDecode_GetNext(&DCtx, &item);
    if (item.uDataType == QCBOR_TYPE_ARRAY && item.val.uCount == 3) {
        QCBORDecode_GetNext(&DCtx, &item);
        if (item.uDataType == QCBOR_TYPE_TEXT_STRING) {
            hm->event_id = memcpy(malloc(item.val.string.len + 1), item.val.string.ptr, item.val.string.len);
            hm->event_id[item.val.string.len] = '\0';
            hm->event_id_length = item.val.string.len;
        }
        QCBORDecode_GetNext(&DCtx, &item);
        if (item.uDataType == QCBOR_TYPE_BYTE_STRING) {
            hm->event_length = item.val.string.len;
            hm->event = memcpy(malloc(item.val.string.len), item.val.string.ptr, item.val.string.len);
        }
        QCBORDecode_GetNext(&DCtx, &item);
        if (item.uDataType == QCBOR_TYPE_ARRAY) {
            hm->h_payload_size = item.val.uCount;
            hm->h_payload = calloc(hm->h_payload_size, sizeof (hash_payload));
            for (uint8_t i = 0; i < hm->h_payload_size; i++) {
                QCBORDecode_GetNext(&DCtx, &item);
                if (item.uDataType == QCBOR_TYPE_ARRAY && item.val.uCount == 2) {
                    QCBORDecode_GetNext(&DCtx, &item);
                    if (item.uDataType == QCBOR_TYPE_INT64) {
                        hm->h_payload[i].alg_name = item.val.uint64;
                        hm->h_payload[i].hash_data = malloc(get_hash_data_size_by_alg_name(hm->h_payload[i].alg_name));
                    }
                    QCBORDecode_GetNext(&DCtx, &item);
                    if (item.uDataType == QCBOR_TYPE_BYTE_STRING && get_hash_data_size_by_alg_name(hm->h_payload[i].alg_name) == item.val.string.len) {
                        memcpy(hm->h_payload[i].hash_data, item.val.string.ptr, item.val.string.len);
                    }
                }
            }
        }

    }
    QCBORDecode_Finish(&DCtx);
}

uint8_t *marshalling(HASH_MESSAGE *hm) {
    QCBOREncodeContext eCtx;
    UsefulBuf buf;
    buf.len = get_size_of_hash_message(hm);
    buf.ptr = malloc(buf.len);
    QCBOREncode_Init(&eCtx, buf);
    QCBOREncode_OpenArray(&eCtx);
    QCBOREncode_AddSZString(&eCtx, hm->event_id);
    QCBOREncode_AddBytes(&eCtx, (UsefulBufC){hm->event, hm->event_length});
    QCBOREncode_OpenArray(&eCtx);
    for (uint16_t i = 0; i < hm->h_payload_size; i++) {
        QCBOREncode_OpenArray(&eCtx);
        QCBOREncode_AddUInt64(&eCtx, hm->h_payload[i].alg_name);
        QCBOREncode_AddBytes(&eCtx, (UsefulBufC){hm->h_payload[i].hash_data, get_hash_data_size_by_alg_name(hm->h_payload[i].alg_name)});
        QCBOREncode_CloseArray(&eCtx);
    }
    QCBOREncode_CloseArray(&eCtx);
    QCBOREncode_CloseArray(&eCtx);
    UsefulBufC Encoded;
    QCBOREncode_Finish(&eCtx, &Encoded);
    uint8_t *reP=malloc(Encoded.len);
    memcpy(reP, Encoded.ptr, Encoded.len);
    return reP;
}

size_t get_size_of_hash_message(HASH_MESSAGE *hm) {
    size_t size = 1; // root array should never have more than 5 elements, so is array type identfifer with array length is 1 byte
    size += get_size_for_cbor_string(hm->event_id);
    size += get_size_for_cbor_bstring(hm->event_length);
    size += get_size_for_cbor_uint(hm->h_payload_size); //inner array should never have more than 5 elements, so is array type identfifer with array length is 1 byte
    for (int i = 0; i < hm->h_payload_size; i++) {
        size += 1; //sub array never have more than 2 elements, so is array type identfifer with array length is 1 byte
        size += get_size_for_cbor_uint(hm->h_payload[i].alg_name);
        size += get_size_for_cbor_uint(get_hash_data_size_by_alg_name(hm->h_payload[i].alg_name));
        size += get_hash_data_size_by_alg_name(hm->h_payload[i].alg_name);
    }

    return size;
}