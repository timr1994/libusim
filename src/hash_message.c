/* SPDX-License-Identifier: BSD-3-Clause  */
/*  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  * 
 *  Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information Technology SIT.
 *  All rights reserved.
 *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  */

/*
 * 
 *  @file hash_message.c
 *  @author Tim Riemann <tim.riemann@sit.fraunhofer.de>
 *  @date 2020-01-27
 *  
 *  @copyright Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information
 *  Technology SIT. All rights reserved.
 * 
 *  @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 *  BSD-3-Clause)
 * 
 */

#include "hash_message.h"
#include <stdio.h>

uint8_t get_hash_data_size_by_alg_name(uint16_t alg_name) {
    switch (alg_name) {
        case TPM2_ALG_SHA1:
            return SHA_DIGEST_SIZE;
        case TPM2_ALG_SHA256:
            return SHA256_DIGEST_SIZE;
        case TPM2_ALG_SHA384:
            return SHA384_DIGEST_SIZE;
        case TPM2_ALG_SHA512:
            return SHA512_DIGEST_SIZE;
        case TPM2_ALG_SM3_256:
            return SM3_256_DIGEST_SIZE;

        default:
            //error
            return 0;
    }
}

void free_hash_message(HASH_MESSAGE *hm) {
    free_hash_payload(hm->h_payload, hm->h_payload_size);
    free(hm->event);
    free(hm->h_payload);
    free(hm->event_id);
    free(hm);
}

void free_hash_payload(hash_payload *hp, uint8_t count) {
    for (uint8_t i = 0; i < count; i++) {
        free(hp[i].hash_data);
    }
}

void pretty_print_hash_message(HASH_MESSAGE *hm) {
    printf("event_id: %s\r\n", hm->event_id);
    printf("event: ");
    for (uint64_t j = 0; j < hm->event_length; j++) {
        printf("%02x", hm->event[j]);
    }
    printf("\r\n");
    for (int i = 0; i < hm->h_payload_size; i++) {
        printf("\t %02d.hash id: %04x\r\n\t %02d.hash: ", i, hm->h_payload[i].alg_name, i);
        for (int j = 0; j < get_hash_data_size_by_alg_name(hm->h_payload[i].alg_name); j++) {
            printf("%02x", hm->h_payload[i].hash_data[j]);
        }
        printf("\r\n");
    }

    HASH_MESSAGE * clone(HASH_MESSAGE * hm) {
        HASH_MESSAGE *cl = malloc(sizeof (HASH_MESSAGE));
        cl->event = malloc(hm->event_length);
        cl->event_length = hm->event_length;
        memcpy(cl->event, hm->event, cl->event_length);
        cl->event_id_length = strlen(hm->event_id);
        cl->event_id = strndup(hm->event_id, cl->event_id_length);
        cl->h_payload = malloc(sizeof (hash_payload));
        cl->h_payload_size = hm->h_payload_size;
        cl->h_payload = malloc(cl->h_payload_size * sizeof (hash_payload));
        for (uint8_t i = 0; i < cl->h_payload_size; i++) {
            cl->h_payload[i].alg_name = hm->h_payload[i].alg_name;
            cl->h_payload[i].hash_data = malloc(get_hash_data_size_by_alg_name(cl->h_payload[i].alg_name));
            memcpy(cl->h_payload[i].hash_data, hm->h_payload[i].hash_data, get_hash_data_size_by_alg_name(cl->h_payload[i].alg_name));
        }
        return cl;
    }

}


