/* SPDX-License-Identifier: BSD-3-Clause  */
/*  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  * 
 *  Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information Technology SIT.
 *  All rights reserved.
 *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  */

/*
 * 
 *  @file hash_message.h
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

#ifndef HASH_MESSAGE_H
#define HASH_MESSAGE_H

#include <stdlib.h>
#include <sys/types.h>
#include <stdbool.h>  
#include <stdint.h>
#include <uthash.h>

#define SHA_DIGEST_SIZE 20
#define SHA1_DIGEST_SIZE 20
#define SHA256_DIGEST_SIZE 32
#define SHA384_DIGEST_SIZE 48
#define SHA512_DIGEST_SIZE 64
#define SM3_256_DIGEST_SIZE 32

/* From TCG Algorithm Registry: Definition of TPM2_ALG_ID Constants */
typedef uint16_t TPM2_ALG_ID;

#define TPM2_ALG_ERROR               ((TPM2_ALG_ID) 0x0000)
#define TPM2_ALG_RSA                 ((TPM2_ALG_ID) 0x0001)
#define TPM2_ALG_TDES                ((TPM2_ALG_ID) 0x0003)
#define TPM2_ALG_SHA                 ((TPM2_ALG_ID) 0x0004)
#define TPM2_ALG_SHA1                ((TPM2_ALG_ID) 0x0004)
#define TPM2_ALG_HMAC                ((TPM2_ALG_ID) 0x0005)
#define TPM2_ALG_AES                 ((TPM2_ALG_ID) 0x0006)
#define TPM2_ALG_MGF1                ((TPM2_ALG_ID) 0x0007)
#define TPM2_ALG_KEYEDHASH           ((TPM2_ALG_ID) 0x0008)
#define TPM2_ALG_XOR                 ((TPM2_ALG_ID) 0x000A)
#define TPM2_ALG_SHA256              ((TPM2_ALG_ID) 0x000B)
#define TPM2_ALG_SHA384              ((TPM2_ALG_ID) 0x000C)
#define TPM2_ALG_SHA512              ((TPM2_ALG_ID) 0x000D)
#define TPM2_ALG_NULL                ((TPM2_ALG_ID) 0x0010)
#define TPM2_ALG_SM3_256             ((TPM2_ALG_ID) 0x0012)
#define TPM2_ALG_SM4                 ((TPM2_ALG_ID) 0x0013)
#define TPM2_ALG_RSASSA              ((TPM2_ALG_ID) 0x0014)
#define TPM2_ALG_RSAES               ((TPM2_ALG_ID) 0x0015)
#define TPM2_ALG_RSAPSS              ((TPM2_ALG_ID) 0x0016)
#define TPM2_ALG_OAEP                ((TPM2_ALG_ID) 0x0017)
#define TPM2_ALG_ECDSA               ((TPM2_ALG_ID) 0x0018)
#define TPM2_ALG_ECDH                ((TPM2_ALG_ID) 0x0019)
#define TPM2_ALG_ECDAA               ((TPM2_ALG_ID) 0x001A)
#define TPM2_ALG_SM2                 ((TPM2_ALG_ID) 0x001B)
#define TPM2_ALG_ECSCHNORR           ((TPM2_ALG_ID) 0x001C)
#define TPM2_ALG_ECMQV               ((TPM2_ALG_ID) 0x001D)
#define TPM2_ALG_KDF1_SP800_56A      ((TPM2_ALG_ID) 0x0020)
#define TPM2_ALG_KDF2                ((TPM2_ALG_ID) 0x0021)
#define TPM2_ALG_KDF1_SP800_108      ((TPM2_ALG_ID) 0x0022)
#define TPM2_ALG_ECC                 ((TPM2_ALG_ID) 0x0023)
#define TPM2_ALG_SYMCIPHER           ((TPM2_ALG_ID) 0x0025)
#define TPM2_ALG_CAMELLIA            ((TPM2_ALG_ID) 0x0026)
#define TPM2_ALG_CMAC                ((TPM2_ALG_ID) 0x003F)
#define TPM2_ALG_CTR                 ((TPM2_ALG_ID) 0x0040)
#define TPM2_ALG_SHA3_256            ((TPM2_ALG_ID) 0x0027)
#define TPM2_ALG_SHA3_384            ((TPM2_ALG_ID) 0x0028)
#define TPM2_ALG_SHA3_512            ((TPM2_ALG_ID) 0x0029)
#define TPM2_ALG_OFB                 ((TPM2_ALG_ID) 0x0041)
#define TPM2_ALG_CBC                 ((TPM2_ALG_ID) 0x0042)
#define TPM2_ALG_CFB                 ((TPM2_ALG_ID) 0x0043)
#define TPM2_ALG_ECB                 ((TPM2_ALG_ID) 0x0044)
#define TPM2_ALG_FIRST               ((TPM2_ALG_ID) 0x0001)
#define TPM2_ALG_LAST                ((TPM2_ALG_ID) 0x0044)

#define MINIMUM_SIZE 15

#define DO_NOT_HANDLE_DUPLICATES 0x01
#define CHECK_PCR 0x02
#define LOG_MULTIPLE_RECORDS_AS_ONE 0x04
#define CHECK_PCR_AN_QUIT 0x08

enum MESSAGE_TYP {
    ER = 0,
    PCR = 1,
    INTEPRETER_NAME = 2,
    FILE_NAME = 3,
    HASH_PAYLOAD_SIZE = 4,
    HASH_PAYLOAD = 5,
    HASH_ALG = 6,
    HASH_DATA = 7

};

typedef struct hash_payload {
    uint16_t alg_name;
    uint8_t *hash_data;
} hash_payload;

typedef struct HASH_MESSAGE {
    char *event_id;
    uint8_t event_id_length;
    uint64_t event_length;
    uint8_t *event;
    uint8_t h_payload_size;
    hash_payload *h_payload;
    UT_hash_handle hh;
} HASH_MESSAGE;

typedef enum IN_RC {
    Nothing = 0x0000,
    EntryInsert,
    AlreadyInsert,
    Collision,
    TPMError,
    TPMPCRValueNotExpected,
    NoRessources,
    SessionIDEnded,
    UnSupportedHash,
    SIF, //ServiceInitFailed
    SessionEnd,
    SessionStart,
    NoHashAlgDefined,
    LoggerInitFailed,
            SendFailed,
    InvalidMessage = 0xFFFF
} IN_RC;


#ifdef __cplusplus
extern "C" {
#endif
    /**
     * @brief size for specifed hash alg.
     * 
     * @param alg_name TPM2_ALG_ID
     * @return size of bytes need for given hash alg
     */
    uint8_t get_hash_data_size_by_alg_name(uint16_t alg_name);

    /**
     * @brief frees a HASH_MESSAGE.
     * 
     * @param hm HASH_MESSAGE should be freed.
     */
    void free_hash_message(HASH_MESSAGE *hm);


    void free_hash_payload(hash_payload *hp, uint8_t count);
    /**
     * @brief Prints a HASH_MESSAGE
     * 
     * @param hm
     */
    void pretty_print_hash_message(HASH_MESSAGE *hm);

    HASH_MESSAGE *clone(HASH_MESSAGE *hm);





#ifdef __cplusplus
}
#endif

#endif /* HASH_MESSAGE_H */

