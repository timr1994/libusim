/* SPDX-License-Identifier: BSD-3-Clause  */
/*  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  * 
 *  Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information Technology SIT.
 *  All rights reserved.
 *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  */

/*
 * 
 *  @file hash_message_cbor.h
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

/* 
 * File:   hash_message_cbor.h
 * Author: Tim Riemann <tim.riemann@sit.fraunhofer.de>
 *
 * Created on 4. Februar 2020, 12:18
 */

#ifndef HASH_MESSAGE_SER_H
#define HASH_MESSAGE_SER_H

#include "hash_message.h"
#include <stdlib.h>
#include <qcbor/qcbor_decode.h>
#include <qcbor/qcbor_encode.h>
#include <qcbor/UsefulBuf.h>
#include "cbor_help.h"

#ifdef __cplusplus
extern "C" {
#endif
    /**
     * @brief unmarshalling of a HASH_MESSAGE
     * 
     * @param data buffer with binary data
     * @param data_length length of the buffer
     * @return pointer to HASH_MESSAGE on base of buffer
     */
    HASH_MESSAGE *unmarshalling(uint8_t *data, size_t data_length);
    
    /**
     * @brief Fills data into a HASH_MESSAGE
     * 
     * @param data buffer with binary data
     * @param data_length length of the buffer
     * @param hm HASH_MESSAGE which should be filled 
     */
    void unmarshalling_fill(uint8_t *data, size_t data_length, HASH_MESSAGE *hm);
    
    /**
     * @brief Brings HASH_MESSAGE into binary data
     * 
     * @param hm HASH_MESSAGE that should be marshalled
     * @return buffer with binary data
     */
    uint8_t *marshalling(HASH_MESSAGE *hm);
    
    /**
     * @brief calculate size of HASH_MESSAGE
     * @param hm HASH_MESSAGE for the size should be calculated
     * @return size of HASH_MESSAGE
     */
    size_t get_size_of_hash_message(HASH_MESSAGE *hm);



#ifdef __cplusplus
}
#endif

#endif /* HASH_MESSAGE_SER_H */

