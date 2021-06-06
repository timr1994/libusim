/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file cbor_util.h
 * @author Michael Eckel (michael.eckel@sit.fraunhofer.de)
 * @brief
 * @version 0.1
 * @date 2019-09-19
 *
 * @copyright Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information
 * Technology SIT. All rights reserved.
 *
 * @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 * BSD-3-Clause).
 */

#ifndef CBOR_UTIL_H
#define CBOR_UTIL_H

#include <tinycbor/cbor.h>

/**
 * @brief Returns a human-readable presentation of a CBOR type.
 *
 * @param type[in] The CBOR type.
 * @return The human-readable CBOR type.
 */
const char* cbor_type_string(const CborType type);

/**
 * @brief Indents a CBOR dump.
 * @see https://github.com/intel/tinycbor/blob/master/examples/simplereader.c
 */
void cbor_indent(int nesting_level);

/**
 * @brief Dumps bytes.
 * @see https://github.com/intel/tinycbor/blob/master/examples/simplereader.c
 */
void cbor_dumpbytes(const uint8_t* buf, size_t len);

/**
 * @brief Dumps a CBOR object recursively.
 * @see https://github.com/intel/tinycbor/blob/master/examples/simplereader.c
 */
CborError cbor_dumprecursive(CborValue* it, int nesting_level);

#endif /* CBOR_UTIL_H */
