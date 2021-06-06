/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file cbor_util.c
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

// #include "cbor_util.h"

#include "cbor_util.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <tinycbor/cbor.h>


const char* cbor_type_string(const CborType type) {
	switch (type) {
	case CborIntegerType:
		return "CborIntegerType";
	case CborByteStringType:
		return "CborByteStringType";
	case CborTextStringType:
		return "CborTextStringType";
	case CborArrayType:
		return "CborArrayType";
	case CborMapType:
		return "CborMapType";
	case CborTagType:
		return "CborTagType";
	case CborSimpleType:
		return "CborSimpleType";
	case CborBooleanType:
		return "CborBooleanType";
	case CborNullType:
		return "CborNullType";
	case CborUndefinedType:
		return "CborUndefinedType";
	case CborHalfFloatType:
		return "CborHalfFloatType";
	case CborFloatType:
		return "CborFloatType";
	case CborDoubleType:
		return "CborDoubleType";
	case CborInvalidType:
		return "CborInvalidType";
	default:
		return "UNKNOWN";
	}
}

void cbor_indent(int nesting_level) {
	while (nesting_level--) {
		printf("  ");
	}
}

void cbor_dumpbytes(const uint8_t* buf, size_t len) {
	while (len--) {
		printf("%02X ", *buf++);
	}
}

CborError cbor_dumprecursive(CborValue* it, int nesting_level) {
	while (!cbor_value_at_end(it)) {
		CborError err;
		CborType type = cbor_value_get_type(it);

		cbor_indent(nesting_level);
		switch (type) {
		case CborArrayType:
		case CborMapType: {
			// recursive type
			CborValue recursed;
			assert(cbor_value_is_container(it));
			puts(type == CborArrayType ? "Array[" : "Map[");
			err = cbor_value_enter_container(it, &recursed);
			if (err)
				return err; // parse error
			err = cbor_dumprecursive(&recursed, nesting_level + 1);
			if (err)
				return err; // parse error
			err = cbor_value_leave_container(it, &recursed);
			if (err)
				return err; // parse error
			cbor_indent(nesting_level);
			puts("]");
			continue;
		}

		case CborIntegerType: {
			int64_t val;
			cbor_value_get_int64(it, &val); // can't fail
			printf("%lld\n", (long long)val);
			break;
		}

		case CborByteStringType: {
			uint8_t* buf;
			size_t n;
			err = cbor_value_dup_byte_string(it, &buf, &n, it);
			if (err)
				return err; // parse error
			cbor_dumpbytes(buf, n);
			puts("");
			free(buf);
			continue;
		}

		case CborTextStringType: {
			char* buf;
			size_t n;
			err = cbor_value_dup_text_string(it, &buf, &n, it);
			if (err)
				return err; // parse error
			puts(buf);
			free(buf);
			continue;
		}

		case CborTagType: {
			CborTag tag;
			cbor_value_get_tag(it, &tag); // can't fail
			printf("Tag(%lld)\n", (long long)tag);
			break;
		}

		case CborSimpleType: {
			uint8_t type;
			cbor_value_get_simple_type(it, &type); // can't fail
			printf("simple(%u)\n", type);
			break;
		}

		case CborNullType:
			puts("null");
			break;

		case CborUndefinedType:
			puts("undefined");
			break;

		case CborBooleanType: {
			bool val;
			cbor_value_get_boolean(it, &val); // can't fail
			puts(val ? "true" : "false");
			break;
		}

		case CborDoubleType: {
			double val;
			if (false) {
				float f;
			case CborFloatType:
				cbor_value_get_float(it, &f);
				val = f;
			} else {
				cbor_value_get_double(it, &val);
			}
			printf("%g\n", val);
			break;
		}
		case CborHalfFloatType: {
			uint16_t val;
			cbor_value_get_half_float(it, &val);
			printf("__f16(%04x)\n", val);
			break;
		}

		case CborInvalidType:
			assert(false); // can't happen
			break;
		}

		err = cbor_value_advance_fixed(it);
		if (err)
			return err;
	}
	return CborNoError;
}