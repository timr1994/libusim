/* SPDX-License-Identifier: BSD-3-Clause  */
/*  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  * 
 *  Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information Technology SIT.
 *  All rights reserved.
 *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  */
/*
 * 
 *  @file rand_help.h
 *  @author Tim Riemann<tim.riemann@sit.fraunhofer.de>
 *  @date 2020-05-22
 * 
 *  @copyright Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information Technology SIT. All rights reserved.
 * 
 *  @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 *  BSD-3-Clause)
 * 
 */


#ifndef RAND_HELP_H
#define RAND_HELP_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>     

#ifdef __cplusplus
extern "C" {
#endif
static char *rand_string(char *str, size_t size);
char* rand_string_alloc(size_t size);



#ifdef __cplusplus
}
#endif

#endif /* RAND_HELP_H */

