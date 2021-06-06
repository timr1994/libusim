/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file help_functions.h
 * @author Tim Riemann (tim.riemann@sit.fraunhofer.de)
 * @brief
 * @version 0.1
 * @date 2020-04-29
 *
 * @copyright Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information
 * Technology SIT. All rights reserved.
 *
 * @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 * BSD-3-Clause).
 */

#ifndef HELP_FUNCTIONS_H
#define HELP_FUNCTIONS_H

#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

    ssize_t full_write(int fd, void *buf, size_t n);
    ssize_t full_read(int fd, void *buf, size_t n);


#ifdef __cplusplus
}
#endif

#endif /* HELP_FUNCTIONS_H */

