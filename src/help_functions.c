/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2021, Tim Riemann & Michael Eckel @ Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file help_functions.c
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

#include "help_functions.h"

ssize_t full_write(int fd, void *buf, size_t n) {
    ssize_t writen = 0;
    ssize_t rc = 0;
    while (writen < n) {
        rc = write(fd, buf + writen, n - writen);
        if (rc <= 0) {
            return rc;
        } else {
            writen += rc;
        }
    }
    return n;

}

ssize_t full_read(int fd, void *buf, size_t n) {
    ssize_t readed = 0;
    ssize_t rc = 0;
    while (readed < n) {
        rc = read(fd, buf + readed, n - readed);
        if (rc <= 0) {
            return rc;
        } else {
            readed += rc;
        }
    }
    return n;
}