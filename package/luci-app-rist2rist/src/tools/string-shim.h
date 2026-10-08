/* librist. Copyright © 2026 SipRadius LLC. All right reserved.
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef LIBRIST_TOOLS_STRING_SHIM_H
#define LIBRIST_TOOLS_STRING_SHIM_H

#include <string.h>

#if defined(_WIN32) || defined(_WIN64)
/* Microsoft's CRT does not ship the C99 strtok_r; the equivalent is
 * strtok_s. Same signature, same semantics. */
#define strtok_r strtok_s
#endif

#endif
