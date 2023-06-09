/*
* Copyright (c) 2019 CTCaer
*
* This program is free software; you can redistribute it and/or modify it
* under the terms and conditions of the GNU General Public License,
* version 2, as published by the Free Software Foundation.
*
* This program is distributed in the hope it will be useful, but WITHOUT
* ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
* FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
* more details.
*
* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _SPRINTF_H_
#define _SPRINTF_H_

#include <stdarg.h>

#include <utils/types.h>

void s_printf(char *out_buf, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void s_vprintf(char *out_buf, const char *fmt, va_list ap);

#endif