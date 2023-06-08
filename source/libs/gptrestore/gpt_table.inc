/*
 * Copyright (c) 2023 WanderingMeow
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

const char _common_mbr_main_gpt[] = {
  0x1f, 0x00, 0x01, 0x00, 0xff, 0xad, 0xef, 0x02, 0x00, 0xee, 0xff, 0xff,
  0xff, 0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xcd, 0x01, 0x1d,
  0xf7, 0x00, 0x55, 0xaa, 0x45, 0x46, 0x49, 0x20, 0x50, 0x41, 0x52, 0x54,
  0x00, 0x00, 0x01, 0x00, 0x5c, 0x3f, 0x00, 0x00, 0x52, 0x00, 0x00, 0x02,
  0x00, 0x04, 0x56, 0x00, 0x10, 0x22, 0x0d, 0x00, 0x0f, 0x66, 0x00, 0x08,
  0x11, 0x02, 0x1e, 0x00, 0x70, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x80,
  0x09, 0x00, 0x03, 0x02, 0x00, 0xf3, 0x11, 0x25, 0x9e, 0x10, 0x98, 0xe2,
  0x64, 0x95, 0x4c, 0x8a, 0x77, 0x41, 0x49, 0x16, 0xf5, 0xbc, 0xeb, 0xd3,
  0xe2, 0x61, 0x55, 0x30, 0x9b, 0x80, 0x4d, 0xa5, 0x46, 0x10, 0xeb, 0x7c,
  0x01, 0x51, 0xfc, 0x27, 0x00, 0x05, 0x02, 0x00, 0x04, 0x78, 0x00, 0xf5,
  0x00, 0x50, 0x00, 0x52, 0x00, 0x4f, 0x00, 0x44, 0x00, 0x49, 0x00, 0x4e,
  0x00, 0x46, 0x00, 0x4f, 0x20, 0x00, 0x0f, 0x02, 0x00, 0x1d, 0xff, 0x01,
  0xec, 0x6a, 0x05, 0xf3, 0x49, 0x54, 0x4c, 0x49, 0x9f, 0x2c, 0x5f, 0xdc,
  0xb7, 0x5b, 0x6e, 0x6e, 0x80, 0x00, 0x25, 0x1f, 0x46, 0x79, 0x00, 0x1d,
  0x03, 0x02, 0x00, 0xf3, 0x11, 0x36, 0xde, 0x65, 0x53, 0x1b, 0x91, 0xb4,
  0x4b, 0x8f, 0xf9, 0xaa, 0x1e, 0xbc, 0xd7, 0x39, 0x90, 0xb7, 0x72, 0x52,
  0x75, 0x5c, 0x44, 0xa3, 0x46, 0x98, 0x7b, 0xd4, 0x0e, 0x5d, 0x25, 0xeb,
  0x83, 0x27, 0x00, 0x05, 0x36, 0x01, 0x04, 0x00, 0x01, 0xf1, 0x18, 0x42,
  0x00, 0x43, 0x00, 0x50, 0x00, 0x4b, 0x00, 0x47, 0x00, 0x32, 0x00, 0x2d,
  0x00, 0x31, 0x00, 0x2d, 0x00, 0x4e, 0x00, 0x6f, 0x00, 0x72, 0x00, 0x6d,
  0x00, 0x61, 0x00, 0x6c, 0x00, 0x2d, 0x00, 0x4d, 0x00, 0x61, 0x00, 0x69,
  0x00, 0x6e, 0x3a, 0x00, 0x0f, 0x02, 0x00, 0x09, 0xff, 0x11, 0x7b, 0x71,
  0x55, 0x84, 0x2b, 0xbd, 0x62, 0x41, 0x84, 0x54, 0x91, 0x69, 0x52, 0x18,
  0xfc, 0x38, 0xd9, 0x04, 0xd9, 0xea, 0xa3, 0x61, 0xba, 0x4d, 0xbb, 0x11,
  0x6e, 0x51, 0x6a, 0x1f, 0x40, 0x93, 0xa0, 0x01, 0x0d, 0x05, 0xf8, 0x01,
  0x12, 0x1f, 0x66, 0x00, 0x04, 0xa0, 0x00, 0x0f, 0xa0, 0x01, 0x56, 0x12,
  0x20, 0x78, 0x00, 0x22, 0xff, 0x3f, 0x08, 0x00, 0x0f, 0x80, 0x00, 0x05,
  0x0f, 0xa0, 0x01, 0x46, 0x12, 0x40, 0x78, 0x00, 0x22, 0xff, 0x7f, 0x08,
  0x00, 0x04, 0x80, 0x00, 0x0f, 0xa0, 0x01, 0x55, 0x04, 0x4d, 0x03, 0x2f,
  0xff, 0xbf, 0x80, 0x00, 0x09, 0x00, 0x24, 0x02, 0x0a, 0x20, 0x02, 0x52,
  0x53, 0x00, 0x75, 0x00, 0x62, 0x33, 0x00, 0x0f, 0x02, 0x00, 0x0a, 0xf2,
  0x13, 0xa6, 0xc9, 0xd6, 0x8e, 0x48, 0x9c, 0x0b, 0x49, 0xbb, 0xeb, 0x00,
  0x1d, 0x17, 0xa4, 0xc0, 0xf7, 0x7a, 0x00, 0x78, 0xef, 0x2c, 0xd0, 0xf8,
  0x4b, 0x9b, 0xef, 0xb5, 0xb5, 0xcb, 0x3f, 0x2b, 0x76, 0x00, 0xc0, 0x3f,
  0x00, 0x04, 0x5c, 0x04, 0x0f, 0x00, 0x01, 0x03, 0x11, 0x33, 0x72, 0x00,
  0xdf, 0x61, 0x00, 0x66, 0x00, 0x65, 0x00, 0x4d, 0x00, 0x6f, 0x00, 0x64,
  0x00, 0x65, 0xa4, 0x02, 0x14, 0xf4, 0x11, 0x1c, 0x75, 0x99, 0x5e, 0xc9,
  0x56, 0xcc, 0x47, 0xaa, 0x30, 0xb6, 0x50, 0x39, 0x88, 0x89, 0x17, 0xd3,
  0x7c, 0xcb, 0xda, 0x24, 0x56, 0xd9, 0x41, 0x85, 0xbf, 0xdb, 0x61, 0xae,
  0x5a, 0x00, 0x96, 0x72, 0x00, 0x22, 0xff, 0x3f, 0x7a, 0x00, 0x02, 0x06,
  0x00, 0x0c, 0x80, 0x01, 0x1f, 0x34, 0x80, 0x00, 0x02, 0x0f, 0x04, 0x01,
  0x11, 0xf2, 0x13, 0xa2, 0xd9, 0x47, 0xc4, 0xb7, 0x24, 0x8a, 0x46, 0x98,
  0xc8, 0x59, 0x5c, 0xd0, 0x77, 0x16, 0x5a, 0x53, 0xf2, 0x58, 0x1c, 0x5e,
  0x94, 0x24, 0x4f, 0x95, 0xf2, 0x29, 0x09, 0x1b, 0x77, 0x5f, 0x56, 0x00,
  0x40, 0x72, 0x00, 0x22, 0xff, 0x7f, 0x08, 0x00, 0x02, 0x06, 0x00, 0x0c,
  0x80, 0x00, 0x91, 0x35, 0x00, 0x2d, 0x00, 0x52, 0x00, 0x65, 0x00, 0x70,
  0x96, 0x03, 0x1f, 0x72, 0xfc, 0x00, 0x14, 0x00, 0x02, 0x00, 0xfd, 0x01,
  0xa1, 0xe1, 0x86, 0x95, 0xa2, 0x3a, 0x90, 0x4c, 0x91, 0xb3, 0x2f, 0x4a,
  0x51, 0x95, 0xb4, 0xd2, 0xa0, 0x04, 0x12, 0x80, 0x72, 0x00, 0x22, 0xff,
  0xbf, 0x08, 0x00, 0x02, 0x06, 0x00, 0x0c, 0x80, 0x00, 0x1d, 0x36, 0x80,
  0x00, 0x0f, 0xfc, 0x00, 0x11, 0x00, 0x02, 0x00, 0xfd, 0x01, 0x6b, 0x9f,
  0x4f, 0xa4, 0xd3, 0x4e, 0x1f, 0x44, 0xa3, 0x4a, 0x56, 0xaa, 0xa1, 0x36,
  0xbc, 0x6a, 0x80, 0x00, 0x12, 0xc0, 0x72, 0x00, 0x30, 0xff, 0xbf, 0x03,
  0x2f, 0x00, 0x12, 0x00, 0x0e, 0x00, 0x90, 0x00, 0x00, 0x53, 0x00, 0x41,
  0x00, 0x46, 0x00, 0x45, 0x0b, 0x00, 0x0f, 0x02, 0x00, 0x2a, 0xfe, 0x01,
  0xf0, 0xcd, 0xb0, 0xac, 0x72, 0x4f, 0x2d, 0x43, 0xaa, 0x0d, 0x53, 0x88,
  0xc7, 0x33, 0xb2, 0x24, 0x80, 0x00, 0x02, 0x78, 0x00, 0x31, 0xff, 0xbf,
  0x53, 0x68, 0x00, 0x06, 0x80, 0x00, 0x91, 0x59, 0x00, 0x53, 0x00, 0x54,
  0x00, 0x45, 0x00, 0x4d, 0x18, 0x00, 0x0f, 0x02, 0x00, 0x25, 0xfe, 0x01,
  0x63, 0x7f, 0x77, 0x2b, 0x42, 0xe8, 0xaf, 0x47, 0x94, 0xc4, 0x25, 0xa7,
  0xf1, 0x8b, 0x22, 0x80, 0x80, 0x00, 0x02, 0x78, 0x00, 0x04, 0x08, 0x07,
  0x04, 0x80, 0x00, 0x7f, 0x55, 0x00, 0x53, 0x00, 0x45, 0x00, 0x52, 0x77,
  0x00, 0x25, 0x0f, 0x02, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xab, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00
};