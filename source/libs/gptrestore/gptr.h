/*
 * Copyright (c) 2026 WanderingMeow
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

#ifndef GPTR_H
#define GPTR_H

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <bdk.h>

#include <libs/compr/lz4.h>
#include <storage/mbr_gpt.h>

#define EMMC_32GB_GPP_SEC_CNT 0x3A3E000
#define EMMC_64GB_GPP_SEC_CNT 0x747C000

// GPT layout constants
#define GPT_NUM_ENTRIES     128
#define PRIMARY_GPT_BLOCK   (GPT_FIRST_LBA + GPT_NUM_BLOCKS)        // 34
#define PRIMARY_GPT_SIZE    (PRIMARY_GPT_BLOCK * EMMC_BLOCKSIZE)    // 34 * 512 B = 17 KiB
#define BACKUP_GPT_BLOCK    GPT_NUM_BLOCKS                          // 33
#define BACKUP_GPT_SIZE     (BACKUP_GPT_BLOCK * EMMC_BLOCKSIZE)     // 33 * 512 B = 16.5 KiB
#define USER_GPP_IDX        (11 - 1)
#define USER_GPP_END_64GB   0x733BFFF
#define USER_GPP_END_32GB   0x393BFFF

typedef struct
{
    mbr_t mbr_section;
    gpt_t gpt_section;
} primary_gpt_t;
static_assert(sizeof(primary_gpt_t) == PRIMARY_GPT_SIZE, "Wrong Primary GPT table size!");

typedef struct
{
    gpt_entry_t entries[GPT_NUM_ENTRIES];
    gpt_header_t header;
} backup_gpt_t;
static_assert(sizeof(backup_gpt_t) == BACKUP_GPT_SIZE, "Wrong Backup GPT table size!");

typedef struct
{
    bool is_crc_validated;
    primary_gpt_t gpt;
} primary_gpt_info_t;

typedef struct
{
    bool is_crc_validated;
    backup_gpt_t gpt;
} backup_gpt_info_t;

typedef enum
{
    GPTR_OK = 0,
    GPTR_ERR_EMMC_INIT = -1,
    GPTR_ERR_SWITCH_EMMC_GPP = -2,
    GPTR_ERR_EMMC_UNSUPPORTED = -3,
    GPTR_ERR_EMMC_READ = -4,
    GPTR_ERR_EMMC_WRITE = -5,
    GPTR_ERR_EMMC_VERIFY = -6,
    GPTR_ERR_DECOMPRESS = -7,
    GPTR_ERR_CRC_MISMATCH = -8,
    GPTR_ERR_MBR_BROKEN = -9,
    GPTR_ERR_PRIMARY_GPT_BROKEN = -10,
    GPTR_ERR_BACKUP_GPT_BROKEN = -11,
    GPTR_ERR_INVALID_PARAM = -12,
    GPTR_ERR_NO_MEMORY = -13,
} gptr_err_t;

typedef struct
{
    bool emmc_64gb;
    u32  backup_start_lba;
    u8   disk_guid[16];
    primary_gpt_info_t  *primary_embedded;
    backup_gpt_info_t   *backup_embedded;
    primary_gpt_info_t  *primary_emmc;
    backup_gpt_info_t   *backup_emmc;
} gpt_core_state_t;

extern gpt_core_state_t g_core;

const char* gptr_err_to_string(gptr_err_t err);

gptr_err_t gptr_core_init(void);
void gptr_core_deinit(void);
gptr_err_t gptr_core_validate(void);

gptr_err_t gptr_storage_init(void);
gptr_err_t gptr_storage_read(u32 sector, u32 num_sectors, void *out);
gptr_err_t gptr_storage_write(u32 sector, u32 num_sects, const void * const in);
gptr_err_t gptr_storage_write_and_verify(u32 sector, u32 num_sects, const void * const in, void *out);

// UI entry points
void gptr_check();
void gptr_restore();

#endif
