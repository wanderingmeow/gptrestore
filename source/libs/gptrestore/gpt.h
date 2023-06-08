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

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <bdk.h>

#define EMMC_32GB_GPP_SEC_CNT 0x3A3E000
#define EMMC_64GB_GPP_SEC_CNT 0x747C000

#define PRIMARY_GPT_BLOCK   (GPT_FIRST_LBA + GPT_NUM_BLOCKS)
#define PRIMARY_GPT_SIZE    PRIMARY_GPT_BLOCK * EMMC_BLOCKSIZE

#define BACKUP_GPT_BLOCK    GPT_NUM_BLOCKS
#define BACKUP_GPT_SIZE     BACKUP_GPT_BLOCK * EMMC_BLOCKSIZE

#define USER_GPP_IDX    11 - 1

typedef enum
{
    GPT_TYPE_PRIMARY = 0,
    GPT_TYPE_BACKUP,
} gpt_type_t;

typedef struct _primary_gpt_t
{
    mbr_t mbr_section;
    gpt_t gpt_section;
} primary_gpt_t;
static_assert(sizeof(primary_gpt_t) == PRIMARY_GPT_SIZE, "Wrong Primary GPT table size!");

typedef struct _backup_gpt_t
{
    gpt_entry_t entries[128];
    gpt_header_t header;
} backup_gpt_t;
static_assert(sizeof(backup_gpt_t) == BACKUP_GPT_SIZE, "Wrong Backup GPT table size!");

typedef struct _table_info_t
{
    gpt_type_t type;
    bool is_crc_validated;
    union {
        primary_gpt_t primary_gpt;
        backup_gpt_t  backup_gpt;
    };
} table_info_t;

typedef struct _gptrestore_info
{
    table_info_t* primary_embedded;
    table_info_t* backup_embedded;
    table_info_t* primary_emmc;
    table_info_t* backup_emmc;
    bool mem_block_allocated;
    bool initialized;
    bool emmc_64gb;
    u32 backup_start_lba;
    u8 disk_guid_emmc[0x10];
} gptrestore_info;

int init_gptrestore();
void run_check();
void run_restore();
void clear_gptrestore();
