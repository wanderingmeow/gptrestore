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

#include "gptr.h"
#include <stddef.h>

gptr_err_t gptr_storage_init(void)
{
    if (!emmc_initialize(false))
        return GPTR_ERR_EMMC_INIT;

    if (!emmc_set_partition(EMMC_GPP))
        return GPTR_ERR_SWITCH_EMMC_GPP;

    const u32 emmc_sect_cnt = emmc_storage.sec_cnt;
    WPRINTFARGS("eMMC capacity: %d MiB",
                (u64)emmc_sect_cnt * EMMC_BLOCKSIZE / SZ_1M);

    if (emmc_sect_cnt != EMMC_32GB_GPP_SEC_CNT &&
        emmc_sect_cnt != EMMC_64GB_GPP_SEC_CNT)
        return GPTR_ERR_EMMC_UNSUPPORTED;

    g_core.emmc_64gb = (emmc_sect_cnt == EMMC_64GB_GPP_SEC_CNT);
    g_core.backup_start_lba = emmc_sect_cnt - BACKUP_GPT_BLOCK; // 0x747BFDF : 0x3A3DFDF

    return GPTR_OK;
}

gptr_err_t gptr_storage_read(u32 sector, u32 num_sects, void *out)
{
    if (out == NULL)
        return GPTR_ERR_INVALID_PARAM;

    if (!sdmmc_storage_read(&emmc_storage, sector, num_sects, out)) {
        EPRINTFARGS("Failed to read %d sectors from LBA 0x%06X",
                    num_sects, sector);
        return GPTR_ERR_EMMC_READ;
    }

    return GPTR_OK;
}

gptr_err_t gptr_storage_write(u32 sector, u32 num_sects, const void * const in)
{
    if (in == NULL)
        return GPTR_ERR_INVALID_PARAM;

    if (!sdmmc_storage_write(&emmc_storage, sector, num_sects, (void *)in)) {
        EPRINTFARGS("Failed to write %d sectors to LBA 0x%06X",
                    num_sects, sector);
        return GPTR_ERR_EMMC_WRITE;
    }

    return GPTR_OK;
}

gptr_err_t gptr_storage_write_and_verify(u32 sector, u32 num_sects, const void * const in, void *out)
{
    if (in == NULL || out == NULL)
        return GPTR_ERR_INVALID_PARAM;

    gptr_err_t res = gptr_storage_write(sector, num_sects, in);
    if (res != GPTR_OK)
        return res;

    res = gptr_storage_read(sector, num_sects, out);
    if (res != GPTR_OK)
        return res;

    const size_t total_bytes = (size_t)num_sects * EMMC_BLOCKSIZE;
    if (memcmp(out, in, total_bytes))
    {
        EPRINTFARGS("Write verification failed at LBA 0x%06X (%d sectors)",
                    sector, num_sects);
        return GPTR_ERR_EMMC_VERIFY;
    }

    return GPTR_OK;
}