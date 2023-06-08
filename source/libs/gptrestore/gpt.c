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

#include "gpt.h"

#include "gpt_table.inc"

gptrestore_info g_info =
{
    .primary_embedded = NULL,
    .backup_embedded = NULL,
    .primary_emmc = NULL,
    .backup_emmc = NULL,
    .mem_block_allocated = false,
    .initialized = false,
    .emmc_64gb = false,
    .backup_start_lba = 0,
};

void print_guid(u8* guid)
{
    size_t separators[] = {4, 2, 2, 2, SIZE_MAX};
    size_t* sep_ptr = &separators[0];
    for (size_t i = 0; i < 0x10; i++) {
        gfx_printf("%02X", guid[i]);
        if (*sep_ptr > 0)
            (*sep_ptr)--;
        if (*sep_ptr == 0)
        {
            gfx_putc('-');
            sep_ptr++;
        }
    }
    gfx_putc('\n');
};

int emmc_check()
{
    if (!emmc_initialize(false))
    {
        EPRINTF("Failed to init eMMC!");
        return -1;
    }

    if (!emmc_set_partition(EMMC_GPP))
    {
        EPRINTF("Failed to switch to eMMC GPP partition!");
        return -2;
    }

    const u32 emmcSectorCnt = emmc_storage.sec_cnt;
    const u32 emmcMib = (u64)emmcSectorCnt * EMMC_BLOCKSIZE / SZ_1M;
    WPRINTFARGS("eMMC capacity: %d MiB", emmcMib);
    WPRINTFARGS("Sect: 0x%06X", emmcSectorCnt);

    if (emmcSectorCnt != EMMC_32GB_GPP_SEC_CNT && emmcSectorCnt != EMMC_64GB_GPP_SEC_CNT)
    {
        EPRINTF("Only 32GB and 64GB eMMC are supported!");
        return -3;
    }

    if (emmcSectorCnt == EMMC_64GB_GPP_SEC_CNT)
        g_info.emmc_64gb = true;

    g_info.backup_start_lba = emmcSectorCnt - BACKUP_GPT_BLOCK; // 0x747BFDF : 0x3A3DFDF

    return 0;
};

int init_gptrestore()
{
    gfx_clear_grey(0x1B);
    gfx_con_setpos(0, 0);

    if (g_info.initialized)
        return 0;

    // Memory blocks allocation
    memset(&g_info, 0, sizeof(g_info));
    g_info.primary_embedded = calloc(1, sizeof(table_info_t));
    g_info.backup_embedded  = calloc(1, sizeof(table_info_t));
    g_info.primary_emmc     = calloc(1, sizeof(table_info_t));
    g_info.backup_emmc      = calloc(1, sizeof(table_info_t));
    g_info.mem_block_allocated = true;
    g_info.primary_embedded->type   = GPT_TYPE_PRIMARY;
    g_info.backup_embedded->type    = GPT_TYPE_BACKUP;
    g_info.primary_emmc->type   = GPT_TYPE_PRIMARY;
    g_info.backup_emmc->type    = GPT_TYPE_BACKUP;

    // Check eMMC connection
    if (emmc_check())
        goto failed;

    if (!sdmmc_storage_read(&emmc_storage, 0, PRIMARY_GPT_BLOCK, &(g_info.primary_emmc->primary_gpt)))
    {
        EPRINTFARGS("Cannot read %d sectors from 0x%06X!", PRIMARY_GPT_BLOCK, 0);
        goto failed;
    }

    if (!sdmmc_storage_read(&emmc_storage, g_info.backup_start_lba, BACKUP_GPT_BLOCK, &(g_info.backup_emmc->backup_gpt)))
    {
        EPRINTFARGS("Cannot read %d sectors from 0x%06X!", BACKUP_GPT_BLOCK, g_info.backup_start_lba);
        goto failed;
    }

    // Read GPT Disk GUID from eMMC
    u8* disk_guid_emmc_primary = g_info.primary_emmc->primary_gpt.gpt_section.header.disk_guid;
    u8* disk_guid_emmc_backup  = g_info.backup_emmc->backup_gpt.header.disk_guid;
    size_t disk_guid_size = sizeof(g_info.primary_emmc->primary_gpt.gpt_section.header.disk_guid);

    memcpy(g_info.disk_guid_emmc, disk_guid_emmc_primary, disk_guid_size);
    WPRINTF("eMMC Disk GUID - Primary GPT Table:\n");
    print_guid(disk_guid_emmc_primary);
    WPRINTF("eMMC Disk GUID - Backup GPT Table:\n");
    print_guid(disk_guid_emmc_backup);

    if (memcmp(disk_guid_emmc_primary, disk_guid_emmc_backup, disk_guid_size))
    {
        WPRINTF("Mismatched!");
        WPRINTF("Use Backup GPT Table GUID instead!");
        memcpy(g_info.disk_guid_emmc, disk_guid_emmc_backup, disk_guid_size);
    }

    // Extract common GPT Table from embedded lz4
    if (PRIMARY_GPT_SIZE != LZ4_decompress_safe(_common_mbr_main_gpt, (char *)&(g_info.primary_embedded->primary_gpt), sizeof(_common_mbr_main_gpt), sizeof(primary_gpt_t))) {
        EPRINTF("Failed to decompress LZ4!");
        goto failed;
    }

    u64 backup_gpt_header_lba = emmc_storage.sec_cnt - 1;   // 0x747BFFF : 0x3A3DFFF
    u64 last_usable_lba = g_info.backup_start_lba - 1;      // 0x747BFDE : 0x3A3DFDE

    u64 user_gpp_lba_end = g_info.emmc_64gb ? 0x733BFFF : 0x393BFFF;

    // Set up embedded Primary GPT Table
    gpt_t* primary_embedded = &(g_info.primary_embedded->primary_gpt.gpt_section);
    primary_embedded->header.alt_lba = backup_gpt_header_lba;
    primary_embedded->header.last_use_lba = last_usable_lba;
    memcpy(primary_embedded->header.disk_guid, g_info.disk_guid_emmc, disk_guid_size);
    primary_embedded->entries[USER_GPP_IDX].lba_end = user_gpp_lba_end;

    primary_embedded->header.part_ents_crc32 = crc32_calc(0, (const u8 *)primary_embedded->entries, sizeof(gpt_entry_t) * primary_embedded->header.num_part_ents);
    primary_embedded->header.crc32 = 0;
    primary_embedded->header.crc32 = crc32_calc(0, (const u8 *)&primary_embedded->header, primary_embedded->header.size);
    g_info.primary_embedded->is_crc_validated = true;

    // Set up embedded Backup GPT Table
    backup_gpt_t* backup_embedded = &(g_info.backup_embedded->backup_gpt);
    memcpy(&backup_embedded->header, &primary_embedded->header, sizeof(gpt_header_t));
    memcpy(backup_embedded->entries, primary_embedded->entries, sizeof(backup_gpt_t) - sizeof(gpt_header_t));

    backup_embedded->header.my_lba = primary_embedded->header.alt_lba;
    backup_embedded->header.alt_lba = primary_embedded->header.my_lba;
    backup_embedded->header.part_ent_lba = g_info.backup_start_lba;

    backup_embedded->header.part_ents_crc32 = primary_embedded->header.part_ents_crc32;
    backup_embedded->header.crc32 = 0;
    backup_embedded->header.crc32 = crc32_calc(0, (const u8 *)&backup_embedded->header, backup_embedded->header.size);
    g_info.backup_embedded->is_crc_validated = true;

    g_info.initialized = true;

    return 0;

failed:
    EPRINTF("Failed to initialize GPT Restore!\n");
    return -1;
};

void clear_gptrestore()
{
    if (!g_info.mem_block_allocated)
        return;

    free(g_info.primary_embedded);
    free(g_info.backup_embedded);
    free(g_info.primary_emmc);
    free(g_info.backup_emmc);
};

int restore_gpt_to_emmc(u32 start_sect, u32 num_sects, u8* in_buf, u8* out_buf)
{
    if (!sdmmc_storage_write(&emmc_storage, start_sect, num_sects, in_buf))
    {
        EPRINTFARGS("Cannot write %d sectors from 0x%06X!", num_sects, start_sect);
        return -1;
    }

    size_t size = EMMC_BLOCKSIZE * num_sects;
    if (!sdmmc_storage_read(&emmc_storage, start_sect, num_sects, out_buf))
    {
        EPRINTFARGS("Cannot read %d sectors from 0x%06X!", num_sects, start_sect);
        return -2;
    }

    if (memcmp(out_buf, in_buf, size))
    {
        EPRINTF("Write validation failed!");
        return -3;
    }

    return 0;
}

void run_check()
{
    if (init_gptrestore())
        goto failed;

    if (memcmp(&g_info.primary_embedded->primary_gpt.mbr_section, &g_info.primary_emmc->primary_gpt.mbr_section, sizeof(mbr_t)))
    {
        WPRINTF("MBR Table is broken");
        goto failed;
    }
    if (memcmp(&g_info.primary_embedded->primary_gpt.gpt_section, &g_info.primary_emmc->primary_gpt.gpt_section, sizeof(gpt_t)))
    {
        WPRINTF("Primary GPT Table is broken");
        goto failed;
    }
    if (memcmp(&g_info.backup_embedded->backup_gpt, &g_info.backup_emmc->backup_gpt, sizeof(backup_gpt_t)))
    {
        WPRINTF("Backup GPT Table is broken");
        goto failed;
    }
    WPRINTF("Passed! Press any key to continue.\n");
    btn_wait();
    return;

failed:
    EPRINTF("Error detected!  Press any key to continue.\n");
    btn_wait();
}

void run_restore()
{
    if (init_gptrestore())
        goto failed;

    if (restore_gpt_to_emmc(0, PRIMARY_GPT_BLOCK, (u8 *)&(g_info.primary_embedded->primary_gpt), (u8 *)&(g_info.primary_emmc->primary_gpt)))
    {
        EPRINTF("Failed to restore Primary GPT Table!");
        goto failed;
    }

    if (restore_gpt_to_emmc(g_info.backup_start_lba, BACKUP_GPT_BLOCK, (u8 *)&(g_info.backup_embedded->backup_gpt), (u8 *)&(g_info.backup_emmc->backup_gpt)))
    {
        EPRINTF("Failed to restore Backup GPT Table!");
        goto failed;
    }

    WPRINTF("Done! Press any key to continue.\n");
    btn_wait();
    return;

failed:
    EPRINTF("Error detected! Press any key to continue.\n");
    btn_wait();
};
