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
#include "gpt_table.inc"
#include <stddef.h>

gpt_core_state_t g_core = {};

const char* gptr_err_to_string(gptr_err_t err)
{
    switch (err)
    {
        case GPTR_OK:                   return "OK";
        case GPTR_ERR_EMMC_INIT:        return "eMMC initialization failed";
        case GPTR_ERR_SWITCH_EMMC_GPP:  return "Failed to switch to eMMC GPP partition";
        case GPTR_ERR_EMMC_UNSUPPORTED: return "Only 32GB and 64GB eMMC are supported";
        case GPTR_ERR_EMMC_READ:        return "Failed to read from eMMC";
        case GPTR_ERR_EMMC_WRITE:       return "Failed to write to eMMC";
        case GPTR_ERR_EMMC_VERIFY:      return "eMMC write verification failed";
        case GPTR_ERR_DECOMPRESS:       return "LZ4 decompression failed";
        case GPTR_ERR_CRC_MISMATCH:     return "CRC mismatch detected";
        case GPTR_ERR_MBR_BROKEN:       return "MBR table is broken";
        case GPTR_ERR_PRIMARY_GPT_BROKEN:   return "Primary GPT table is broken";
        case GPTR_ERR_BACKUP_GPT_BROKEN:    return "Backup GPT table is broken";
        case GPTR_ERR_INVALID_PARAM:    return "Invalid parameter";
        case GPTR_ERR_NO_MEMORY:        return "Memory allocation failed";
        default:                        return "Unknown error";
    }
}

static void _print_guid(const u8* guid)
{
    if (guid == NULL) return;

    // GUID format: 8-4-4-4-12 hex digits (16 bytes total)
    for (size_t i = 0; i < 16; i++)
    {
        gfx_printf("%02X", guid[i]);
        if (i == 3 || i == 5 || i == 7 || i == 9)
            gfx_putc('-');
    }
    gfx_putc('\n');
}

static u32 _calc_gpt_crc32(const void *data, size_t len)
{
    return crc32_calc(0, (const u8 *)data, len);
}

static gptr_err_t _setup_embedded_gpt(void)
{
    if (!g_core.primary_embedded)
    {
        g_core.primary_embedded = calloc(1, sizeof(primary_gpt_info_t));
        if (!g_core.primary_embedded)
            return GPTR_ERR_NO_MEMORY;
    }
    if (!g_core.backup_embedded)
    {
        g_core.backup_embedded  = calloc(1, sizeof(backup_gpt_info_t));
        if (!g_core.backup_embedded)
            return GPTR_ERR_NO_MEMORY;
    }

    // Decompress common GPT Table from embedded LZ4 data
    int decomp_size = LZ4_decompress_safe(
        _common_mbr_main_gpt,
        (char*)&g_core.primary_embedded->gpt,
        sizeof(_common_mbr_main_gpt),
        sizeof(primary_gpt_t)
    );
    if (decomp_size != PRIMARY_GPT_SIZE)
        return GPTR_ERR_DECOMPRESS;

    // Calculate based on detected eMMC size
    const u32 emmc_sectors = emmc_storage.sec_cnt;
    const u64 backup_gpt_header_lba = emmc_sectors - 1;         // 0x747BFFF : 0x3A3DFFF
    const u64 last_usable_lba = g_core.backup_start_lba - 1;    // 0x747BFDE : 0x3A3DFDE
    const u32 user_gpp_lba_end = g_core.emmc_64gb ? USER_GPP_END_64GB : USER_GPP_END_32GB;

    // Reconstruct embedded Primary GPT
    primary_gpt_t * const primary = &g_core.primary_embedded->gpt;
    gpt_t * const gpt = &primary->gpt_section;

    gpt->header.alt_lba = backup_gpt_header_lba;
    gpt->header.last_use_lba = last_usable_lba;

    memcpy(gpt->header.disk_guid, g_core.disk_guid, sizeof(gpt->header.disk_guid));

    gpt->entries[USER_GPP_IDX].lba_end = user_gpp_lba_end;

    const size_t gpt_entries_size = sizeof(gpt_entry_t) * gpt->header.num_part_ents;
    gpt->header.part_ents_crc32 = _calc_gpt_crc32(gpt->entries, gpt_entries_size);
    gpt->header.crc32 = 0;
    gpt->header.crc32 = _calc_gpt_crc32(&gpt->header, gpt->header.size);
    g_core.primary_embedded->is_crc_validated = true;

    // Reconstruct embedded Backup GPT
    backup_gpt_t * const backup = &g_core.backup_embedded->gpt;

    memcpy(&backup->header, &gpt->header, sizeof(gpt_header_t));
    memcpy(backup->entries, gpt->entries, sizeof(backup->entries));

    static_assert(sizeof(backup->entries) == sizeof(backup_gpt_t) - sizeof(gpt_header_t), "Invalid Size");

    backup->header.my_lba = gpt->header.alt_lba;
    backup->header.alt_lba = gpt->header.my_lba;
    backup->header.part_ent_lba = g_core.backup_start_lba;
    backup->header.part_ents_crc32 = gpt->header.part_ents_crc32;

    backup->header.crc32 = 0;
    backup->header.crc32 = _calc_gpt_crc32(&backup->header, backup->header.size);
    g_core.backup_embedded->is_crc_validated = true;

    return GPTR_OK;
}

static bool _is_emmc_inited(void) {
    return g_core.backup_start_lba != 0;
}

static bool _is_core_inited(void)
{
    return _is_emmc_inited()
        && g_core.primary_embedded && g_core.backup_embedded
        && g_core.primary_emmc && g_core.backup_emmc;
}

gptr_err_t gptr_core_init(void)
{
    if (_is_core_inited())
        return GPTR_OK;

    gptr_err_t res = GPTR_OK;

    // Phase 1: Initialize storage
    if (!_is_emmc_inited())
        res = gptr_storage_init();

    if (res != GPTR_OK)
        return res;

    // Phase 2: Read Primary GPT
    if (!g_core.primary_emmc)
    {
        g_core.primary_emmc = calloc(1, sizeof(primary_gpt_info_t));
        if (!g_core.primary_emmc)
            return GPTR_ERR_NO_MEMORY;
    }

    primary_gpt_t *primary_gpt = &g_core.primary_emmc->gpt;
    res = gptr_storage_read(0x0, PRIMARY_GPT_BLOCK, primary_gpt);
    if (res != GPTR_OK)
        return res;

    memcpy(g_core.disk_guid, primary_gpt->gpt_section.header.disk_guid, sizeof(g_core.disk_guid));
    WPRINTF("eMMC Disk GUID - Primary GPT Table:");
    _print_guid(g_core.disk_guid);

    // Phase 3: Read Backup GPT
    if (!g_core.backup_emmc)
    {
        g_core.backup_emmc = calloc(1, sizeof(backup_gpt_info_t));
        if (!g_core.backup_emmc)
            return GPTR_ERR_NO_MEMORY;
    }

    res = gptr_storage_read(g_core.backup_start_lba, BACKUP_GPT_BLOCK, &g_core.backup_emmc->gpt);
    if (res != GPTR_OK)
        return res;

    const u8 *backup_guid  = g_core.backup_emmc->gpt.header.disk_guid;
    WPRINTF("eMMC Disk GUID - Backup GPT Table:");
    _print_guid(backup_guid);

    // Verify GUID
    if (memcmp(g_core.disk_guid, backup_guid, sizeof(g_core.disk_guid)))
    {
        WPRINTF("GUID Mismatched Detected! Using Backup GPT GUID.");
        memcpy(g_core.disk_guid, backup_guid, sizeof(g_core.disk_guid));
    }

    // Phase 4: Setup embedded GPT
    res = _setup_embedded_gpt();

    return res;
}

void gptr_core_deinit(void)
{
    memset(g_core.disk_guid, 0, sizeof(g_core.disk_guid));

    if (g_core.primary_embedded)
    {
        free(g_core.primary_embedded);
        g_core.primary_embedded = NULL;
    }
    if (g_core.backup_embedded)
    {
        free(g_core.backup_embedded);
        g_core.backup_embedded = NULL;
    }
    if (g_core.primary_emmc)
    {
        free(g_core.primary_emmc);
        g_core.primary_emmc = NULL;
    }
    if (g_core.backup_emmc)
    {
        free(g_core.backup_emmc);
        g_core.backup_emmc = NULL;
    }
}

gptr_err_t gptr_core_validate(void)
{
    if (memcmp(&g_core.primary_embedded->gpt.mbr_section,
               &g_core.primary_emmc    ->gpt.mbr_section,
               sizeof(mbr_t)))
        return GPTR_ERR_MBR_BROKEN;

    if (memcmp(&g_core.primary_embedded->gpt.gpt_section,
               &g_core.primary_emmc    ->gpt.gpt_section,
               sizeof(gpt_t)))
        return GPTR_ERR_PRIMARY_GPT_BROKEN;

    if (memcmp(&g_core.backup_embedded->gpt,
               &g_core.backup_emmc    ->gpt,
               sizeof(backup_gpt_t)))
        return GPTR_ERR_BACKUP_GPT_BROKEN;

    return GPTR_OK;
}
