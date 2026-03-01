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

static void _print_error(gptr_err_t err)
{
    EPRINTFARGS("Error: %s", gptr_err_to_string(err));
}

static void _print_success(const char *msg)
{
    WPRINTFARGS("%s", msg);
}

static gptr_err_t _do_init(void)
{
    gfx_clear_grey(0x1B);
    gfx_con_setpos(0, 0);
    return gptr_core_init();
}

void gptr_check()
{
    gptr_err_t res = _do_init();

    if (res == GPTR_OK)
        res = gptr_core_validate();

    if (res == GPTR_OK)
        _print_success("Passed!");
    else
        _print_error(res);

    EPRINTF("Press any key to continue.");
    btn_wait();
    gptr_core_deinit();
}

void gptr_restore()
{
    gptr_err_t res = _do_init();

    if (res != GPTR_OK)
        goto end_error;

    res = gptr_core_validate();

    if (res == GPTR_OK)
    {
        _print_success("No restore needed.");
        goto cleanup;
    }

    // Restore Primary GPT (includes MBR) if corrupted
    if (res == GPTR_ERR_MBR_BROKEN || res == GPTR_ERR_BACKUP_GPT_BROKEN)
    {
        res = gptr_storage_write_and_verify(0, PRIMARY_GPT_BLOCK,
                                            &g_core.primary_embedded->gpt,
                                            &g_core.primary_emmc->gpt);
        if (res != GPTR_OK)
        {
            EPRINTF("Primary GPT restore failed");
            goto end_error;
        }

        res = gptr_core_validate();
    }

    // Restore Backup GPT if corrupted
    if (res == GPTR_ERR_BACKUP_GPT_BROKEN)
    {
        res = gptr_storage_write_and_verify(g_core.backup_start_lba, BACKUP_GPT_BLOCK,
                                            &g_core.backup_embedded->gpt,
                                            &g_core.backup_emmc->gpt);

        if (res != GPTR_OK)
        {
            EPRINTF("Backup GPT restore failed");
            goto end_error;
        }

        res = gptr_core_validate();
    }

end_error:
    if (res == GPTR_OK)
        _print_success("Restore completed!");
    else
    {
        _print_error(res);
        EPRINTF("Restore failed!");
    }

cleanup:
    EPRINTF("Press any key to continue.");
    btn_wait();
    gptr_core_deinit();
}
