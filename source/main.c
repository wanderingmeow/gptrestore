/*
 * Copyright (c) 2018 naehrwert
 *
 * Copyright (c) 2018-2023 CTCaer
 *
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

#include <string.h>
#include <stdlib.h>

#include <bdk.h>

#include "config.h"
#include "gfx/tui.h"
#include <ianos/ianos.h>
#include <libs/compr/blz.h>
#include <libs/fatfs/ff.h>

#include "libs/gptrestore/gpt.h"

hekate_config h_cfg;
boot_cfg_t __attribute__((section ("._boot_cfg"))) b_cfg;
const volatile ipl_ver_meta_t __attribute__((section ("._ipl_version"))) ipl_ver = {
	.magic = BL_MAGIC,
	.version = (BL_VER_MJ + '0') | ((BL_VER_MN + '0') << 8) | ((BL_VER_HF + '0') << 16),
	.rsvd0 = 0,
	.rsvd1 = 0
};

volatile nyx_storage_t *nyx_str = (nyx_storage_t *)NYX_STORAGE_ADDR;

// This is a safe and unused DRAM region for our payloads.
#define RELOC_META_OFF      0x7C
#define PATCHED_RELOC_SZ    0x94
#define PATCHED_RELOC_STACK 0x40007000
#define PATCHED_RELOC_ENTRY 0x40010000
#define EXT_PAYLOAD_ADDR    0xC0000000
#define RCM_PAYLOAD_ADDR    (EXT_PAYLOAD_ADDR + ALIGN(PATCHED_RELOC_SZ, 0x10))
#define COREBOOT_END_ADDR   0xD0000000
#define COREBOOT_VER_OFF    0x41
#define CBFS_DRAM_EN_ADDR   0x4003E000
#define  CBFS_DRAM_MAGIC    0x4452414D // "DRAM"

static void *coreboot_addr;

static void _reloc_patcher(u32 payload_dst, u32 payload_src, u32 payload_size)
{
	memcpy((u8 *)payload_src, (u8 *)IPL_LOAD_ADDR, PATCHED_RELOC_SZ);

	reloc_meta_t *relocator = (reloc_meta_t *)(payload_src + RELOC_META_OFF);

	relocator->start = payload_dst - ALIGN(PATCHED_RELOC_SZ, 0x10);
	relocator->stack = PATCHED_RELOC_STACK;
	relocator->end   = payload_dst + payload_size;
	relocator->ep    = payload_dst;

	if (payload_size == 0x7000)
	{
		memcpy((u8 *)(payload_src + ALIGN(PATCHED_RELOC_SZ, 0x10)), coreboot_addr, 0x7000); // Bootblock.
		*(vu32 *)CBFS_DRAM_EN_ADDR = CBFS_DRAM_MAGIC;
	}
}

static void _launch_payload(char *path, bool update, bool clear_screen)
{
	if (clear_screen)
		gfx_clear_grey(0x1B);
	gfx_con_setpos(0, 0);

	FIL fp;
	if (f_open(&fp, path, FA_READ))
	{
		gfx_con.mute = false;
		EPRINTFARGS("Payload file is missing!\n(%s)", path);

		goto out;
	}

	// Read and copy the payload to our chosen address
	void *buf;
	u32 size = f_size(&fp);

	if (size < 0x30000)
		buf = (void *)RCM_PAYLOAD_ADDR;
	else
	{
		coreboot_addr = (void *)(COREBOOT_END_ADDR - size);
		buf = coreboot_addr;
		if (h_cfg.t210b01)
		{
			f_close(&fp);

			gfx_con.mute = false;
			EPRINTF("Coreboot not allowed on Mariko!");

			goto out;
		}
	}

	if (f_read(&fp, buf, size, NULL))
	{
		f_close(&fp);

		goto out;
	}

	f_close(&fp);

	sd_end();

	if (size < 0x30000)
	{
		if (update)
			memcpy((u8 *)(RCM_PAYLOAD_ADDR + PATCHED_RELOC_SZ), &b_cfg, sizeof(boot_cfg_t)); // Transfer boot cfg.
		else
			_reloc_patcher(PATCHED_RELOC_ENTRY, EXT_PAYLOAD_ADDR, ALIGN(size, 0x10));

		hw_reinit_workaround(false, byte_swap_32(*(u32 *)(buf + size - sizeof(u32))));
	}
	else
	{
		_reloc_patcher(PATCHED_RELOC_ENTRY, EXT_PAYLOAD_ADDR, 0x7000);

		// Get coreboot seamless display magic.
		u32 magic = 0;
		char *magic_ptr = buf + COREBOOT_VER_OFF;
		memcpy(&magic, magic_ptr + strlen(magic_ptr) - 4, 4);
		hw_reinit_workaround(true, magic);
	}

	// Some cards (Sandisk U1), do not like a fast power cycle. Wait min 100ms.
	sdmmc_storage_init_wait_sd();

	void (*update_ptr)()      = (void *)RCM_PAYLOAD_ADDR;
	void (*ext_payload_ptr)() = (void *)EXT_PAYLOAD_ADDR;

	// Launch our payload.
	if (!update)
		(*ext_payload_ptr)();
	else
	{
		// Set updated flag to skip check on launch.
		EMC(EMC_SCRATCH0) |= EMC_HEKA_UPD;
		(*update_ptr)();
	}

out:
	if (!update)
	{
		gfx_con.mute = false;
		EPRINTF("Failed to launch payload!");
	}
}

static void _launch_payloads()
{
	u8 max_entries = 61;
	char *filelist = NULL;
	char *file_sec = NULL;
	char *dir = NULL;

	ment_t *ments = (ment_t *)malloc(sizeof(ment_t) * (max_entries + 3));

	gfx_clear_grey(0x1B);
	gfx_con_setpos(0, 0);

	if (!sd_mount())
	{
		free(ments);
		goto failed_sd_mount;
	}

	dir = (char *)malloc(256);
	memcpy(dir, "bootloader/payloads", 20);

	filelist = dirlist(dir, NULL, false, false);

	u32 i = 0;

	if (filelist)
	{
		// Build configuration menu.
		ments[0].type    = MENT_BACK;
		ments[0].caption = "Back";

		ments[1].type    = MENT_CHGLINE;

		u32 i_off = 2;

		if (!f_stat("atmosphere/reboot_payload.bin", NULL))
		{
			ments[i_off].type = INI_CHOICE;
			ments[i_off].caption = "atmosphere/reboot_payload.bin";
			ments[i_off].data = "atmosphere/reboot_payload.bin";
			i_off++;
		}

		while (true)
		{
			if (i > max_entries || !filelist[i * 256])
				break;
			ments[i + i_off].type    = INI_CHOICE;
			ments[i + i_off].caption = &filelist[i * 256];
			ments[i + i_off].data    = &filelist[i * 256];

			i++;
		}
	}

	if (i > 0)
	{
		memset(&ments[i + 2], 0, sizeof(ment_t));
		menu_t menu = { ments, "Choose a payload", 0, 0 };

		file_sec = (char *)tui_do_menu(&menu);

		if (!file_sec)
		{
			free(ments);
			free(dir);
			free(filelist);
			sd_end();

			return;
		}
	}
	else
		EPRINTF("No payloads found.");

	free(ments);
	free(filelist);

	if (file_sec)
	{
		memcpy(dir + strlen(dir), "/", 2);
		memcpy(dir + strlen(dir), file_sec, strlen(file_sec) + 1);

		_launch_payload(dir, false, true);
	}

failed_sd_mount:
	sd_end();
	free(dir);

	btn_wait();
}

static void _launch_hekate()
{
	if (!sd_mount())
		goto end;

	if (!f_stat("bootloader/update.bin", NULL))
		_launch_payload("bootloader/update.bin", false, true);

end:
	sd_end();
	btn_wait();
}

#define EXCP_EN_ADDR   0x4003FFFC
#define  EXCP_MAGIC       0x30505645 // "EVP0".
#define EXCP_TYPE_ADDR 0x4003FFF8
#define  EXCP_TYPE_RESET  0x545352   // "RST".
#define  EXCP_TYPE_UNDEF  0x464455   // "UDF".
#define  EXCP_TYPE_PABRT  0x54424150 // "PABT".
#define  EXCP_TYPE_DABRT  0x54424144 // "DABT".
#define  EXCP_TYPE_WDT    0x544457   // "WDT".
#define EXCP_LR_ADDR   0x4003FFF4

#define PSTORE_LOG_OFFSET 0x180000
#define PSTORE_RAM_SIG    0x43474244 // "DBGC".

power_state_t STATE_POWER_OFF           = POWER_OFF_RESET;
power_state_t STATE_REBOOT_RCM          = REBOOT_RCM;
power_state_t STATE_REBOOT_BYPASS_FUSES = REBOOT_BYPASS_FUSES;

ment_t ment_top[] = {
	MDEF_HANDLER("Check GPT table errors", run_check),
	MDEF_HANDLER("Restore GPT table", run_restore),
	MDEF_CAPTION("---------------", TXT_CLR_GREY_DM),
	MDEF_HANDLER("Payloads...",  _launch_payloads),
	MDEF_HANDLER("Reboot to hekate", _launch_hekate),
	MDEF_CAPTION("---------------", TXT_CLR_GREY_DM),
	MDEF_HANDLER_EX("Reboot (OFW)", &STATE_REBOOT_BYPASS_FUSES, power_set_state_ex),
	MDEF_HANDLER_EX("Reboot (RCM)", &STATE_REBOOT_RCM,          power_set_state_ex),
	MDEF_HANDLER_EX("Power off",    &STATE_POWER_OFF,           power_set_state_ex),
	MDEF_END()
};

menu_t menu_top = { ment_top, "GPT Restore 1.0.0", 0, 0 };

void disable_menu_item(ment_t *menu)
{
	menu->type = MENT_CAPTION;
	menu->color = 0xFF555555;
	menu->handler = NULL;
}

extern void pivot_stack(u32 stack_top);

void ipl_main()
{
	// Do initial HW configuration. This is compatible with consecutive reruns without a reset.
	hw_init();

	// Pivot the stack so we have enough space.
	pivot_stack(IPL_STACK_TOP);

	// Tegra/Horizon configuration goes to 0x80000000+, package2 goes to 0xA9800000, we place our heap in between.
	heap_init((void *)IPL_HEAP_START);

	// Set bootloader's default configuration.
	set_default_configuration();

	// Initialize display.
	display_init();

	// Mount SD Card.
	h_cfg.errors |= !sd_mount() ? ERR_SD_BOOT_EN : 0;

	// Initialize display window, backlight and gfx console.
	u32 *fb = display_init_framebuffer_pitch();
	gfx_init_ctxt(fb, 720, 1280, 720);
	gfx_con_init();

	display_backlight_pwm_init();
	//display_backlight_brightness(h_cfg.backlight, 1000);

	// Overclock BPMP.
	bpmp_clk_rate_set(h_cfg.t210b01 ? BPMP_CLK_DEFAULT_BOOST : BPMP_CLK_LOWER_BOOST);

	// Set ram to a freq that doesn't need periodic training.
	minerva_change_freq(FREQ_800);

	// Disable reboot to hekate option if no update.bin found.
	if (f_stat("bootloader/update.bin", NULL))
		disable_menu_item(&ment_top[4]);

	// Disable RCM on Mariko or patched consoles.
	if (h_cfg.t210b01 || h_cfg.rcm_patched)
		disable_menu_item(&ment_top[7]);

	while (true)
		tui_do_menu(&menu_top);

	clear_gptrestore();
	// Halt BPMP if we managed to get out of execution.
	while (true)
		bpmp_halt();
}
