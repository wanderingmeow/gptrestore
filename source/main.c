/*
 * Copyright (c) 2018 naehrwert
 *
 * Copyright (c) 2018-2026 CTCaer
 *
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

#include <string.h>
#include <stdlib.h>

#include <bdk.h>

#include "config.h"
#include "gfx/logos.h"
#include "gfx/tui.h"
#include <ianos/ianos.h>
#include <libs/compr/blz.h>
#include <libs/fatfs/ff.h>

#include "libs/gptrestore/gpt.h"

hekate_config h_cfg;
boot_cfg_t __attribute__((section ("._boot_cfg"))) b_cfg;
const volatile ipl_ver_meta_t __attribute__((section ("._ipl_version"))) ipl_ver = {
	.magic             = BL_MAGIC,
	.version           = (BL_VER_MJ + '0') | ((BL_VER_MN + '0') << 8) | ((BL_VER_HF + '0') << 16) | ((BL_VER_RL) << 24),
	.rcfg.rsvd_flags   = 0,
	.rcfg.bclk_t210    = BPMP_CLK_LOWER_BOOST,
	.rcfg.bclk_t210b01 = BPMP_CLK_DEFAULT_BOOST
};

volatile nyx_storage_t *nyx_str = (nyx_storage_t *)NYX_STORAGE_ADDR;

// This is a safe and unused DRAM region for our payloads.
#define RELOC_META_OFF      0x7C
#define PATCHED_RELOC_SZ    0x94
#define VERSION_RCFG_OFF    0x120
#define PATCHED_RELOC_STACK 0x40007000
#define PATCHED_RELOC_ENTRY 0x40010000
#define EXT_PAYLOAD_ADDR    0xC0000000
#define RCM_PAYLOAD_ADDR    (EXT_PAYLOAD_ADDR + ALIGN(PATCHED_RELOC_SZ, 0x10))

static void _reloc_append(u32 payload_dst, u32 payload_src, u32 payload_size)
{
	memcpy((u8 *)payload_src, (u8 *)IPL_LOAD_ADDR, PATCHED_RELOC_SZ);

	volatile reloc_meta_t *relocator = (reloc_meta_t *)(payload_src + RELOC_META_OFF);

	relocator->start = payload_dst - ALIGN(PATCHED_RELOC_SZ, 0x10);
	relocator->stack = PATCHED_RELOC_STACK;
	relocator->end   = payload_dst + payload_size;
	relocator->ep    = payload_dst;
}

bool is_ipl_updated(void *buf, u32 size, const char *path, bool force)
{
	ipl_ver_meta_t *update_ft = (ipl_ver_meta_t *)(buf + PATCHED_RELOC_SZ + sizeof(boot_cfg_t));

	bool magic_valid  = update_ft->magic == ipl_ver.magic;
	bool force_update = force && !magic_valid;
	bool is_valid_old = magic_valid && (byte_swap_32(update_ft->version) < byte_swap_32(ipl_ver.version));

	// Check if newer version.
	if (!force && magic_valid)
	{
		// Copy reserved config.
		if (size && !is_valid_old && memcmp((u8 *)(IPL_LOAD_ADDR + VERSION_RCFG_OFF), (u8 *)(buf + VERSION_RCFG_OFF), sizeof(rsvd_cfg_t)))
		{
			memcpy((u8 *)(buf + VERSION_RCFG_OFF), (u8 *)(IPL_LOAD_ADDR + VERSION_RCFG_OFF), sizeof(rsvd_cfg_t));
			sd_save_to_file(buf, size, path);
		}

		if (byte_swap_32(update_ft->version) > byte_swap_32(ipl_ver.version))
			return false;
	}

	// Update if old or broken.
	if (force_update || is_valid_old)
	{
		boot_cfg_t tmp_cfg;
		reloc_meta_t *reloc = (reloc_meta_t *)(IPL_LOAD_ADDR + RELOC_META_OFF);

		// Reset boot storage configuration.
		memcpy(&tmp_cfg, (u8 *)(reloc->start + PATCHED_RELOC_SZ), sizeof(boot_cfg_t));
		memset((u8 *)(reloc->start + PATCHED_RELOC_SZ), 0, sizeof(boot_cfg_t));

		sd_save_to_file((u8 *)reloc->start, reloc->end - reloc->start, path);

		// Restore boot storage configuration.
		memcpy((u8 *)(reloc->start + PATCHED_RELOC_SZ), &tmp_cfg, sizeof(boot_cfg_t));
	}

	return true;
}

static void _launch_payload(char *path, bool update, bool clear_screen)
{
	if (clear_screen)
		gfx_clear_grey(0x1B);
	gfx_con_setpos(0, 0);

	// Read payload.
	u32 size = 0;
	void *buf = sd_file_read(path, &size);
	if (!buf)
	{
		gfx_con.mute = false;
		EPRINTFARGS("Payload file is missing!\n(%s)", path);

		goto out;
	}

	if (update && is_ipl_updated(buf, size, path, false))
		goto out;

	// Check if it safely fits IRAM.
	if (size > 0x30000)
	{
		gfx_con.mute = false;
		EPRINTF("Payload is too big!");

		goto out;
	}

	sd_end();

	// Copy the payload to our chosen address.
	memcpy((void *)RCM_PAYLOAD_ADDR, buf, size);

	// Append relocator or set config.
	void (*payload_ptr)();
	if (!update)
	{
		_reloc_append(PATCHED_RELOC_ENTRY, EXT_PAYLOAD_ADDR, ALIGN(size, 0x10));

		payload_ptr = (void *)EXT_PAYLOAD_ADDR;
	}
	else
	{
		memcpy((u8 *)(RCM_PAYLOAD_ADDR + PATCHED_RELOC_SZ), &b_cfg, sizeof(boot_cfg_t)); // Transfer boot cfg.

		// Set updated flag to skip check on launch.
		EMC(EMC_SCRATCH0) |= EMC_HEKA_UPD;

		payload_ptr = (void *)RCM_PAYLOAD_ADDR;
	}

	hw_deinit(false);

	// Launch our payload.
	(*payload_ptr)();

out:
	free(buf);
	if (!update)
	{
		gfx_con.mute = false;
		EPRINTF("Failed to launch payload!");
	}
}

static void _launch_payloads()
{
	u8 max_entries = 61;
	ment_t *ments  = NULL;
	char *file_sec = NULL;
	char *dir = NULL;
	dirlist_t *filelist = NULL;

	gfx_clear_grey(0x1B);
	gfx_con_setpos(0, 0);

	if (!sd_mount())
		goto failed_sd_mount;

	ments = (ment_t *)malloc(sizeof(ment_t) * (max_entries + 3));

	dir = (char *)malloc(256);
	memcpy(dir, "bootloader/payloads", 20);

	filelist = dirlist(dir, NULL, 0);

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
			if (i > max_entries || !filelist->name[i])
				break;
			ments[i + i_off].type    = INI_CHOICE;
			ments[i + i_off].caption = filelist->name[i];
			ments[i + i_off].data    = filelist->name[i];

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

	if (file_sec)
	{
		memcpy(dir + strlen(dir), "/", 2);
		memcpy(dir + strlen(dir), file_sec, strlen(file_sec) + 1);

		_launch_payload(dir, false, true);
	}

failed_sd_mount:
	free(dir);
	free(ments);
	free(filelist);
	sd_end();

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

static void _check_low_battery()
{
	if (h_cfg.devmode)
		goto out;

	int enough_battery;
	int batt_volt = 0;
	int charge_status = 0;

	// Enable charger in case it's disabled.
	bq24193_enable_charger();

	bq24193_get_property(BQ24193_ChargeStatus, &charge_status);
	max17050_get_property(MAX17050_AvgVCELL,   &batt_volt);

	enough_battery = charge_status ? 3300 : 3100;

	// If battery voltage is enough, exit.
	if (batt_volt > enough_battery || !batt_volt)
		goto out;

	// Prepare battery icon resources.
	u8 *battery_res = malloc(ALIGN(BATTERY_EMPTY_SIZE, SZ_4K));
	blz_uncompress_srcdest(battery_icons_blz, BATTERY_EMPTY_BLZ_SIZE, battery_res, BATTERY_EMPTY_SIZE);

	u8 *battery_icon     = malloc(0x95A); // 21x38x3
	u8 *charging_icon    = malloc(0x2F4); // 21x12x3
	u8 *no_charging_icon = zalloc(0x2F4);

	memcpy(charging_icon, battery_res, 0x2F4);
	memcpy(battery_icon, battery_res + 0x2F4, 0x95A);

	u32 battery_icon_y_pos  = 1280 - 16 - BATTERY_EMPTY_BATT_HEIGHT;
	u32 charging_icon_y_pos = 1280 - 16 - BATTERY_EMPTY_BATT_HEIGHT - 12 - BATTERY_EMPTY_CHRG_HEIGHT;
	free(battery_res);

	charge_status = !charge_status;

	u32 timer = 0;
	bool screen_on = false;
	while (true)
	{
		bpmp_msleep(250);

		// Refresh battery stats.
		int current_charge_status = 0;
		bq24193_get_property(BQ24193_ChargeStatus, &current_charge_status);
		max17050_get_property(MAX17050_AvgVCELL, &batt_volt);
		enough_battery = current_charge_status ? 3300 : 3100;

		// If battery voltage is enough, exit.
		if (batt_volt > enough_battery)
			break;

		// Refresh charging icon.
		if (screen_on && (charge_status != current_charge_status))
		{
			if (current_charge_status)
				gfx_set_rect_rgb(charging_icon,    BATTERY_EMPTY_WIDTH, BATTERY_EMPTY_CHRG_HEIGHT, 16, charging_icon_y_pos);
			else
				gfx_set_rect_rgb(no_charging_icon, BATTERY_EMPTY_WIDTH, BATTERY_EMPTY_CHRG_HEIGHT, 16, charging_icon_y_pos);
		}

		// Check if it's time to turn off display.
		if (screen_on && timer < get_tmr_ms())
		{
			// If battery is not charging, power off.
			if (!current_charge_status)
			{
				max77620_low_battery_monitor_config(true);

				// Handle full hw deinit and power off.
				power_set_state(POWER_OFF_RESET);
			}

			// If charging, just disable display.
			display_end();
			screen_on = false;
		}

		// Check if charging status changed or Power button was pressed and enable display.
		if ((charge_status != current_charge_status) || (btn_wait_timeout_single(0, BTN_POWER) & BTN_POWER))
		{
			if (!screen_on)
			{
				display_init();
				u32 *fb = display_init_window_a_pitch();
				gfx_init_ctxt(fb, 720, 1280, 720);

				gfx_set_rect_rgb(battery_icon,         BATTERY_EMPTY_WIDTH, BATTERY_EMPTY_BATT_HEIGHT, 16, battery_icon_y_pos);
				if (current_charge_status)
					gfx_set_rect_rgb(charging_icon,    BATTERY_EMPTY_WIDTH, BATTERY_EMPTY_CHRG_HEIGHT, 16, charging_icon_y_pos);
				else
					gfx_set_rect_rgb(no_charging_icon, BATTERY_EMPTY_WIDTH, BATTERY_EMPTY_CHRG_HEIGHT, 16, charging_icon_y_pos);

				display_backlight_pwm_init();
				display_backlight_brightness(100, 1000);

				screen_on = true;
			}

			timer = get_tmr_ms() + 15000;
		}

		// Check if forcefully continuing.
		if (btn_read_vol() == (BTN_VOL_UP | BTN_VOL_DOWN))
			break;

		charge_status = current_charge_status;
	}

	if (screen_on)
		display_end();

	free(battery_icon);
	free(charging_icon);
	free(no_charging_icon);

out:
	// Re enable Low Battery Monitor shutdown.
	max77620_low_battery_monitor_config(true);
}

static void _r2c_get_config_t210b01()
{
	rtc_reboot_reason_t rr;
	if (!max77620_rtc_get_reboot_reason(&rr))
		return;

	// Check if reason is actually set.
	if (rr.dec.reason != REBOOT_REASON_NOP)
	{
		// Clear boot storage.
		memset(&b_cfg, 0, sizeof(boot_cfg_t));

		// Enable boot storage.
		b_cfg.boot_cfg |= BOOT_CFG_AUTOBOOT_EN;
	}

	switch (rr.dec.reason)
	{
	case REBOOT_REASON_NOP:
		break;
	case REBOOT_REASON_REC:
		PMC(APBDEV_PMC_SCRATCH0) |= PMC_SCRATCH0_MODE_RECOVERY;
	case REBOOT_REASON_SELF:
		b_cfg.autoboot      = rr.dec.autoboot_idx;
		b_cfg.autoboot_list = rr.dec.autoboot_list;
		break;
	case REBOOT_REASON_MENU:
		break;
	case REBOOT_REASON_UMS:
		b_cfg.extra_cfg |= EXTRA_CFG_NYX_UMS;
		b_cfg.ums = rr.dec.ums_idx;
		break;
	case REBOOT_REASON_PANIC:
		PMC(APBDEV_PMC_SCRATCH37) = PMC_SCRATCH37_KERNEL_PANIC_MAGIC;
		break;
	}
}

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
	// Override DRAM ID if needed.
	if (ipl_ver.rcfg.rsvd_flags & RSVD_FLAG_DRAM_8GB)
		fuse_force_8gb_dramid();

	// Do initial HW configuration. This is compatible with consecutive reruns without a reset.
	hw_init();

	// Pivot the stack under IPL. (Only max 4KB is needed).
	pivot_stack(IPL_LOAD_ADDR);

	// Place heap at a place outside of L4T/HOS configuration and binaries.
	heap_init((void *)IPL_HEAP_START);

	// Set bootloader's default configuration.
	set_default_configuration();

	// Check if battery is enough.
	_check_low_battery();

	// Prep RTC regs for read. Needed for T210B01 R2C.
	max77620_rtc_prep_read();

	// Initialize display.
	display_init();

	// Overclock BPMP.
	bpmp_clk_rate_set(h_cfg.t210b01 ? ipl_ver.rcfg.bclk_t210b01 : ipl_ver.rcfg.bclk_t210);

	// Mount SD Card.
	h_cfg.errors |= !sd_mount() ? ERR_SD_BOOT_EN : 0;

	// Initialize display window, backlight and gfx console.
	u32 *fb = display_init_window_a_pitch();
	gfx_init_ctxt(fb, 720, 1280, 720);
	gfx_con_init();

	// Initialize backlight PWM.
	display_backlight_pwm_init();
	//display_backlight_brightness(h_cfg.backlight, 1000);

	// Get R2C config from RTC.
	if (h_cfg.t210b01)
		_r2c_get_config_t210b01();

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
