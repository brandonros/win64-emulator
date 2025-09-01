/*
SystemParametersInfoA function (winuser.h)
03/27/2024
 Important

Some information relates to a prerelease product which may be substantially modified before it's commercially released. Microsoft makes no warranties, express or implied, with respect to the information provided here.

Retrieves or sets the value of one of the system-wide parameters. This function can also update the user profile while setting a parameter.

Syntax
C++

Copy
BOOL SystemParametersInfoA(
  [in]      UINT  uiAction,
  [in]      UINT  uiParam,
  [in, out] PVOID pvParam,
  [in]      UINT  fWinIni
);
*/

use unicorn_engine::{Unicorn, RegisterX86};
use crate::emulation::memory;
use crate::winapi;

// Common SPI actions
const SPI_GETBEEP: u32 = 0x0001;
const SPI_GETMOUSE: u32 = 0x0003;
const SPI_GETKEYBOARDSPEED: u32 = 0x000A;
const SPI_GETKEYBOARDDELAY: u32 = 0x0016;
const SPI_GETSCREENSAVEACTIVE: u32 = 0x0010;
const SPI_GETSCREENSAVETIMEOUT: u32 = 0x000E;
const SPI_GETDESKWALLPAPER: u32 = 0x0073;
const SPI_GETWORKAREA: u32 = 0x0030;
const SPI_GETNONCLIENTMETRICS: u32 = 0x0029;
const SPI_GETMOUSEHOVERTIME: u32 = 0x0066;
const SPI_GETMOUSEHOVERWIDTH: u32 = 0x0062;
const SPI_GETMOUSEHOVERHEIGHT: u32 = 0x0064;
const SPI_GETSHOWSOUNDS: u32 = 0x0038;
const SPI_GETKEYBOARDCUES: u32 = 0x100A;
const SPI_GETHOTTRACKING: u32 = 0x100E;
const SPI_GETMENUFADE: u32 = 0x1012;
const SPI_GETSELECTIONFADE: u32 = 0x1014;
const SPI_GETTOOLTIPANIMATION: u32 = 0x1016;
const SPI_GETTOOLTIPFADE: u32 = 0x1018;
const SPI_GETCURSORSHADOW: u32 = 0x101A;
const SPI_GETUIEFFECTS: u32 = 0x103E;
const SPI_GETCOMBOBOXANIMATION: u32 = 0x1004;
const SPI_GETLISTBOXSMOOTHSCROLLING: u32 = 0x1006;
const SPI_GETGRADIENTCAPTIONS: u32 = 0x1008;

pub fn SystemParametersInfoA(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // BOOL SystemParametersInfoA(
    //   UINT  uiAction,  // RCX
    //   UINT  uiParam,   // RDX
    //   PVOID pvParam,   // R8
    //   UINT  fWinIni    // R9
    // )
    
    let action = emu.reg_read(RegisterX86::RCX)? as u32;
    let param = emu.reg_read(RegisterX86::RDX)? as u32;
    let pv_param = emu.reg_read(RegisterX86::R8)?;
    let win_ini = emu.reg_read(RegisterX86::R9)? as u32;
    
    log::info!(
        "[SystemParametersInfoA] Action: 0x{:04x}, Param: 0x{:x}, pvParam: 0x{:x}, fWinIni: 0x{:x}",
        action, param, pv_param, win_ini
    );
    
    // Handle common actions with reasonable defaults
    match action {
        SPI_GETBEEP => {
            log::info!("[SystemParametersInfoA] SPI_GETBEEP - returning TRUE (beep enabled)");
            if pv_param != 0 {
                let value: u32 = 1; // TRUE
                emu.mem_write(pv_param, &value.to_le_bytes())?;
            }
        }
        SPI_GETSCREENSAVEACTIVE => {
            log::info!("[SystemParametersInfoA] SPI_GETSCREENSAVEACTIVE - returning FALSE (screensaver disabled)");
            if pv_param != 0 {
                let value: u32 = 0; // FALSE
                emu.mem_write(pv_param, &value.to_le_bytes())?;
            }
        }
        SPI_GETSCREENSAVETIMEOUT => {
            log::info!("[SystemParametersInfoA] SPI_GETSCREENSAVETIMEOUT - returning 600 seconds");
            if pv_param != 0 {
                let value: u32 = 600; // 10 minutes
                emu.mem_write(pv_param, &value.to_le_bytes())?;
            }
        }
        SPI_GETWORKAREA => {
            log::info!("[SystemParametersInfoA] SPI_GETWORKAREA - returning 1920x1080 work area");
            if pv_param != 0 {
                // RECT structure: left, top, right, bottom
                let rect: [i32; 4] = [0, 0, 1920, 1080];
                for (i, val) in rect.iter().enumerate() {
                    emu.mem_write(pv_param + (i * 4) as u64, &val.to_le_bytes())?;
                }
            }
        }
        SPI_GETMOUSEHOVERTIME => {
            log::info!("[SystemParametersInfoA] SPI_GETMOUSEHOVERTIME - returning 400ms");
            if pv_param != 0 {
                let value: u32 = 400;
                emu.mem_write(pv_param, &value.to_le_bytes())?;
            }
        }
        SPI_GETMOUSEHOVERWIDTH | SPI_GETMOUSEHOVERHEIGHT => {
            log::info!("[SystemParametersInfoA] SPI_GETMOUSEHOVER WIDTH/HEIGHT - returning 4 pixels");
            if pv_param != 0 {
                let value: u32 = 4;
                emu.mem_write(pv_param, &value.to_le_bytes())?;
            }
        }
        SPI_GETKEYBOARDSPEED => {
            log::info!("[SystemParametersInfoA] SPI_GETKEYBOARDSPEED - returning 31 (fastest)");
            if pv_param != 0 {
                let value: u32 = 31; // 0-31, 31 is fastest
                emu.mem_write(pv_param, &value.to_le_bytes())?;
            }
        }
        SPI_GETKEYBOARDDELAY => {
            log::info!("[SystemParametersInfoA] SPI_GETKEYBOARDDELAY - returning 1 (250ms)");
            if pv_param != 0 {
                let value: u32 = 1; // 0-3, 0=250ms, 1=500ms, 2=750ms, 3=1000ms
                emu.mem_write(pv_param, &value.to_le_bytes())?;
            }
        }
        SPI_GETSHOWSOUNDS | SPI_GETKEYBOARDCUES | SPI_GETHOTTRACKING | 
        SPI_GETMENUFADE | SPI_GETSELECTIONFADE | SPI_GETTOOLTIPANIMATION | 
        SPI_GETTOOLTIPFADE | SPI_GETCURSORSHADOW | SPI_GETUIEFFECTS |
        SPI_GETCOMBOBOXANIMATION | SPI_GETLISTBOXSMOOTHSCROLLING | SPI_GETGRADIENTCAPTIONS => {
            log::info!("[SystemParametersInfoA] UI effect flag 0x{:04x} - returning TRUE", action);
            if pv_param != 0 {
                let value: u32 = 1; // TRUE for all UI effects
                emu.mem_write(pv_param, &value.to_le_bytes())?;
            }
        }
        SPI_GETDESKWALLPAPER => {
            log::info!("[SystemParametersInfoA] SPI_GETDESKWALLPAPER - returning empty string");
            if pv_param != 0 {
                // Write empty string
                memory::write_string_to_memory(emu, pv_param, "")?;
            }
        }
        SPI_GETNONCLIENTMETRICS => {
            log::info!("[SystemParametersInfoA] SPI_GETNONCLIENTMETRICS - returning mock metrics");
            if pv_param != 0 {
                // This is a complex structure, just zero it out for now
                // Real implementation would need proper NONCLIENTMETRICSA structure
                let size = param as usize; // uiParam contains the size
                if size > 0 {
                    let zeros = vec![0u8; size];
                    emu.mem_write(pv_param, &zeros)?;
                    // Set cbSize field (first UINT)
                    emu.mem_write(pv_param, &(size as u32).to_le_bytes())?;
                }
            }
        }
        _ => {
            log::warn!("[SystemParametersInfoA] Unhandled action: 0x{:04x}", action);
            // Still return success for unknown parameters
        }
    }
    
    // Return TRUE for success
    emu.reg_write(RegisterX86::RAX, 1)?;
    
    Ok(())
}