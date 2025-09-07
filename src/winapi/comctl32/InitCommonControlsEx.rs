/*
InitCommonControlsEx function (commctrl.h)
02/22/2024
Ensures that the common control DLL (Comctl32.dll) is loaded, and registers specific common control classes from the DLL. An application must call this function before creating a common control.

Syntax
C++

Copy
BOOL InitCommonControlsEx(
  [in] const INITCOMMONCONTROLSEX *picce
);
Parameters
[in] picce

Type: const LPINITCOMMONCONTROLSEX

A pointer to an INITCOMMONCONTROLSEX structure that contains information specifying which control classes will be registered.

Return value
Type: BOOL

Returns TRUE if successful, or FALSE otherwise.
*/

use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};
use crate::emulation::memory;
use windows_sys::Win32::UI::Controls::INITCOMMONCONTROLSEX;

// Common control classes flags
const ICC_LISTVIEW_CLASSES: u32 = 0x00000001;
const ICC_TREEVIEW_CLASSES: u32 = 0x00000002;
const ICC_BAR_CLASSES: u32 = 0x00000004;
const ICC_TAB_CLASSES: u32 = 0x00000008;
const ICC_UPDOWN_CLASS: u32 = 0x00000010;
const ICC_PROGRESS_CLASS: u32 = 0x00000020;
const ICC_HOTKEY_CLASS: u32 = 0x00000040;
const ICC_ANIMATE_CLASS: u32 = 0x00000080;
const ICC_WIN95_CLASSES: u32 = 0x000000FF;
const ICC_DATE_CLASSES: u32 = 0x00000100;
const ICC_USEREX_CLASSES: u32 = 0x00000200;
const ICC_COOL_CLASSES: u32 = 0x00000400;
const ICC_INTERNET_CLASSES: u32 = 0x00000800;
const ICC_PAGESCROLLER_CLASS: u32 = 0x00001000;
const ICC_NATIVEFNTCTL_CLASS: u32 = 0x00002000;
const ICC_STANDARD_CLASSES: u32 = 0x00004000;
const ICC_LINK_CLASS: u32 = 0x00008000;

pub fn InitCommonControlsEx(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    // BOOL InitCommonControlsEx(
    //   const INITCOMMONCONTROLSEX *picce  // RCX
    // )
    
    let picce_ptr = emu.reg_read(X86Register::RCX)?;
    
    if picce_ptr == 0 {
        log::warn!("[InitCommonControlsEx] NULL INITCOMMONCONTROLSEX pointer");
        emu.reg_write(X86Register::RAX, 0)?; // FALSE
        return Ok(());
    }
    
    // Read INITCOMMONCONTROLSEX structure
    let icce = match memory::read_struct::<INITCOMMONCONTROLSEX>(emu, picce_ptr) {
        Ok(s) => s,
        Err(e) => {
            log::error!("[InitCommonControlsEx] Failed to read INITCOMMONCONTROLSEX: {:?}", e);
            emu.reg_write(X86Register::RAX, 0)?; // FALSE
            return Ok(());
        }
    };
    
    // Check structure size
    if icce.dwSize != std::mem::size_of::<INITCOMMONCONTROLSEX>() as u32 {
        log::warn!("[InitCommonControlsEx] Invalid structure size: {} (expected {})",
            icce.dwSize, std::mem::size_of::<INITCOMMONCONTROLSEX>());
    }
    
    // Log which control classes are being registered
    let mut classes = Vec::new();
    if icce.dwICC & ICC_LISTVIEW_CLASSES != 0 { classes.push("LISTVIEW"); }
    if icce.dwICC & ICC_TREEVIEW_CLASSES != 0 { classes.push("TREEVIEW"); }
    if icce.dwICC & ICC_BAR_CLASSES != 0 { classes.push("BAR"); }
    if icce.dwICC & ICC_TAB_CLASSES != 0 { classes.push("TAB"); }
    if icce.dwICC & ICC_UPDOWN_CLASS != 0 { classes.push("UPDOWN"); }
    if icce.dwICC & ICC_PROGRESS_CLASS != 0 { classes.push("PROGRESS"); }
    if icce.dwICC & ICC_HOTKEY_CLASS != 0 { classes.push("HOTKEY"); }
    if icce.dwICC & ICC_ANIMATE_CLASS != 0 { classes.push("ANIMATE"); }
    if icce.dwICC & ICC_DATE_CLASSES != 0 { classes.push("DATE"); }
    if icce.dwICC & ICC_USEREX_CLASSES != 0 { classes.push("USEREX"); }
    if icce.dwICC & ICC_COOL_CLASSES != 0 { classes.push("COOL"); }
    if icce.dwICC & ICC_INTERNET_CLASSES != 0 { classes.push("INTERNET"); }
    if icce.dwICC & ICC_PAGESCROLLER_CLASS != 0 { classes.push("PAGESCROLLER"); }
    if icce.dwICC & ICC_NATIVEFNTCTL_CLASS != 0 { classes.push("NATIVEFNTCTL"); }
    if icce.dwICC & ICC_STANDARD_CLASSES != 0 { classes.push("STANDARD"); }
    if icce.dwICC & ICC_LINK_CLASS != 0 { classes.push("LINK"); }
    
    log::info!("[InitCommonControlsEx] Registering control classes: 0x{:08x} ({})",
        icce.dwICC, classes.join(", "));
    
    // Return TRUE for success
    emu.reg_write(X86Register::RAX, 1)?;
    
    Ok(())
}