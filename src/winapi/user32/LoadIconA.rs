/*
LoadIconA function (winuser.h)
11/19/2024
Loads the specified icon resource from the executable (.exe) file associated with an application instance.

 Note

This function has been superseded by the LoadImage function (with LR_DEFAULTSIZE and LR_SHARED flags set).

Syntax
C++

Copy
HICON LoadIconA(
  [in, optional] HINSTANCE hInstance,
  [in]           LPCSTR    lpIconName
);
Parameters
[in, optional] hInstance

Type: HINSTANCE

A handle to the module of either a DLL or executable (.exe) file that contains the icon to be loaded. For more information, see GetModuleHandle.

To load a predefined system icon, set this parameter to NULL.

[in] lpIconName

Type: LPCTSTR

If hInstance is non-NULL, lpIconName specifies the icon resource either by name or ordinal. This ordinal must be packaged by using the MAKEINTRESOURCE macro.

If hInstance is NULL, lpIconName specifies the identifier (beginning with the IDI_ prefix) of a predefined system icon to load.

Return value
Type: HICON

If the function succeeds, the return value is a handle to the newly loaded icon.

If the function fails, the return value is NULL. To get extended error information, call GetLastError.
*/

use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};
use crate::emulation::memory;
use std::sync::atomic::{AtomicU64, Ordering};

// Predefined system icon IDs
const IDI_APPLICATION: u64 = 32512;
const IDI_HAND: u64 = 32513;
const IDI_QUESTION: u64 = 32514;
const IDI_EXCLAMATION: u64 = 32515;
const IDI_ASTERISK: u64 = 32516;
const IDI_WINLOGO: u64 = 32517;
const IDI_SHIELD: u64 = 32518;
const IDI_WARNING: u64 = 32515;  // Same as IDI_EXCLAMATION
const IDI_ERROR: u64 = 32513;     // Same as IDI_HAND
const IDI_INFORMATION: u64 = 32516; // Same as IDI_ASTERISK

// Global handle counter for icon handles
static NEXT_ICON_HANDLE: AtomicU64 = AtomicU64::new(0x9000);

pub fn LoadIconA(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    // HICON LoadIconA(
    //   HINSTANCE hInstance,  // RCX
    //   LPCSTR    lpIconName  // RDX
    // )
    
    let hinstance = emu.reg_read(X86Register::RCX)?;
    let icon_name_ptr = emu.reg_read(X86Register::RDX)?;
    
    // Check if loading system icon (hInstance == NULL)
    if hinstance == 0 {
        // System icon - icon_name_ptr is an ID
        let icon_id = icon_name_ptr;
        
        let icon_name = match icon_id {
            IDI_APPLICATION => "IDI_APPLICATION",
            IDI_HAND | IDI_ERROR => "IDI_ERROR/IDI_HAND",
            IDI_QUESTION => "IDI_QUESTION",
            IDI_EXCLAMATION | IDI_WARNING => "IDI_WARNING/IDI_EXCLAMATION",
            IDI_ASTERISK | IDI_INFORMATION => "IDI_INFORMATION/IDI_ASTERISK",
            IDI_WINLOGO => "IDI_WINLOGO",
            IDI_SHIELD => "IDI_SHIELD",
            _ => "Unknown system icon",
        };
        
        log::info!("[LoadIconA] Loading system icon: {} (ID: 0x{:x})", icon_name, icon_id);
    } else {
        // Application icon
        if icon_name_ptr < 0x10000 {
            // Icon identified by ordinal (MAKEINTRESOURCE)
            log::info!("[LoadIconA] Loading icon by ordinal: {} from hInstance: 0x{:x}", 
                icon_name_ptr, hinstance);
        } else {
            // Icon identified by name
            let icon_name = memory::read_string_from_memory(emu, icon_name_ptr)?;
            log::info!("[LoadIconA] Loading icon by name: \"{}\" from hInstance: 0x{:x}", 
                icon_name, hinstance);
        }
    }
    
    // Create a mock icon handle
    let icon_handle = NEXT_ICON_HANDLE.fetch_add(0x10, Ordering::SeqCst);
    
    log::info!("[LoadIconA] Returning icon handle: 0x{:x}", icon_handle);
    
    // Return the icon handle
    emu.reg_write(X86Register::RAX, icon_handle)?;
    
    Ok(())
}