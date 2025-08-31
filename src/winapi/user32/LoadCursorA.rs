/*
LoadCursorA function (winuser.h)
11/19/2024
Loads the specified cursor resource from the executable (.EXE) file associated with an application instance.

 Note

This function has been superseded by the LoadImage function (with LR_DEFAULTSIZE and LR_SHARED flags set).

Syntax
C++

Copy
HCURSOR LoadCursorA(
  [in, optional] HINSTANCE hInstance,
  [in]           LPCSTR    lpCursorName
);
Parameters
[in, optional] hInstance

Type: HINSTANCE

A handle to the module of either a DLL or executable (.exe) file that contains the cursor to be loaded. For more information, see GetModuleHandle.

To load a predefined system cursor, set this parameter to NULL.

[in] lpCursorName

Type: LPCTSTR

If hInstance is non-NULL, lpCursorName specifies the cursor resource either by name or ordinal. This ordinal must be packaged by using the MAKEINTRESOURCE macro.

If hInstance is NULL, lpCursorName specifies the identifier (beginning with the IDC_ prefix) of a predefined system cursor to load.

Return value
Type: HCURSOR

If the function succeeds, the return value is the handle to the newly loaded cursor.

If the function fails, the return value is NULL. To get extended error information, call GetLastError.
*/

use unicorn_engine::{Unicorn, RegisterX86};
use crate::emulation::memory;
use std::sync::atomic::{AtomicU64, Ordering};

// Predefined system cursor IDs
const IDC_ARROW: u64 = 32512;
const IDC_IBEAM: u64 = 32513;
const IDC_WAIT: u64 = 32514;
const IDC_CROSS: u64 = 32515;
const IDC_UPARROW: u64 = 32516;
const IDC_SIZE: u64 = 32640;
const IDC_ICON: u64 = 32641;
const IDC_SIZENWSE: u64 = 32642;
const IDC_SIZENESW: u64 = 32643;
const IDC_SIZEWE: u64 = 32644;
const IDC_SIZENS: u64 = 32645;
const IDC_SIZEALL: u64 = 32646;
const IDC_NO: u64 = 32648;
const IDC_HAND: u64 = 32649;
const IDC_APPSTARTING: u64 = 32650;
const IDC_HELP: u64 = 32651;

// Global handle counter for cursor handles
static NEXT_CURSOR_HANDLE: AtomicU64 = AtomicU64::new(0xA000);

pub fn LoadCursorA(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // HCURSOR LoadCursorA(
    //   HINSTANCE hInstance,    // RCX
    //   LPCSTR    lpCursorName  // RDX
    // )
    
    let hinstance = emu.reg_read(RegisterX86::RCX)?;
    let cursor_name_ptr = emu.reg_read(RegisterX86::RDX)?;
    
    // Check if loading system cursor (hInstance == NULL)
    if hinstance == 0 {
        // System cursor - cursor_name_ptr is an ID
        let cursor_id = cursor_name_ptr;
        
        let cursor_name = match cursor_id {
            IDC_ARROW => "IDC_ARROW",
            IDC_IBEAM => "IDC_IBEAM",
            IDC_WAIT => "IDC_WAIT",
            IDC_CROSS => "IDC_CROSS",
            IDC_UPARROW => "IDC_UPARROW",
            IDC_SIZE => "IDC_SIZE",
            IDC_ICON => "IDC_ICON",
            IDC_SIZENWSE => "IDC_SIZENWSE",
            IDC_SIZENESW => "IDC_SIZENESW",
            IDC_SIZEWE => "IDC_SIZEWE",
            IDC_SIZENS => "IDC_SIZENS",
            IDC_SIZEALL => "IDC_SIZEALL",
            IDC_NO => "IDC_NO",
            IDC_HAND => "IDC_HAND",
            IDC_APPSTARTING => "IDC_APPSTARTING",
            IDC_HELP => "IDC_HELP",
            _ => "Unknown system cursor",
        };
        
        log::info!("[LoadCursorA] Loading system cursor: {} (ID: 0x{:x})", cursor_name, cursor_id);
    } else {
        // Application cursor
        if cursor_name_ptr < 0x10000 {
            // Cursor identified by ordinal (MAKEINTRESOURCE)
            log::info!("[LoadCursorA] Loading cursor by ordinal: {} from hInstance: 0x{:x}", 
                cursor_name_ptr, hinstance);
        } else {
            // Cursor identified by name
            let cursor_name = memory::read_string_from_memory(emu, cursor_name_ptr)?;
            log::info!("[LoadCursorA] Loading cursor by name: \"{}\" from hInstance: 0x{:x}", 
                cursor_name, hinstance);
        }
    }
    
    // Create a mock cursor handle
    let cursor_handle = NEXT_CURSOR_HANDLE.fetch_add(0x10, Ordering::SeqCst);
    
    log::info!("[LoadCursorA] Returning cursor handle: 0x{:x}", cursor_handle);
    
    // Return the cursor handle
    emu.reg_write(RegisterX86::RAX, cursor_handle)?;
    
    Ok(())
}