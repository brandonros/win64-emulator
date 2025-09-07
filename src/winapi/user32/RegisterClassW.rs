/*
RegisterClassW function (winuser.h)
02/08/2023
Registers a window class for subsequent use in calls to the CreateWindow or CreateWindowEx function.

Note  The RegisterClass function has been superseded by the RegisterClassEx function. You can still use RegisterClass, however, if you do not need to set the class small icon.
 
Syntax
C++

Copy
ATOM RegisterClassW(
  [in] const WNDCLASSW *lpWndClass
);
Parameters
[in] lpWndClass

Type: const WNDCLASS*

A pointer to a WNDCLASS structure. You must fill the structure with the appropriate class attributes before passing it to the function.

Return value
Type: ATOM

If the function succeeds, the return value is a class atom that uniquely identifies the class being registered. This atom can only be used by the CreateWindow, CreateWindowEx, GetClassInfo, GetClassInfoEx, FindWindow, FindWindowEx, and UnregisterClass functions and the IActiveIMMap::FilterClientWindows method.

If the function fails, the return value is zero. To get extended error information, call GetLastError.
*/

use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};
use crate::emulation::memory;
use std::sync::atomic::{AtomicU16, Ordering};
use windows_sys::Win32::UI::WindowsAndMessaging::WNDCLASSW;

// Global atom counter
static NEXT_CLASS_ATOM: AtomicU16 = AtomicU16::new(0xC000);

pub fn RegisterClassW(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    // ATOM RegisterClassW(
    //   const WNDCLASSW *lpWndClass  // RCX
    // )
    
    let wndclass_ptr = emu.reg_read(X86Register::RCX)?;
    
    if wndclass_ptr == 0 {
        log::warn!("[RegisterClassW] NULL WNDCLASSW pointer");
        emu.reg_write(X86Register::RAX, 0)?;
        return Ok(());
    }
    
    log::info!("[RegisterClassW] WNDCLASSW ptr: 0x{:x}", wndclass_ptr);
    
    // Read WNDCLASSW structure using read_struct
    let wndclass = match memory::read_struct::<WNDCLASSW>(emu, wndclass_ptr) {
        Ok(wc) => wc,
        Err(e) => {
            log::error!("[RegisterClassW] Failed to read WNDCLASSW structure: {:?}", e);
            emu.reg_write(X86Register::RAX, 0)?;
            return Ok(());
        }
    };
    
    let class_name_ptr = wndclass.lpszClassName as u64;
    
    let class_name = if class_name_ptr != 0 && class_name_ptr < 0x10000 {
        // It's an atom/ordinal
        format!("Atom(0x{:x})", class_name_ptr)
    } else if class_name_ptr != 0 {
        // It's a string pointer
        match memory::read_wide_string_from_memory(emu, class_name_ptr) {
            Ok(name) => name,
            Err(_) => {
                log::warn!("[RegisterClassW] Failed to read class name from 0x{:x}", class_name_ptr);
                String::from("(unreadable)")
            }
        }
    } else {
        String::from("(unnamed)")
    };
    
    log::info!("[RegisterClassW] Registering class \"{}\"", class_name);
    
    // Generate and return a unique atom
    let class_atom = NEXT_CLASS_ATOM.fetch_add(1, Ordering::SeqCst);
    
    log::info!("[RegisterClassW] Registered with atom: 0x{:x}", class_atom);
    
    emu.reg_write(X86Register::RAX, class_atom as u64)?;
    
    Ok(())
}