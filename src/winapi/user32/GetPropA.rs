use unicorn_engine::{Unicorn, RegisterX86};
use crate::emulation::memory;
use std::collections::HashMap;
use std::sync::{Mutex, LazyLock};

// Global storage for window properties
// Key: (HWND, property_name), Value: HANDLE
static WINDOW_PROPERTIES: LazyLock<Mutex<HashMap<(u64, String), u64>>> = LazyLock::new(|| {
    Mutex::new(HashMap::new())
});

pub fn GetPropA(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // HANDLE GetPropA(
    //   [in] HWND   hWnd,      // RCX
    //   [in] LPCSTR lpString   // RDX
    // )
    
    let hwnd = emu.reg_read(RegisterX86::RCX)?;
    let lp_string = emu.reg_read(RegisterX86::RDX)?;
    
    // Handle NULL window
    if hwnd == 0 {
        log::error!("[GetPropA] NULL window handle");
        emu.reg_write(RegisterX86::RAX, 0)?; // Return NULL
        return Ok(());
    }
    
    // Get the property name
    let property_name = if lp_string == 0 {
        log::error!("[GetPropA] NULL property string");
        emu.reg_write(RegisterX86::RAX, 0)?; // Return NULL
        return Ok(());
    } else if lp_string < 0x10000 {
        // It's an atom (16-bit value in low word)
        format!("Atom_{:04X}", lp_string & 0xFFFF)
    } else {
        // It's a string pointer
        match memory::read_string_from_memory(emu, lp_string) {
            Ok(name) => name,
            Err(e) => {
                log::error!("[GetPropA] Failed to read property string from 0x{:x}: {:?}", lp_string, e);
                emu.reg_write(RegisterX86::RAX, 0)?; // Return NULL
                return Ok(());
            }
        }
    };
    
    log::info!("[GetPropA] Window: 0x{:x}, Property: \"{}\"", hwnd, property_name);
    
    // Look up the property in our global storage
    let handle = {
        let properties = WINDOW_PROPERTIES.lock().unwrap();
        properties.get(&(hwnd, property_name.clone())).copied()
    };
    
    match handle {
        Some(h) => {
            log::info!("[GetPropA] Found property \"{}\" with handle: 0x{:x}", property_name, h);
            emu.reg_write(RegisterX86::RAX, h)?;
        }
        None => {
            log::info!("[GetPropA] Property \"{}\" not found", property_name);
            emu.reg_write(RegisterX86::RAX, 0)?; // Return NULL
        }
    }
    
    Ok(())
}