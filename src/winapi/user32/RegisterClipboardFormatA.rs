use unicorn_engine::{Unicorn, RegisterX86};
use crate::emulation::memory;
use std::collections::HashMap;
use std::sync::{Mutex, LazyLock};
use std::sync::atomic::{AtomicU32, Ordering};

// Global storage for registered clipboard formats
// Key: format name (case-insensitive), Value: format ID
static CLIPBOARD_FORMATS: LazyLock<Mutex<HashMap<String, u32>>> = LazyLock::new(|| {
    Mutex::new(HashMap::new())
});

// Counter for new format IDs (0xC000 through 0xFFFF)
static NEXT_FORMAT_ID: AtomicU32 = AtomicU32::new(0xC000);

pub fn RegisterClipboardFormatA(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // UINT RegisterClipboardFormatA(
    //   [in] LPCSTR lpszFormat  // RCX
    // )
    
    let lpsz_format = emu.reg_read(RegisterX86::RCX)?;
    
    // Check for NULL format name
    if lpsz_format == 0 {
        log::error!("[RegisterClipboardFormatA] NULL format name");
        emu.reg_write(RegisterX86::RAX, 0)?; // Return 0 for failure
        return Ok(());
    }
    
    // Read the format name string
    let format_name = match memory::read_string_from_memory(emu, lpsz_format) {
        Ok(name) => name,
        Err(e) => {
            log::error!("[RegisterClipboardFormatA] Failed to read format name from 0x{:x}: {:?}", 
                lpsz_format, e);
            emu.reg_write(RegisterX86::RAX, 0)?; // Return 0 for failure
            return Ok(());
        }
    };
    
    // Check for empty format name
    if format_name.is_empty() {
        log::error!("[RegisterClipboardFormatA] Empty format name");
        emu.reg_write(RegisterX86::RAX, 0)?; // Return 0 for failure
        return Ok(());
    }
    
    log::info!("[RegisterClipboardFormatA] Format name: \"{}\"", format_name);
    
    // Convert to lowercase for case-insensitive comparison
    let format_key = format_name.to_lowercase();
    
    // Check if format already exists or register new one
    let format_id = {
        let mut formats = CLIPBOARD_FORMATS.lock().unwrap();
        
        if let Some(&existing_id) = formats.get(&format_key) {
            // Format already exists, return existing ID
            log::info!("[RegisterClipboardFormatA] Format \"{}\" already registered with ID: 0x{:04x}", 
                format_name, existing_id);
            existing_id
        } else {
            // Register new format
            let new_id = NEXT_FORMAT_ID.fetch_add(1, Ordering::SeqCst);
            
            // Check if we've exceeded the valid range (0xC000-0xFFFF)
            if new_id > 0xFFFF {
                log::error!("[RegisterClipboardFormatA] Exceeded maximum clipboard format ID range");
                emu.reg_write(RegisterX86::RAX, 0)?; // Return 0 for failure
                return Ok(());
            }
            
            formats.insert(format_key.clone(), new_id);
            log::info!("[RegisterClipboardFormatA] Registered new format \"{}\" with ID: 0x{:04x}", 
                format_name, new_id);
            new_id
        }
    };
    
    // Return the format ID
    emu.reg_write(RegisterX86::RAX, format_id as u64)?;
    
    Ok(())
}