use unicorn_engine::Unicorn;
use unicorn_engine::RegisterX86;

use crate::pe::MODULE_REGISTRY;
use crate::winapi;

pub fn GetModuleFileNameW(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // Get parameters from registers (x64 calling convention)
    let h_module = emu.reg_read(RegisterX86::RCX)?;
    let lp_filename = emu.reg_read(RegisterX86::RDX)?;
    let n_size = emu.reg_read(RegisterX86::R8)? as u32;
    
    log::info!("[GetModuleFileNameW] hModule: 0x{:x}, lpFilename: 0x{:x}, nSize: {}", 
              h_module, lp_filename, n_size);
    
    // Determine which module to get the filename for
    let filename = if h_module == 0 {
        // NULL means get the main executable's path
        "C:\\Program Files\\Application\\enigma_test_protected.exe"
    } else {
        // Check if this is a known module
        if let Some(module) = MODULE_REGISTRY.get_loaded_module_by_module_base(h_module) {
            // Return a mock path based on the module name
            match module.name.as_str() {
                "enigma_test_protected.exe" | "enigma_test_protected" => "C:\\Program Files\\Application\\enigma_test_protected.exe",
                "kernel32.dll" | "kernel32" => "C:\\Windows\\System32\\kernel32.dll",
                "user32.dll" | "user32" => "C:\\Windows\\System32\\user32.dll",
                "ntdll.dll" | "ntdll" => "C:\\Windows\\System32\\ntdll.dll",
                "ole32.dll" | "ole32" => "C:\\Windows\\System32\\ole32.dll",
                "oleaut32.dll" | "oleaut32" => "C:\\Windows\\System32\\oleaut32.dll",
                "msvcrt.dll" | "msvcrt" => "C:\\Windows\\System32\\msvcrt.dll",
                "advapi32.dll" | "advapi32" => "C:\\Windows\\System32\\advapi32.dll",
                _ => {
                    log::error!("unmapped module.name: {}", module.name);
                    panic!("TODO");
                }
            }
        } else {
            log::warn!("[GetModuleFileNameW] Unknown module handle: 0x{:x}", h_module);
            winapi::set_last_error(emu, windows_sys::Win32::Foundation::ERROR_INVALID_HANDLE)?;
            emu.reg_write(RegisterX86::RAX, 0)?; // Return 0 for failure
            return Ok(());
        }
    };
    
    // Convert to UTF-16 wide string
    let wide_chars: Vec<u16> = filename.encode_utf16().collect();
    
    // Calculate the length to copy (in wide characters, including null terminator)
    // n_size is the buffer size in characters (not bytes)
    let copy_len = std::cmp::min(wide_chars.len() + 1, n_size as usize);
    let actual_copied = std::cmp::min(wide_chars.len(), copy_len - 1);
    
    // Write the filename to the buffer
    if lp_filename > 0 && n_size > 0 {
        // Convert wide chars to bytes for writing
        let mut buffer = Vec::with_capacity(actual_copied * 2);
        for &wchar in &wide_chars[..actual_copied] {
            buffer.extend_from_slice(&wchar.to_le_bytes());
        }
        
        // Write the wide string
        emu.mem_write(lp_filename, &buffer)?;
        
        // Write null terminator (2 bytes for wide char)
        emu.mem_write(lp_filename + (actual_copied * 2) as u64, &[0u8, 0u8])?;
    }
    
    // Return the number of wide characters copied (not including null terminator)
    emu.reg_write(RegisterX86::RAX, actual_copied as u64)?;
    
    log::info!("[GetModuleFileNameW] Returned path: {} (length: {} wide chars)", 
              filename, actual_copied);
    
    Ok(())
}
