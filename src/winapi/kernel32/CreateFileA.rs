use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};
use crate::emulation::{memory, vfs::VIRTUAL_FS};
use crate::winapi;

pub fn CreateFileA(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    // HANDLE CreateFileA(
    //   LPCSTR                lpFileName,       // RCX
    //   DWORD                 dwDesiredAccess,   // RDX  
    //   DWORD                 dwShareMode,       // R8
    //   LPSECURITY_ATTRIBUTES lpSecurityAttributes, // R9
    //   DWORD                 dwCreationDisposition, // [RSP+40]
    //   DWORD                 dwFlagsAndAttributes,  // [RSP+48]
    //   HANDLE                hTemplateFile          // [RSP+50]
    // )
    
    let file_name_ptr = emu.reg_read(X86Register::RCX)?;
    let desired_access = emu.reg_read(X86Register::RDX)? as u32;
    let share_mode = emu.reg_read(X86Register::R8)? as u32;
    let security_attributes = emu.reg_read(X86Register::R9)?;
    
    // Read stack parameters
    let rsp = emu.reg_read(X86Register::RSP)?;
    let mut creation_disposition_bytes = [0u8; 4];
    emu.mem_read(rsp + 0x40, &mut creation_disposition_bytes)?;
    let creation_disposition = u32::from_le_bytes(creation_disposition_bytes);
    
    let mut flags_and_attributes_bytes = [0u8; 4];
    emu.mem_read(rsp + 0x48, &mut flags_and_attributes_bytes)?;
    let flags_and_attributes = u32::from_le_bytes(flags_and_attributes_bytes);
    
    let mut template_file_bytes = [0u8; 8];
    emu.mem_read(rsp + 0x50, &mut template_file_bytes)?;
    let template_file = u64::from_le_bytes(template_file_bytes);
    
    // Try to read the filename (ANSI string)
    let filename = if file_name_ptr != 0 {
        match memory::read_string_from_memory(emu, file_name_ptr) {
            Ok(name) => name,
            Err(_) => {
                log::warn!("[CreateFileA] Failed to read filename at 0x{:x}", file_name_ptr);
                String::from("<unreadable>")
            }
        }
    } else {
        String::from("<null>")
    };
    
    log::info!("[CreateFileA] lpFileName: '{}' (0x{:x})", filename, file_name_ptr);
    log::info!("[CreateFileA] dwDesiredAccess: 0x{:x}", desired_access);
    log::info!("[CreateFileA] dwShareMode: 0x{:x}", share_mode);
    log::info!("[CreateFileA] lpSecurityAttributes: 0x{:x}", security_attributes);
    log::info!("[CreateFileA] dwCreationDisposition: 0x{:x}", creation_disposition);
    log::info!("[CreateFileA] dwFlagsAndAttributes: 0x{:x}", flags_and_attributes);
    log::info!("[CreateFileA] hTemplateFile: 0x{:x}", template_file);
    
    // Check for null filename
    if file_name_ptr == 0 {
        log::warn!("[CreateFileA] NULL filename provided");
        winapi::set_last_error(emu, windows_sys::Win32::Foundation::ERROR_INVALID_PARAMETER)?;
        emu.reg_write(X86Register::RAX, 0xFFFFFFFFFFFFFFFF)?; // INVALID_HANDLE_VALUE
        return Ok(());
    }
    
    // For now, just return a mock handle for any file
    // In a real implementation, you'd track opened files and their states
    
    // Special handling for common system files/devices
    if filename.to_lowercase() == "conout$" || filename.to_lowercase() == "con" {
        // Console output - return a special handle
        let console_handle = 0x20u64;
        log::info!("[CreateFileA] Opening console output, returning handle: 0x{:x}", console_handle);
        emu.reg_write(X86Register::RAX, console_handle)?;
        return Ok(());
    }
    
    if filename.to_lowercase() == "nul" || filename.to_lowercase() == "\\\\.\\nul" {
        // NUL device - return a special handle
        let nul_handle = 0x30u64;
        log::info!("[CreateFileA] Opening NUL device, returning handle: 0x{:x}", nul_handle);
        emu.reg_write(X86Register::RAX, nul_handle)?;
        return Ok(());
    }
    
    // For advanced features, panic as requested
    if template_file != 0 {
        panic!("[CreateFileA] Template file parameter not supported (advanced feature)");
    }
    
    if (flags_and_attributes & 0x10000000) != 0 { // FILE_FLAG_OVERLAPPED
        panic!("[CreateFileA] Overlapped I/O not supported (advanced feature)");
    }
    
    // Register file in VFS
    let handle = {
        let mut vfs = VIRTUAL_FS.write().unwrap();
        vfs.register_file(filename, desired_access, share_mode, flags_and_attributes)
    };
    
    log::info!("[CreateFileA] Created handle: 0x{:x}", handle);
    emu.reg_write(X86Register::RAX, handle)?;
    
    Ok(())
}