use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};

use crate::winapi;

pub fn ReadProcessMemory(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    // Get parameters from registers (x64 calling convention)
    let h_process = emu.reg_read(X86Register::RCX)?;
    let lp_base_address = emu.reg_read(X86Register::RDX)?;
    let lp_buffer = emu.reg_read(X86Register::R8)?;
    let n_size = emu.reg_read(X86Register::R9)? as usize;
    
    // Get lpNumberOfBytesRead from stack (5th parameter)
    let rsp = emu.reg_read(X86Register::RSP)?;
    let lp_number_of_bytes_read_bytes = emu.mem_read_as_vec(rsp + 0x28, 8)?;
    let lp_number_of_bytes_read = u64::from_le_bytes(lp_number_of_bytes_read_bytes.try_into().unwrap());
    
    log::info!("[ReadProcessMemory] hProcess: 0x{:x}, lpBaseAddress: 0x{:x}, lpBuffer: 0x{:x}, nSize: {}, lpNumberOfBytesRead: 0x{:x}",
              h_process, lp_base_address, lp_buffer, n_size, lp_number_of_bytes_read);
    
    // Check if this is the current process (pseudo handle -1)
    if h_process == 0xFFFFFFFFFFFFFFFF {
        // Reading from current process - this is just a memory copy within the emulator
        if lp_base_address == 0 || lp_buffer == 0 || n_size == 0 {
            log::warn!("[ReadProcessMemory] Invalid parameters");
            winapi::set_last_error(emu, windows_sys::Win32::Foundation::ERROR_INVALID_PARAMETER)?;
            emu.reg_write(X86Register::RAX, 0)?; // FALSE
            return Ok(());
        }
        
        // Try to read the memory
        match emu.mem_read_as_vec(lp_base_address, n_size) {
            Ok(data) => {
                // Write data to destination buffer
                if let Err(_) = emu.mem_write(lp_buffer, &data) {
                    log::error!("[ReadProcessMemory] Failed to write to destination buffer");
                    winapi::set_last_error(emu, windows_sys::Win32::Foundation::ERROR_INVALID_ADDRESS)?;
                    emu.reg_write(X86Register::RAX, 0)?; // FALSE
                    return Ok(());
                }
                
                // Set number of bytes read if pointer is provided
                if lp_number_of_bytes_read != 0 {
                    let bytes_read = n_size as u64;
                    emu.mem_write(lp_number_of_bytes_read, &bytes_read.to_le_bytes())?;
                }
                
                // Success
                log::info!("[ReadProcessMemory] Successfully read {} bytes from 0x{:x} to 0x{:x}",
                          n_size, lp_base_address, lp_buffer);
                winapi::set_last_error(emu, 0)?; // ERROR_SUCCESS
                emu.reg_write(X86Register::RAX, 1)?; // TRUE
            },
            Err(_) => {
                log::error!("[ReadProcessMemory] Failed to read from source address 0x{:x}", lp_base_address);
                
                // Set bytes read to 0 if pointer is provided
                if lp_number_of_bytes_read != 0 {
                    emu.mem_write(lp_number_of_bytes_read, &0u64.to_le_bytes())?;
                }
                
                winapi::set_last_error(emu, windows_sys::Win32::Foundation::ERROR_INVALID_ADDRESS)?;
                emu.reg_write(X86Register::RAX, 0)?; // FALSE
            }
        }
    } else {
        // Reading from another process - not supported in this emulator
        log::warn!("[ReadProcessMemory] Cross-process memory reading not supported, hProcess: 0x{:x} ERROR_INVALID_HANDLE", h_process);
        
        // Set bytes read to 0 if pointer is provided
        if lp_number_of_bytes_read != 0 {
            emu.mem_write(lp_number_of_bytes_read, &0u64.to_le_bytes())?;
        }
        
        winapi::set_last_error(emu, windows_sys::Win32::Foundation::ERROR_INVALID_HANDLE)?;
        emu.reg_write(X86Register::RAX, 0)?; // FALSE
    }
    
    Ok(())
}