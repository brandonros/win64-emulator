use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};

use crate::winapi;

pub fn WriteFile(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    // BOOL WriteFile(
    //   HANDLE hFile,
    //   LPCVOID lpBuffer,
    //   DWORD nNumberOfBytesToWrite,
    //   LPDWORD lpNumberOfBytesWritten,
    //   LPOVERLAPPED lpOverlapped
    // )
    
    let h_file = emu.reg_read(X86Register::RCX)?;
    let lp_buffer = emu.reg_read(X86Register::RDX)?;
    let n_number_of_bytes_to_write = emu.reg_read(X86Register::R8)? as u32;
    let lp_number_of_bytes_written = emu.reg_read(X86Register::R9)?;
    
    // Get lpOverlapped from stack (5th parameter)
    let rsp = emu.reg_read(X86Register::RSP)?;
    let lp_overlapped_bytes = emu.mem_read_as_vec(rsp + 0x28, 8)?;
    let lp_overlapped = u64::from_le_bytes(lp_overlapped_bytes.try_into().unwrap());
    
    log::info!("[WriteFile] hFile: 0x{:x}, lpBuffer: 0x{:x}, nNumberOfBytesToWrite: {}, lpNumberOfBytesWritten: 0x{:x}, lpOverlapped: 0x{:x}",
              h_file, lp_buffer, n_number_of_bytes_to_write, lp_number_of_bytes_written, lp_overlapped);

    // invalid handle
    if h_file != 0x14 && h_file != 0x18 {
        log::warn!("[WriteFile] Unknown module handle: 0x{:x} ERROR_INVALID_HANDLE", h_file);
        winapi::set_last_error(emu, windows_sys::Win32::Foundation::ERROR_INVALID_HANDLE)?;
        emu.reg_write(X86Register::RAX, 0)?; // Return 0 for failure
        return Ok(());
    }
    
    // Panic on complex paths as requested
    if lp_overlapped != 0 {
        panic!("WriteFile: Overlapped I/O not supported!");
    }
    
    if n_number_of_bytes_to_write == 0 {
        panic!("WriteFile: Zero-byte writes not supported!");
    }
    
    if lp_buffer == 0 {
        panic!("WriteFile: NULL buffer not supported!");
    }
    
    // Simple case: assume it's writing to stdout/stderr/console
    // Standard handles from GetStdHandle: stdin=0x10, stdout=0x14, stderr=0x18
    if h_file == 0x14 || h_file == 0x18 {
        // Read the data from the buffer
        let data = emu.mem_read_as_vec(lp_buffer, n_number_of_bytes_to_write as usize)?;
        
        // Convert to string and log it (simple console output simulation)
        if let Ok(text) = String::from_utf8(data) {
            log::info!("[WriteFile] Console output: \"{}\"", text.escape_debug());
        } else {
            log::info!("[WriteFile] Console output: {} bytes (binary data)", n_number_of_bytes_to_write);
        }
        
        // Set number of bytes written if pointer provided
        if lp_number_of_bytes_written != 0 {
            emu.mem_write(lp_number_of_bytes_written, &(n_number_of_bytes_to_write as u32).to_le_bytes())?;
        }
        
        // Return TRUE (success)
        emu.reg_write(X86Register::RAX, 1)?;
        
        log::info!("[WriteFile] Successfully wrote {} bytes to console", n_number_of_bytes_to_write);
    }
    
    Ok(())
}
