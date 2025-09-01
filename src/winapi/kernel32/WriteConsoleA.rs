use unicorn_engine::{Unicorn, RegisterX86};
use crate::emulation::memory;

/*
WriteConsole function
12/30/2021
Writes a character string to a console screen buffer beginning at the current cursor location.

Syntax
C

Copy
BOOL WINAPI WriteConsole(
  _In_             HANDLE  hConsoleOutput,
  _In_       const VOID    *lpBuffer,
  _In_             DWORD   nNumberOfCharsToWrite,
  _Out_opt_        LPDWORD lpNumberOfCharsWritten,
  _Reserved_       LPVOID  lpReserved
);
Parameters
hConsoleOutput [in]
A handle to the console screen buffer. The handle must have the GENERIC_WRITE access right. For more information, see Console Buffer Security and Access Rights.

lpBuffer [in]
A pointer to a buffer that contains characters to be written to the console screen buffer. This is expected to be an array of either char for WriteConsoleA or wchar_t for WriteConsoleW.

nNumberOfCharsToWrite [in]
The number of characters to be written. If the total size of the specified number of characters exceeds the available heap, the function fails with ERROR_NOT_ENOUGH_MEMORY.

lpNumberOfCharsWritten [out, optional]
A pointer to a variable that receives the number of characters actually written.

lpReserved Reserved; must be NULL.

Return value
If the function succeeds, the return value is nonzero.

If the function fails, the return value is zero. To get extended error information, call GetLastError.
*/

pub fn WriteConsoleA(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // BOOL WINAPI WriteConsoleA(
    //   HANDLE  hConsoleOutput,              // RCX
    //   const VOID *lpBuffer,                // RDX
    //   DWORD   nNumberOfCharsToWrite,       // R8
    //   LPDWORD lpNumberOfCharsWritten,      // R9
    //   LPVOID  lpReserved                   // [RSP+40]
    // )
    
    let console_handle = emu.reg_read(RegisterX86::RCX)?;
    let buffer_ptr = emu.reg_read(RegisterX86::RDX)?;
    let num_chars_to_write = emu.reg_read(RegisterX86::R8)? as u32;
    let num_chars_written_ptr = emu.reg_read(RegisterX86::R9)?;
    
    // Read stack parameter for lpReserved
    let rsp = emu.reg_read(RegisterX86::RSP)?;
    let mut reserved_bytes = [0u8; 8];
    emu.mem_read(rsp + 0x40, &mut reserved_bytes)?;
    let reserved = u64::from_le_bytes(reserved_bytes);
    
    log::info!("[WriteConsoleA] hConsoleOutput: 0x{:x}", console_handle);
    log::info!("[WriteConsoleA] lpBuffer: 0x{:x}", buffer_ptr);
    log::info!("[WriteConsoleA] nNumberOfCharsToWrite: {}", num_chars_to_write);
    log::info!("[WriteConsoleA] lpNumberOfCharsWritten: 0x{:x}", num_chars_written_ptr);
    log::info!("[WriteConsoleA] lpReserved: 0x{:x}", reserved);
    
    // Validate reserved parameter (must be NULL)
    /*if reserved != 0 {
        log::error!("[WriteConsoleA] lpReserved must be NULL");
        emu.reg_write(RegisterX86::RAX, 0)?; // FALSE
        return Ok(());
    }*/
    
    // Check for NULL buffer
    if buffer_ptr == 0 {
        log::error!("[WriteConsoleA] NULL buffer pointer");
        emu.reg_write(RegisterX86::RAX, 0)?; // FALSE
        return Ok(());
    }
    
    // Check for invalid console handle (basic validation)
    if console_handle == 0 || console_handle == 0xFFFFFFFFFFFFFFFF {
        log::error!("[WriteConsoleA] Invalid console handle");
        emu.reg_write(RegisterX86::RAX, 0)?; // FALSE
        return Ok(());
    }
    
    // Read the buffer to write (ANSI string for WriteConsoleA)
    let mut buffer = vec![0u8; num_chars_to_write as usize];
    match emu.mem_read(buffer_ptr, &mut buffer) {
        Ok(_) => {},
        Err(e) => {
            log::error!("[WriteConsoleA] Failed to read buffer: {:?}", e);
            emu.reg_write(RegisterX86::RAX, 0)?; // FALSE
            return Ok(());
        }
    }
    
    // Convert buffer to string for display
    let output_string = String::from_utf8_lossy(&buffer);
    
    // Simulate console output
    log::info!("[WriteConsoleA] OUTPUT: {}", output_string);
    
    // Write the number of characters written if the pointer is provided
    if num_chars_written_ptr != 0 {
        let chars_written_bytes = num_chars_to_write.to_le_bytes();
        match emu.mem_write(num_chars_written_ptr, &chars_written_bytes) {
            Ok(_) => {
                log::info!("[WriteConsoleA] Wrote {} to lpNumberOfCharsWritten", num_chars_to_write);
            },
            Err(e) => {
                log::error!("[WriteConsoleA] Failed to write to lpNumberOfCharsWritten: {:?}", e);
                emu.reg_write(RegisterX86::RAX, 0)?; // FALSE
                return Ok(());
            }
        }
    }
    
    log::info!("[WriteConsoleA] Successfully wrote {} characters to console", num_chars_to_write);
    
    // Return TRUE (non-zero) for success
    emu.reg_write(RegisterX86::RAX, 1)?;
    
    Ok(())
}