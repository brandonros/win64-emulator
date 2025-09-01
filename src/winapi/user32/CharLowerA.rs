use unicorn_engine::{Unicorn, RegisterX86};
use crate::emulation::memory::utils::read_string_from_memory;

/*
CharLowerA function (winuser.h)
11/19/2024
Converts a character string or a single character to lowercase. If the operand is a character string, the function converts the characters in place.

Syntax
C++

Copy
LPSTR CharLowerA(
  [in, out] LPSTR lpsz
);
Parameters
[in, out] lpsz

Type: LPTSTR

A null-terminated string, or specifies a single character. If the high-order word of this parameter is zero, the low-order word must contain a single character to be converted.

Return value
Type: LPTSTR

If the operand is a character string, the function returns a pointer to the converted string. Because the string is converted in place, the return value is equal to lpsz.

If the operand is a single character, the return value is a 32-bit value whose high-order word is zero, and low-order word contains the converted character.

There is no indication of success or failure. Failure is rare. There is no extended error information for this function; do not call GetLastError.
*/

pub fn CharLowerA(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // LPSTR CharLowerA(
    //   [in, out] LPSTR lpsz  // RCX
    // )
    
    let lpsz = emu.reg_read(RegisterX86::RCX)?;
    
    log::info!("[CharLowerA] lpsz: 0x{:x}", lpsz);
    
    // Check if this is a single character or a string pointer
    // If the high-order word is zero (value < 0x10000), it's a single character
    if lpsz < 0x10000 {
        // Single character conversion
        let character = (lpsz & 0xFF) as u8;
        log::info!("[CharLowerA] Single character mode: '{}' (0x{:02x})", 
                  character as char, character);
        
        // Convert to lowercase
        let lower_char = if character >= b'A' && character <= b'Z' {
            character + 32  // Convert uppercase to lowercase
        } else {
            character  // Already lowercase or not a letter
        };
        
        log::info!("[CharLowerA] Converted to: '{}' (0x{:02x})", 
                  lower_char as char, lower_char);
        
        // Return the converted character in the low-order word
        emu.reg_write(RegisterX86::RAX, lower_char as u64)?;
    } else {
        // String conversion mode
        log::info!("[CharLowerA] String mode: pointer at 0x{:x}", lpsz);
        
        // Read the string from memory
        match read_string_from_memory(emu, lpsz) {
            Ok(original_string) => {
                log::info!("[CharLowerA] Original string: '{}'", original_string);
                
                // Convert to lowercase
                let lower_string = original_string.to_lowercase();
                log::info!("[CharLowerA] Converted string: '{}'", lower_string);
                
                // Write the converted string back to memory (in-place conversion)
                let lower_bytes = lower_string.as_bytes();
                
                // Write the converted string
                match emu.mem_write(lpsz, lower_bytes) {
                    Ok(_) => {
                        // Write null terminator
                        emu.mem_write(lpsz + lower_bytes.len() as u64, &[0u8])?;
                        log::info!("[CharLowerA] Successfully converted string in place");
                    }
                    Err(e) => {
                        log::error!("[CharLowerA] Failed to write converted string: {:?}", e);
                        // Still return the original pointer even on write failure
                    }
                }
                
                // Return the original pointer (string was converted in place)
                emu.reg_write(RegisterX86::RAX, lpsz)?;
            }
            Err(e) => {
                log::error!("[CharLowerA] Failed to read string from memory: {:?}", e);
                // Return the original pointer even on failure (per documentation)
                emu.reg_write(RegisterX86::RAX, lpsz)?;
            }
        }
    }
    
    Ok(())
}