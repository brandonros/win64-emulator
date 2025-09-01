use unicorn_engine::{Unicorn, RegisterX86};
use crate::emulation::memory::heap_manager::HEAP_ALLOCATIONS;

/*
SysReAllocStringLen function (oleauto.h)
02/22/2024
Creates a new BSTR containing a specified number of characters from an old BSTR, and frees the old BSTR.

Syntax
C++

Copy
INT SysReAllocStringLen(
  [in, out]      BSTR          *pbstr,
  [in, optional] const OLECHAR *psz,
  [in]           unsigned int  len
);
Parameters
[in, out] pbstr

The previously allocated string.

[in, optional] psz

The string from which to copy len characters, or NULL to keep the string uninitialized.

[in] len

The number of characters to copy. A null character is placed afterward, allocating a total of len plus one characters.

Return value
Return code	Description
TRUE
The string is reallocated successfully.
FALSE
Insufficient memory exists.
Remarks
Allocates a new string, copies len characters from the passed string into it, and then appends a null character. Frees the BSTR referenced currently by pbstr, and resets pbstr to point to the new BSTR. If psz is null, a string of length len is allocated but not initialized.

The psz string can contain embedded null characters and does not need to end with a null.

If this function is passed a NULL pointer, there will be an access violation and the program will crash. It is your responsibility to protect this function against NULL pointers.

typedef [string] char   OLECHAR, *LPOLESTR;
typedef WCHAR OLECHAR;
typedef OLECHAR* BSTR;
typedef BSTR* LPBSTR;
*/

pub fn SysReAllocStringLen(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // INT SysReAllocStringLen(
    //   [in, out]      BSTR          *pbstr,  // RCX
    //   [in, optional] const OLECHAR *psz,    // RDX
    //   [in]           unsigned int  len      // R8
    // )
    
    let pbstr = emu.reg_read(RegisterX86::RCX)?;
    let psz = emu.reg_read(RegisterX86::RDX)?;
    let len = emu.reg_read(RegisterX86::R8)? as u32;
    
    log::info!("[SysReAllocStringLen] pbstr: 0x{:x}", pbstr);
    log::info!("[SysReAllocStringLen] psz: 0x{:x}", psz);
    log::info!("[SysReAllocStringLen] len: {}", len);
    
    // Check for NULL pbstr pointer (would cause access violation)
    if pbstr == 0 {
        log::error!("[SysReAllocStringLen] NULL pbstr pointer - would crash!");
        emu.reg_write(RegisterX86::RAX, 0)?; // Return FALSE
        return Ok(());
    }
    
    // Read the current BSTR pointer from pbstr
    let mut current_bstr_bytes = [0u8; 8];
    emu.mem_read(pbstr, &mut current_bstr_bytes)?;
    let current_bstr = u64::from_le_bytes(current_bstr_bytes);
    
    log::info!("[SysReAllocStringLen] Current BSTR at *pbstr: 0x{:x}", current_bstr);
    
    // BSTR format:
    // [-4 bytes: length] [string data] [null terminator]
    // The BSTR pointer points to the string data, not the length prefix
    
    // Calculate new allocation size
    // len characters * 2 bytes per OLECHAR (wide char) + 4 byte length prefix + 2 byte null terminator
    let string_data_size = (len as usize) * 2;
    let total_size = 4 + string_data_size + 2; // TODO add 16 padding as a workaround?
    
    // Allocate new memory for the BSTR
    let alloc_addr = {
        let mut heap = HEAP_ALLOCATIONS.lock().unwrap();
        match heap.allocate(total_size) {
            Ok(addr) => addr,
            Err(e) => {
                log::error!("[SysReAllocStringLen] Failed to allocate memory: {}", e);
                emu.reg_write(RegisterX86::RAX, 0)?; // Return FALSE
                return Ok(());
            }
        }
    };
    
    // Write the length prefix (in bytes, not characters)
    let length_bytes = (string_data_size as u32).to_le_bytes();
    emu.mem_write(alloc_addr, &length_bytes)?;
    
    // The BSTR pointer points to the string data, not the length prefix
    let new_bstr = alloc_addr + 4;
    
    // Copy string data if psz is provided
    if psz != 0 {
        // Copy len wide characters from psz
        let mut buffer = vec![0u8; string_data_size];
        if let Err(e) = emu.mem_read(psz, &mut buffer) {
            log::warn!("[SysReAllocStringLen] Failed to read source string: {:?}", e);
            // Continue anyway - string will be uninitialized as per spec
        } else {
            // Write the string data to the new BSTR
            emu.mem_write(new_bstr, &buffer)?;
            
            // Log the string content for debugging
            let wide_chars: Vec<u16> = buffer
                .chunks_exact(2)
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                .collect();
            let string_content = String::from_utf16_lossy(&wide_chars);
            log::info!("[SysReAllocStringLen] Copied string: '{}'", string_content);
        }
    } else {
        log::info!("[SysReAllocStringLen] psz is NULL - leaving string uninitialized");
    }
    
    // Write null terminator after the string data
    let null_terminator = [0u8, 0u8];
    emu.mem_write(new_bstr + string_data_size as u64, &null_terminator)?;
    
    // Free the old BSTR if it exists
    if current_bstr != 0 {
        // BSTR pointer points to string data, actual allocation starts 4 bytes before
        let old_alloc_start = current_bstr - 4;
        {
            let mut heap = HEAP_ALLOCATIONS.lock().unwrap();
            match heap.free(old_alloc_start, emu) {
                Ok(_) => {
                    log::info!("[SysReAllocStringLen] Freed old BSTR allocation at 0x{:x}", old_alloc_start);
                }
                Err(e) => {
                    log::warn!("[SysReAllocStringLen] Failed to free old BSTR: {}", e);
                    // Continue anyway - we've already allocated the new BSTR
                }
            }
        }
    }
    
    // Update the BSTR pointer at pbstr
    let new_bstr_bytes = new_bstr.to_le_bytes();
    emu.mem_write(pbstr, &new_bstr_bytes)?;
    
    log::warn!("[SysReAllocStringLen] Mock implementation - allocated new BSTR at 0x{:x}", new_bstr);
    log::info!("[SysReAllocStringLen] Updated *pbstr to point to new BSTR");
    
    // Return TRUE (non-zero) to indicate success
    emu.reg_write(RegisterX86::RAX, 1)?;
    
    Ok(())
}