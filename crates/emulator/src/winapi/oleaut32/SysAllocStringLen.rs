use unicorn_engine::{Unicorn, RegisterX86};
use crate::emulation::memory::heap_manager::HEAP_ALLOCATIONS;

/*
SysAllocStringLen function (oleauto.h)
02/22/2024
Allocates a new string, copies the specified number of characters from the passed string, and appends a null-terminating character.

Syntax
C++

Copy
BSTR SysAllocStringLen(
  [in] const OLECHAR *strIn,
  [in] UINT          ui
);
Parameters
[in] strIn

The input string.

[in] ui

The number of characters to copy. A null character is placed afterwards, allocating a total of ui plus one characters.

Return value
A copy of the string, or NULL if there is insufficient memory to complete the operation.

Remarks
The string can contain embedded null characters and does not need to end with a NULL. Free the returned string later with SysFreeString. If strIn is not NULL, then the memory allocated to strIn must be at least ui characters long.

Note  This function does not convert a char * string into a Unicode BSTR.
*/

pub fn SysAllocStringLen(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // BSTR SysAllocStringLen(
    //   [in] const OLECHAR *strIn,  // RCX
    //   [in] UINT          ui        // RDX
    // )
    
    let str_in = emu.reg_read(RegisterX86::RCX)?;
    let ui = emu.reg_read(RegisterX86::RDX)? as u32;
    
    log::info!("[SysAllocStringLen] strIn: 0x{:x}", str_in);
    log::info!("[SysAllocStringLen] ui: {} characters", ui);
    
    // BSTR format:
    // [-4 bytes: length] [string data] [null terminator]
    // The BSTR pointer points to the string data, not the length prefix
    
    // Calculate allocation size
    // ui characters * 2 bytes per OLECHAR (wide char) + 4 byte length prefix + 2 byte null terminator
    let string_data_size = (ui as usize) * 2;
    let total_size = 4 + string_data_size + 2;
    
    // Allocate memory for the BSTR
    let alloc_addr = {
        let mut heap = HEAP_ALLOCATIONS.lock().unwrap();
        match heap.allocate(total_size) {
            Ok(addr) => addr,
            Err(e) => {
                log::error!("[SysAllocStringLen] Failed to allocate memory: {}", e);
                emu.reg_write(RegisterX86::RAX, 0)?; // Return NULL
                return Ok(());
            }
        }
    };
    
    // Write the length prefix (in bytes, not characters)
    let length_bytes = (string_data_size as u32).to_le_bytes();
    emu.mem_write(alloc_addr, &length_bytes)?;
    
    // The BSTR pointer points to the string data, not the length prefix
    let bstr = alloc_addr + 4;
    
    // Copy string data if strIn is provided
    if str_in != 0 && ui > 0 {
        // Copy ui wide characters from strIn
        let mut buffer = vec![0u8; string_data_size];
        match emu.mem_read(str_in, &mut buffer) {
            Ok(_) => {
                // Write the string data to the BSTR
                emu.mem_write(bstr, &buffer)?;
                
                // Log the string content for debugging
                let wide_chars: Vec<u16> = buffer
                    .chunks_exact(2)
                    .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                    .collect();
                let string_content = String::from_utf16_lossy(&wide_chars);
                log::info!("[SysAllocStringLen] Copied string: '{}'", string_content);
            }
            Err(e) => {
                log::warn!("[SysAllocStringLen] Failed to read source string: {:?}", e);
                // Continue anyway - string will be uninitialized
                // But still allocate the memory as per spec
            }
        }
    } else if str_in == 0 {
        log::info!("[SysAllocStringLen] strIn is NULL - allocating uninitialized BSTR of length {}", ui);
        // Leave the string data uninitialized (already zero from allocation)
    } else {
        log::info!("[SysAllocStringLen] ui is 0 - allocating empty BSTR");
    }
    
    // Write null terminator after the string data
    let null_terminator = [0u8, 0u8];
    emu.mem_write(bstr + string_data_size as u64, &null_terminator)?;
    
    log::warn!("[SysAllocStringLen] Mock implementation - allocated BSTR at 0x{:x}", bstr);
    log::info!("[SysAllocStringLen] BSTR header at 0x{:x}, data at 0x{:x}", alloc_addr, bstr);
    
    // Return the BSTR pointer (points to string data, not the length prefix)
    emu.reg_write(RegisterX86::RAX, bstr)?;
    
    Ok(())
}