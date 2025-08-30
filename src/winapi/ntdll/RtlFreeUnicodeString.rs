use unicorn_engine::{Unicorn, RegisterX86};
use windows_sys::Win32::Foundation::UNICODE_STRING;
use crate::emulation::memory;

/*
RtlFreeUnicodeString function (winternl.h)
02/22/2024
Frees the string buffer allocated by RtlAnsiStringToUnicodeString or by RtlUpcaseUnicodeString.

Syntax
C++

Copy
VOID RtlFreeUnicodeString(
  [in, out] PUNICODE_STRING UnicodeString
);
Parameters
[in, out] UnicodeString

A pointer to the Unicode string whose buffer was previously allocated by RtlAnsiStringToUnicodeString.

Return value
None

Remarks
This routine does not release the ANSI string buffer passed to RtlAnsiStringToUnicodeString or RtlUpcaseUnicodeString.

Because there is no import library for this function, you must use GetProcAddress.
*/

pub fn RtlFreeUnicodeString(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // VOID RtlFreeUnicodeString(
    //   [in, out] PUNICODE_STRING UnicodeString  // RCX
    // )
    
    let unicode_string_ptr = emu.reg_read(RegisterX86::RCX)?;
    
    log::info!("[RtlFreeUnicodeString] UnicodeString: 0x{:x}", unicode_string_ptr);
    
    if unicode_string_ptr == 0 {
        log::warn!("[RtlFreeUnicodeString] NULL UnicodeString pointer");
        return Ok(());
    }
    
    // Read the UNICODE_STRING structure
    if let Ok(unicode_str) = memory::read_struct::<UNICODE_STRING>(emu, unicode_string_ptr) {
        let buffer_ptr = unicode_str.Buffer as u64;
        
        if buffer_ptr != 0 {
            log::info!("[RtlFreeUnicodeString] Freeing buffer at: 0x{:x}", buffer_ptr);
            
            // In a real implementation, this would call RtlFreeHeap or ExFreePool
            // For our mock implementation, we just log that we would free it
            
            // Clear the UNICODE_STRING structure
            let cleared_unicode_string = UNICODE_STRING {
                Length: 0,
                MaximumLength: 0,
                Buffer: std::ptr::null_mut(),
            };
            
            // Write the cleared structure back to memory
            memory::write_struct(emu, unicode_string_ptr, &cleared_unicode_string)?;
            
            log::info!("[RtlFreeUnicodeString] Cleared UNICODE_STRING structure");
        } else {
            log::info!("[RtlFreeUnicodeString] Buffer is already NULL, nothing to free");
        }
    }
    
    log::warn!("[RtlFreeUnicodeString] Mock implementation - buffer not actually freed");
    
    // RtlFreeUnicodeString returns void, no return value to set
    Ok(())
}