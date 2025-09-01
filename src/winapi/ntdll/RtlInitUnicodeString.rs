use unicorn_engine::{Unicorn, RegisterX86};
use windows_sys::Win32::Foundation::UNICODE_STRING;
use crate::emulation::memory::utils::{read_wide_string_from_memory, write_struct};

/*
RtlInitUnicodeString function (wdm.h)
02/22/2024
For more information, see the WdmlibRtlInitUnicodeStringEx function.

Syntax
C++

Copy
NTSYSAPI VOID RtlInitUnicodeString(
  [out]          PUNICODE_STRING         DestinationString,
  [in, optional] __drv_aliasesMem PCWSTR SourceString
);
Parameters
[out] DestinationString

For more information, see the WdmlibRtlInitUnicodeStringEx function.

[in, optional] SourceString

For more information, see the WdmlibRtlInitUnicodeStringEx function.

Return value
For more information, see the WdmlibRtlInitUnicodeStringEx function.

Remarks
The RTL_CONSTANT_STRING macro creates a string or Unicode string structure to hold a counted string.

STRING RTL_CONSTANT_STRING(
  [in]  PCSZ SourceString
);

UNICODE_STRING RTL_CONSTANT_STRING(
  [in]  PCWSTR SourceString
);
RTL_CONSTANT_STRING returns either a string structure or Unicode string structure.

The RTL_CONSTANT_STRING macro replaces the RtlInitAnsiString, RtlInitString, and RtlInitUnicodeString routines when passing a constant string.

You can use RTL_CONSTANT_STRING to initialize global variables.


*/

pub fn RtlInitUnicodeString(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // VOID RtlInitUnicodeString(
    //   [out]          PUNICODE_STRING DestinationString,  // RCX
    //   [in, optional] PCWSTR          SourceString        // RDX
    // )
    
    let dest_string_ptr = emu.reg_read(RegisterX86::RCX)?;
    let source_string_ptr = emu.reg_read(RegisterX86::RDX)?;
    
    log::info!("[RtlInitUnicodeString] DestinationString: 0x{:x}", dest_string_ptr);
    log::info!("[RtlInitUnicodeString] SourceString: 0x{:x}", source_string_ptr);
    
    // Check for NULL destination pointer
    if dest_string_ptr == 0 {
        log::error!("[RtlInitUnicodeString] NULL DestinationString pointer");
        // Even though this returns void, we should probably not crash
        return Ok(());
    }
    
    let unicode_string = if source_string_ptr == 0 {
        // If source is NULL, initialize an empty UNICODE_STRING
        log::info!("[RtlInitUnicodeString] SourceString is NULL, initializing empty UNICODE_STRING");
        UNICODE_STRING {
            Length: 0,
            MaximumLength: 0,
            Buffer: std::ptr::null_mut(),
        }
    } else {
        // Read the wide string to calculate its length
        match read_wide_string_from_memory(emu, source_string_ptr) {
            Ok(string) => {
                // Calculate length in bytes (not including null terminator)
                // Each wide character is 2 bytes
                let length_in_chars = string.encode_utf16().count();
                let length_in_bytes = (length_in_chars * 2) as u16;
                
                // MaximumLength includes the null terminator
                let max_length = length_in_bytes + 2;
                
                log::info!("[RtlInitUnicodeString] Source string: '{}'", string);
                log::info!("[RtlInitUnicodeString] Length: {} bytes, MaximumLength: {} bytes", 
                          length_in_bytes, max_length);
                
                UNICODE_STRING {
                    Length: length_in_bytes,
                    MaximumLength: max_length,
                    Buffer: source_string_ptr as *mut u16,
                }
            }
            Err(e) => {
                log::error!("[RtlInitUnicodeString] Failed to read source string: {:?}", e);
                // Even on error, initialize with the pointer but zero lengths
                UNICODE_STRING {
                    Length: 0,
                    MaximumLength: 0,
                    Buffer: source_string_ptr as *mut u16,
                }
            }
        }
    };
    
    // Write the UNICODE_STRING structure to the destination using write_struct
    write_struct(emu, dest_string_ptr, &unicode_string)?;
    
    log::info!("[RtlInitUnicodeString] Initialized UNICODE_STRING structure:");
    log::info!("  Length: {} bytes", unicode_string.Length);
    log::info!("  MaximumLength: {} bytes", unicode_string.MaximumLength);
    log::info!("  Buffer: 0x{:x}", unicode_string.Buffer as u64);
    
    // RtlInitUnicodeString returns void, no return value to set
    Ok(())
}