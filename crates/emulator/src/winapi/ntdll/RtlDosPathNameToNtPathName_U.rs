use unicorn_engine::{Unicorn, RegisterX86};
use windows_sys::Win32::Foundation::UNICODE_STRING;

/*
RtlDosPathNameToNtPathName_U_WithStatus function
09/14/2023
Converts a DOS path name to an NT path name.

Syntax
C++

Copy
NTSTATUS RtlDosPathNameToNtPathName_U_WithStatus(
    __in PCWSTR DosFileName,
    __out PUNICODE_STRING NtFileName,
    __deref_opt_out_opt PWSTR *FilePart,
    __reserved PVOID Reserved
    )
Parameters
DosFileName [in]
A pointer to a DOS file name path.

PUNICODE_STRING [out]
A pointer to a reference-counted Unicode string structure containing a Win32-style NT path name.

FilePart [out, optional]
If present, supplies a pointer to a variable which, on success, receives a pointer to the base name portion of the output NT path name.

Reserved
Reserved.

Return value
An NTSTATUS code. For more information, see Using NTSTATUS values.

Remarks
This function has no associated import library or header file; you must call it using the LoadLibrary and GetProcAddress functions. The API is exported from ntdll.dll.
*/

pub fn RtlDosPathNameToNtPathName_U(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // BOOLEAN RtlDosPathNameToNtPathName_U(
    //   [in]  PCWSTR DosFileName,             // RCX
    //   [out] PUNICODE_STRING NtFileName,     // RDX
    //   [out] PWSTR *FilePart,                // R8
    //   [out] PRTL_RELATIVE_NAME_U RelativeName // R9
    // )
    
    let dos_file_name = emu.reg_read(RegisterX86::RCX)?;
    let nt_file_name = emu.reg_read(RegisterX86::RDX)?;
    let file_part = emu.reg_read(RegisterX86::R8)?;
    let relative_name = emu.reg_read(RegisterX86::R9)?;
    
    log::info!("[RtlDosPathNameToNtPathName_U] DosFileName: 0x{:x}", dos_file_name);
    log::info!("[RtlDosPathNameToNtPathName_U] NtFileName: 0x{:x}", nt_file_name);
    log::info!("[RtlDosPathNameToNtPathName_U] FilePart: 0x{:x}", file_part);
    log::info!("[RtlDosPathNameToNtPathName_U] RelativeName: 0x{:x}", relative_name);
    
    // Check for NULL pointers
    if dos_file_name == 0 || nt_file_name == 0 {
        log::error!("[RtlDosPathNameToNtPathName_U] NULL pointer in required parameters");
        emu.reg_write(RegisterX86::RAX, 0u64)?; // FALSE
        return Ok(());
    }
    
    // Read the DOS path from memory
    let mut dos_path_bytes = vec![0u8; 2048]; // Support longer paths
    emu.mem_read(dos_file_name, &mut dos_path_bytes)?;
    
    // Convert bytes to wide chars and find null terminator
    let mut dos_path_wide = Vec::new();
    for chunk in dos_path_bytes.chunks_exact(2) {
        let wchar = u16::from_le_bytes([chunk[0], chunk[1]]);
        if wchar == 0 {
            break;
        }
        dos_path_wide.push(wchar);
    }
    
    let dos_path_str = String::from_utf16_lossy(&dos_path_wide);
    log::info!("[RtlDosPathNameToNtPathName_U] DOS path: '{}'", dos_path_str);
    
    // Convert DOS path to NT path format based on the Stack Overflow discussion
    let nt_path = if dos_path_str.starts_with("\\\\?\\") {
        // \\?\ prefix - convert to \??\ by replacing second backslash
        // This bypasses path parsing according to the SO discussion
        format!("\\??\\{}", &dos_path_str[4..])
    } else if dos_path_str.starts_with("\\\\.\\") {
        // \\.\  device namespace - keep as is but convert to NT format
        format!("\\??\\{}", &dos_path_str[4..])
    } else if dos_path_str.starts_with("\\??\\") {
        // Already in NT format - keep as is
        dos_path_str.clone()
    } else if dos_path_str.starts_with("\\\\") {
        // UNC path - \\server\share -> \??\UNC\server\share
        format!("\\??\\UNC{}", &dos_path_str[1..])
    } else if dos_path_str.len() >= 2 && dos_path_str.chars().nth(1) == Some(':') {
        // Drive letter path - C:\path -> \??\C:\path
        format!("\\??\\{}", dos_path_str)
    } else {
        // Relative path - need to expand to full path first
        // In a real implementation, this would get the current directory
        // For simulation, we'll assume current directory is C:\Windows\System32
        let current_dir = "C:\\Windows\\System32";
        let full_path = if dos_path_str.starts_with('\\') {
            // Root-relative path
            format!("C:{}", dos_path_str)
        } else {
            // Relative path
            format!("{}\\{}", current_dir, dos_path_str)
        };
        format!("\\??\\{}", full_path)
    };
    
    log::info!("[RtlDosPathNameToNtPathName_U] NT path: '{}'", nt_path);
    
    // Handle path normalization (.. and . handling) unless \\?\ was used
    let normalized_path = if !dos_path_str.starts_with("\\\\?\\") {
        // Normalize the path (remove . and .. components)
        normalize_path(&nt_path)
    } else {
        // \\?\ prefix disables normalization
        nt_path.clone()
    };
    
    // Convert NT path to wide string
    let nt_path_wide: Vec<u16> = normalized_path.encode_utf16().collect();
    let nt_path_bytes = nt_path_wide.len() * 2;
    
    // Check for MAX_PATH limitation (260 characters) unless \\?\ prefix was used
    // According to SO, \??\ prefix still has MAX_PATH limitation
    if !dos_path_str.starts_with("\\\\?\\") && nt_path_wide.len() > 260 {
        log::warn!("[RtlDosPathNameToNtPathName_U] Path exceeds MAX_PATH without \\\\?\\ prefix");
        emu.reg_write(RegisterX86::RAX, 0u64)?; // FALSE
        return Ok(());
    }
    
    // Allocate memory for NT path wide string
    // In real implementation this would use RtlAllocateHeap
    let nt_path_buffer = 0x10000000u64;
    
    // Write NT path to allocated memory
    let mut buffer = Vec::with_capacity(nt_path_bytes + 2);
    for &wchar in &nt_path_wide {
        buffer.extend_from_slice(&wchar.to_le_bytes());
    }
    buffer.extend_from_slice(&[0u8, 0u8]); // null terminator
    
    emu.mem_write(nt_path_buffer, &buffer)?;
    
    // Set up UNICODE_STRING structure
    let unicode_string = UNICODE_STRING {
        Length: nt_path_bytes as u16,
        MaximumLength: (nt_path_bytes + 2) as u16,
        Buffer: nt_path_buffer as *mut u16,
    };
    
    // Write UNICODE_STRING to NtFileName
    let unicode_bytes = unsafe {
        std::slice::from_raw_parts(
            &unicode_string as *const UNICODE_STRING as *const u8,
            std::mem::size_of::<UNICODE_STRING>(),
        )
    };
    emu.mem_write(nt_file_name, unicode_bytes)?;
    
    // Set FilePart if requested - points to the filename component
    if file_part != 0 {
        // Find last backslash to get filename part
        if let Some(last_backslash_pos) = normalized_path.rfind('\\') {
            // Calculate offset in wide chars
            let prefix_len = normalized_path[..last_backslash_pos + 1]
                .encode_utf16()
                .count() as u64;
            let filename_ptr = nt_path_buffer + (prefix_len * 2);
            emu.mem_write(file_part, &filename_ptr.to_le_bytes())?;
        } else {
            // No backslash found, entire path is filename
            emu.mem_write(file_part, &nt_path_buffer.to_le_bytes())?;
        }
    }
    
    // Clear RelativeName if provided
    if relative_name != 0 {
        // RTL_RELATIVE_NAME_U structure
        let zero_bytes = vec![0u8; 32];
        emu.mem_write(relative_name, &zero_bytes)?;
    }
    
    log::info!("[RtlDosPathNameToNtPathName_U] Conversion successful");
    log::debug!("[RtlDosPathNameToNtPathName_U] Converted '{}' to '{}'", 
               dos_path_str, normalized_path);
    
    // Return TRUE (success)
    emu.reg_write(RegisterX86::RAX, 1u64)?;
    
    Ok(())
}

// Helper function to normalize paths (remove . and .. components)
/*fn normalize_path(path: &str) -> String {
    let mut components = Vec::new();
    let mut result = String::new();
    
    // Keep the prefix (\??\)
    if let Some(prefix_end) = path.find("\\??\\") {
        result.push_str("\\??\\");
        let remainder = &path[4..];
        
        // Split the remainder into components
        for component in remainder.split('\\') {
            match component {
                "" | "." => {
                    // Skip empty and current directory references
                }
                ".." => {
                    // Go up one directory if possible
                    components.pop();
                }
                _ => {
                    components.push(component);
                }
            }
        }
        
        // Rebuild the path
        result.push_str(&components.join("\\"));
        result
    } else {
        // No recognized prefix, return as-is
        path.to_string()
    }
}*/

fn normalize_path(path: &str) -> String {
    let mut result = String::new();
    
    // Keep the prefix (\??\)
    if path.starts_with("\\??\\") {
        result.push_str("\\??\\");
        let remainder = &path[4..];
        
        // Handle drive letter
        let normalized_remainder = if remainder.len() >= 2 && remainder.chars().nth(1) == Some(':') {
            let mut chars = remainder.chars();
            let drive = chars.next().unwrap().to_ascii_uppercase();
            format!("{}{}", drive, chars.collect::<String>())
        } else {
            remainder.to_string()
        };
        
        // Split into components and normalize
        let mut components = Vec::new();
        for component in normalized_remainder.split('\\') {
            match component {
                "" => {
                    // Keep empty component at the beginning (after drive:)
                    if components.is_empty() || components.len() == 1 {
                        components.push(component);
                    }
                }
                "." => {
                    // Skip current directory references
                }
                ".." => {
                    // Go up one directory if possible (but not past drive root)
                    if components.len() > 2 {  // Keep drive: and first \
                        components.pop();
                    }
                }
                _ => {
                    components.push(component);
                }
            }
        }
        
        // Rebuild the path
        result.push_str(&components.join("\\"));
        result
    } else {
        // No recognized prefix, return as-is
        path.to_string()
    }
}

