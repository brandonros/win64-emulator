#![allow(non_snake_case)]

use common::types::*;

use std::ffi::CString;
use std::ptr;

// GetUserNameA - Retrieves the name of the user associated with the current thread
#[unsafe(no_mangle)]
pub extern "system" fn GetUserNameA(
    lpBuffer: *mut u8,     // LPSTR
    pcbBuffer: *mut DWORD, // LPDWORD
) -> i32 {
    // BOOL return type (0 = FALSE, non-zero = TRUE)
    
    // Check for NULL pcbBuffer pointer
    if pcbBuffer.is_null() {
        log::error!("[GetUserNameA] NULL pcbBuffer pointer");
        // In a real implementation, we'd call SetLastError(ERROR_INVALID_PARAMETER)
        return 0; // FALSE
    }
    
    // Mock username
    let username = "TestUser";
    let username_with_null = CString::new(username).unwrap();
    let username_bytes = username_with_null.as_bytes_with_nul();
    let required_size = username_bytes.len() as DWORD;
    
    unsafe {
        // Read the buffer size
        let buffer_size = *pcbBuffer;
        
        log::info!("[GetUserNameA] Buffer size: {} characters, required: {}", buffer_size, required_size);
        
        // Check if buffer is large enough
        if buffer_size < required_size {
            log::warn!("[GetUserNameA] Buffer too small: need {} characters, got {}", required_size, buffer_size);
            
            // Write required size back to pcbBuffer
            *pcbBuffer = required_size;
            
            // In a real implementation, we'd call SetLastError(ERROR_INSUFFICIENT_BUFFER)
            return 0; // FALSE
        }
        
        // Write username to buffer if lpBuffer is provided
        if !lpBuffer.is_null() {
            // Copy the username string including null terminator
            ptr::copy_nonoverlapping(
                username_bytes.as_ptr(),
                lpBuffer,
                username_bytes.len(),
            );
            
            log::info!("[GetUserNameA] Wrote username: '{}'", username);
        }
        
        // Write actual length to pcbBuffer (including null terminator)
        *pcbBuffer = required_size;
        
        log::info!("[GetUserNameA] Mock implementation - returned username: '{}'", username);
    }
    
    1 // TRUE (success)
}