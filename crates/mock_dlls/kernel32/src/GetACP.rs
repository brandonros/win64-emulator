#![allow(non_snake_case)]

use common::types::*;

// GetACP - Get ANSI Code Page
#[unsafe(no_mangle)]
pub extern "system" fn GetACP() -> UINT {
    // 1252 = Windows-1252 (Latin 1) - most common Western European code page
    // Other common values:
    // - 437 (OEM United States)
    // - 65001 (UTF-8)
    let code_page: UINT = 1252;
    
    log::info!("[GetACP] Returning code page: {}", code_page);
    
    code_page
}
