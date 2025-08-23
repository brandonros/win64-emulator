use unicorn_engine::{Unicorn, RegisterX86};

pub fn CompareStringW(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // int CompareStringW(
    //   LCID   Locale,    // RCX
    //   DWORD  dwCmpFlags,// RDX
    //   PCNZWCH lpString1, // R8
    //   int    cchCount1, // R9
    //   PCNZWCH lpString2, // [RSP+0x28]
    //   int    cchCount2  // [RSP+0x30]
    // )
    
    let locale = emu.reg_read(RegisterX86::RCX)?;
    let dw_cmp_flags = emu.reg_read(RegisterX86::RDX)?;
    let lp_string1 = emu.reg_read(RegisterX86::R8)?;
    let cch_count1 = emu.reg_read(RegisterX86::R9)? as i32;
    
    // Read stack parameters
    let rsp = emu.reg_read(RegisterX86::RSP)?;
    let mut lp_string2_bytes = [0u8; 8];
    emu.mem_read(rsp + 0x28, &mut lp_string2_bytes)?;
    let lp_string2 = u64::from_le_bytes(lp_string2_bytes);
    
    let mut cch_count2_bytes = [0u8; 4];
    emu.mem_read(rsp + 0x30, &mut cch_count2_bytes)?;
    let cch_count2 = i32::from_le_bytes(cch_count2_bytes);
    
    log::info!("[CompareStringW] Locale: 0x{:x}", locale);
    log::info!("[CompareStringW] dwCmpFlags: 0x{:x}", dw_cmp_flags);
    log::info!("[CompareStringW] lpString1: 0x{:x}", lp_string1);
    log::info!("[CompareStringW] cchCount1: {}", cch_count1);
    log::info!("[CompareStringW] lpString2: 0x{:x}", lp_string2);
    log::info!("[CompareStringW] cchCount2: {}", cch_count2);
    
    // Check for NULL pointers
    if lp_string1 == 0 || lp_string2 == 0 {
        log::warn!("[CompareStringW] NULL string pointer");
        emu.reg_write(RegisterX86::RAX, 0)?; // Return 0 on error
        return Ok(());
    }
    
    // Read the first wide string
    let string1 = if cch_count1 == -1 {
        // Null-terminated wide string
        match crate::emulation::memory::read_wide_string_from_memory(emu, lp_string1) {
            Ok(s) => s,
            Err(_) => {
                log::warn!("[CompareStringW] Failed to read wide string1");
                emu.reg_write(RegisterX86::RAX, 0)?;
                return Ok(());
            }
        }
    } else if cch_count1 > 0 {
        // Fixed-length wide string
        let byte_count = (cch_count1 as usize) * 2; // 2 bytes per wide char
        let mut buffer = vec![0u8; byte_count];
        if let Err(_) = emu.mem_read(lp_string1, &mut buffer) {
            log::warn!("[CompareStringW] Failed to read string1 buffer");
            emu.reg_write(RegisterX86::RAX, 0)?;
            return Ok(());
        }
        // Convert bytes to UTF-16 and then to String
        let wide_chars: Vec<u16> = buffer
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();
        String::from_utf16_lossy(&wide_chars)
    } else {
        String::new()
    };
    
    // Read the second wide string
    let string2 = if cch_count2 == -1 {
        // Null-terminated wide string
        match crate::emulation::memory::read_wide_string_from_memory(emu, lp_string2) {
            Ok(s) => s,
            Err(_) => {
                log::warn!("[CompareStringW] Failed to read wide string2");
                emu.reg_write(RegisterX86::RAX, 0)?;
                return Ok(());
            }
        }
    } else if cch_count2 > 0 {
        // Fixed-length wide string
        let byte_count = (cch_count2 as usize) * 2; // 2 bytes per wide char
        let mut buffer = vec![0u8; byte_count];
        if let Err(_) = emu.mem_read(lp_string2, &mut buffer) {
            log::warn!("[CompareStringW] Failed to read string2 buffer");
            emu.reg_write(RegisterX86::RAX, 0)?;
            return Ok(());
        }
        // Convert bytes to UTF-16 and then to String
        let wide_chars: Vec<u16> = buffer
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();
        String::from_utf16_lossy(&wide_chars)
    } else {
        String::new()
    };
    
    log::info!("[CompareStringW] Comparing '{}' with '{}'", string1, string2);
    
    // Comparison flags (same as CompareStringA)
    const NORM_IGNORECASE: u32 = 0x00000001;
    const NORM_IGNORENONSPACE: u32 = 0x00000002;
    const NORM_IGNORESYMBOLS: u32 = 0x00000004;
    const LINGUISTIC_IGNORECASE: u32 = 0x00000010;
    const LINGUISTIC_IGNOREDIACRITIC: u32 = 0x00000020;
    const NORM_IGNOREKANATYPE: u32 = 0x00010000;
    const NORM_IGNOREWIDTH: u32 = 0x00020000;
    const NORM_LINGUISTIC_CASING: u32 = 0x08000000;
    const SORT_STRINGSORT: u32 = 0x00001000;
    
    // Apply comparison flags (simplified implementation)
    let (cmp_string1, cmp_string2) = if (dw_cmp_flags as u32) & NORM_IGNORECASE != 0 {
        log::info!("[CompareStringW] Case-insensitive comparison");
        (string1.to_lowercase(), string2.to_lowercase())
    } else if (dw_cmp_flags as u32) & LINGUISTIC_IGNORECASE != 0 {
        log::info!("[CompareStringW] Linguistic case-insensitive comparison");
        (string1.to_lowercase(), string2.to_lowercase())
    } else {
        (string1.clone(), string2.clone())
    };
    
    // Handle other flags with warnings for unsupported features
    if (dw_cmp_flags as u32) & NORM_IGNORENONSPACE != 0 {
        log::warn!("[CompareStringW] NORM_IGNORENONSPACE not fully implemented");
    }
    if (dw_cmp_flags as u32) & NORM_IGNORESYMBOLS != 0 {
        log::warn!("[CompareStringW] NORM_IGNORESYMBOLS not fully implemented");
    }
    if (dw_cmp_flags as u32) & NORM_IGNOREKANATYPE != 0 {
        log::warn!("[CompareStringW] NORM_IGNOREKANATYPE not implemented (Japanese)");
    }
    if (dw_cmp_flags as u32) & NORM_IGNOREWIDTH != 0 {
        log::warn!("[CompareStringW] NORM_IGNOREWIDTH not implemented (East Asian)");
    }
    
    // Perform comparison
    // Return values:
    // CSTR_LESS_THAN    = 1  (string1 < string2)
    // CSTR_EQUAL        = 2  (string1 == string2)
    // CSTR_GREATER_THAN = 3  (string1 > string2)
    // 0 = error
    
    const CSTR_LESS_THAN: u64 = 1;
    const CSTR_EQUAL: u64 = 2;
    const CSTR_GREATER_THAN: u64 = 3;
    
    let result = match cmp_string1.cmp(&cmp_string2) {
        std::cmp::Ordering::Less => {
            log::info!("[CompareStringW] Result: CSTR_LESS_THAN (1)");
            CSTR_LESS_THAN
        }
        std::cmp::Ordering::Equal => {
            log::info!("[CompareStringW] Result: CSTR_EQUAL (2)");
            CSTR_EQUAL
        }
        std::cmp::Ordering::Greater => {
            log::info!("[CompareStringW] Result: CSTR_GREATER_THAN (3)");
            CSTR_GREATER_THAN
        }
    };
    
    log::warn!("[CompareStringW] Mock implementation - simplified locale-aware comparison");
    
    emu.reg_write(RegisterX86::RAX, result)?;
    
    Ok(())
}