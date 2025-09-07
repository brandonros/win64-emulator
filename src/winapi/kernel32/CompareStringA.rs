use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};

pub fn CompareStringA(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    // int CompareStringA(
    //   LCID   Locale,    // RCX
    //   DWORD  dwCmpFlags,// RDX
    //   PCNZCH lpString1, // R8
    //   int    cchCount1, // R9
    //   PCNZCH lpString2, // [RSP+0x28]
    //   int    cchCount2  // [RSP+0x30]
    // )
    
    let locale = emu.reg_read(X86Register::RCX)?;
    let dw_cmp_flags = emu.reg_read(X86Register::RDX)?;
    let lp_string1 = emu.reg_read(X86Register::R8)?;
    let cch_count1 = emu.reg_read(X86Register::R9)? as i32;
    
    // Read stack parameters
    let rsp = emu.reg_read(X86Register::RSP)?;
    let mut lp_string2_bytes = [0u8; 8];
    emu.mem_read(rsp + 0x28, &mut lp_string2_bytes)?;
    let lp_string2 = u64::from_le_bytes(lp_string2_bytes);
    
    let mut cch_count2_bytes = [0u8; 4];
    emu.mem_read(rsp + 0x30, &mut cch_count2_bytes)?;
    let cch_count2 = i32::from_le_bytes(cch_count2_bytes);
    
    log::info!("[CompareStringA] Locale: 0x{:x}", locale);
    log::info!("[CompareStringA] dwCmpFlags: 0x{:x}", dw_cmp_flags);
    log::info!("[CompareStringA] lpString1: 0x{:x}", lp_string1);
    log::info!("[CompareStringA] cchCount1: {}", cch_count1);
    log::info!("[CompareStringA] lpString2: 0x{:x}", lp_string2);
    log::info!("[CompareStringA] cchCount2: {}", cch_count2);
    
    // Check for NULL pointers
    if lp_string1 == 0 || lp_string2 == 0 {
        log::warn!("[CompareStringA] NULL string pointer");
        emu.reg_write(X86Register::RAX, 0)?; // Return 0 on error
        return Ok(());
    }
    
    // Read the first string
    let string1 = if cch_count1 == -1 {
        // Null-terminated string
        match crate::emulation::memory::read_string_from_memory(emu, lp_string1) {
            Ok(s) => s,
            Err(_) => {
                log::warn!("[CompareStringA] Failed to read string1");
                emu.reg_write(X86Register::RAX, 0)?;
                return Ok(());
            }
        }
    } else if cch_count1 > 0 {
        // Fixed-length string
        let mut buffer = vec![0u8; cch_count1 as usize];
        if let Err(_) = emu.mem_read(lp_string1, &mut buffer) {
            log::warn!("[CompareStringA] Failed to read string1 buffer");
            emu.reg_write(X86Register::RAX, 0)?;
            return Ok(());
        }
        String::from_utf8_lossy(&buffer).into_owned()
    } else {
        String::new()
    };
    
    // Read the second string
    let string2 = if cch_count2 == -1 {
        // Null-terminated string
        match crate::emulation::memory::read_string_from_memory(emu, lp_string2) {
            Ok(s) => s,
            Err(_) => {
                log::warn!("[CompareStringA] Failed to read string2");
                emu.reg_write(X86Register::RAX, 0)?;
                return Ok(());
            }
        }
    } else if cch_count2 > 0 {
        // Fixed-length string
        let mut buffer = vec![0u8; cch_count2 as usize];
        if let Err(_) = emu.mem_read(lp_string2, &mut buffer) {
            log::warn!("[CompareStringA] Failed to read string2 buffer");
            emu.reg_write(X86Register::RAX, 0)?;
            return Ok(());
        }
        String::from_utf8_lossy(&buffer).into_owned()
    } else {
        String::new()
    };
    
    log::info!("[CompareStringA] Comparing '{}' with '{}'", string1, string2);
    
    // Comparison flags
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
        log::info!("[CompareStringA] Case-insensitive comparison");
        (string1.to_lowercase(), string2.to_lowercase())
    } else {
        (string1.clone(), string2.clone())
    };
    
    // Handle other flags with warnings for unsupported features
    if (dw_cmp_flags as u32) & NORM_IGNORENONSPACE != 0 {
        log::warn!("[CompareStringA] NORM_IGNORENONSPACE not fully implemented");
    }
    if (dw_cmp_flags as u32) & NORM_IGNORESYMBOLS != 0 {
        log::warn!("[CompareStringA] NORM_IGNORESYMBOLS not fully implemented");
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
            log::info!("[CompareStringA] Result: CSTR_LESS_THAN (1)");
            CSTR_LESS_THAN
        }
        std::cmp::Ordering::Equal => {
            log::info!("[CompareStringA] Result: CSTR_EQUAL (2)");
            CSTR_EQUAL
        }
        std::cmp::Ordering::Greater => {
            log::info!("[CompareStringA] Result: CSTR_GREATER_THAN (3)");
            CSTR_GREATER_THAN
        }
    };
    
    log::warn!("[CompareStringA] Mock implementation - simplified locale-aware comparison");
    
    emu.reg_write(X86Register::RAX, result)?;
    
    Ok(())
}