use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};

pub fn SizeofResource(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    // DWORD SizeofResource(
    //   HMODULE hModule,  // RCX
    //   HRSRC   hResInfo  // RDX
    // )
    
    let h_module = emu.reg_read(X86Register::RCX)?;
    let h_res_info = emu.reg_read(X86Register::RDX)?;
    
    log::info!("[SizeofResource] hModule: 0x{:x}", h_module);
    log::info!("[SizeofResource] hResInfo: 0x{:x}", h_res_info);
    
    // Check for NULL resource handle
    if h_res_info == 0 {
        log::warn!("[SizeofResource] NULL resource handle");
        emu.reg_write(X86Register::RAX, 0)?;
        return Ok(());
    }
    
    // In a real implementation, this would:
    // - Use the HRSRC handle from FindResource/FindResourceEx
    // - Look up the resource in the PE file
    // - Return the size of the resource data in bytes
    
    // For mock implementation, return reasonable sizes based on resource handle
    // We can use the handle value to generate consistent sizes
    let size = if h_res_info >= 0x500000 && h_res_info < 0x700000 {
        // This looks like one of our mock HRSRC handles
        // Generate a reasonable size based on the handle
        
        // Extract some bits from the handle to determine resource type
        let handle_id = (h_res_info - 0x500000) / 0x100;
        
        let resource_size = match handle_id {
            0..=10 => {
                // Small resources (icons, cursors)
                log::info!("[SizeofResource] Small resource type");
                1024 + (handle_id * 256)  // 1KB - 3.5KB
            }
            11..=20 => {
                // Medium resources (dialogs, string tables)
                log::info!("[SizeofResource] Medium resource type");
                4096 + (handle_id * 512)  // 4KB - 14KB
            }
            21..=30 => {
                // Large resources (bitmaps, version info)
                log::info!("[SizeofResource] Large resource type");
                16384 + (handle_id * 1024)  // 16KB - 46KB
            }
            31..=40 => {
                // Very large resources (manifest, RCDATA)
                log::info!("[SizeofResource] Very large resource type");
                65536 + (handle_id * 2048)  // 64KB - 144KB
            }
            _ => {
                // Default size for unknown resources
                log::info!("[SizeofResource] Default resource size");
                8192  // 8KB default
            }
        };
        resource_size
    } else if h_res_info >= 0x600000 && h_res_info < 0x700000 {
        // This might be a FindResourceEx handle with language info
        // Use similar logic but account for language variants
        let base_size = 8192;  // 8KB base
        let language_offset = (h_res_info & 0xFFFF) as u64;  // Language ID affects size slightly
        base_size + (language_offset * 16)  // Small variation based on language
    } else {
        // Unknown resource handle
        log::warn!("[SizeofResource] Unknown resource handle format: 0x{:x}", h_res_info);
        0
    };
    
    if size != 0 {
        log::info!("[SizeofResource] Resource size: {} bytes (0x{:x})", size, size);
        log::warn!("[SizeofResource] Mock implementation - returning simulated resource size");
    } else {
        log::info!("[SizeofResource] Failed to get resource size");
    }
    
    // Return as DWORD (32-bit)
    emu.reg_write(X86Register::RAX, size & 0xFFFFFFFF)?;
    
    Ok(())
}