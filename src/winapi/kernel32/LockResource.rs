use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};

pub fn LockResource(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    // LPVOID LockResource(
    //   HGLOBAL hResData  // RCX
    // )
    
    let h_res_data = emu.reg_read(X86Register::RCX)?;
    
    log::info!("[LockResource] hResData: 0x{:x}", h_res_data);
    
    // Check for NULL resource data handle
    if h_res_data == 0 {
        log::warn!("[LockResource] NULL resource data handle");
        emu.reg_write(X86Register::RAX, 0)?;
        return Ok(());
    }
    
    // In a real implementation, this would:
    // - Take the HGLOBAL handle from LoadResource
    // - Lock the memory (though on modern Windows this is a no-op)
    // - Return a pointer to the actual resource data
    
    // For mock implementation, we'll return a pointer to mock resource data
    // The pointer should be different from the HGLOBAL handle
    
    let data_ptr = if h_res_data >= 0x1500000 && h_res_data < 0x1700000 {
        // This looks like one of our mock HGLOBAL handles from LoadResource
        // Convert it to a mock data pointer
        // We'll allocate some mock memory for the resource data
        
        // Use a different memory range for resource data
        static mut NEXT_RESOURCE_DATA_PTR: u64 = 0x2000000;
        let resource_data_ptr = unsafe {
            NEXT_RESOURCE_DATA_PTR += 0x10000;  // 64KB apart
            NEXT_RESOURCE_DATA_PTR
        };
        
        // In a real implementation, we'd actually have resource data here
        // For mock, we could optionally write some dummy data to memory
        
        // Get the resource size (we'd need to track this from SizeofResource)
        // For now, just use a default size
        let mock_data_size = 1024;  // 1KB of mock data
        
        // Optionally write some mock data
        let mock_data = vec![0x4Du8, 0x5A];  // MZ header for PE files
        if let Err(e) = emu.mem_write(resource_data_ptr, &mock_data) {
            log::warn!("[LockResource] Failed to write mock resource data: {:?}", e);
            // Continue anyway - the pointer is still valid
        }
        
        log::info!("[LockResource] Returning data pointer: 0x{:x} (mock data size: {} bytes)", 
                  resource_data_ptr, mock_data_size);
        resource_data_ptr
    } else if h_res_data >= 0x500000 && h_res_data < 0x700000 {
        // This might be an HRSRC handle passed directly (incorrect usage)
        log::warn!("[LockResource] Warning: HRSRC handle passed instead of HGLOBAL from LoadResource");
        // Return NULL for incorrect usage
        0
    } else {
        // Unknown handle format
        log::warn!("[LockResource] Unknown resource data handle format: 0x{:x}", h_res_data);
        // In Windows, LockResource often just returns the handle itself
        // as modern Windows doesn't actually lock memory
        h_res_data
    };
    
    if data_ptr != 0 {
        log::info!("[LockResource] Resource locked successfully!");
        log::warn!("[LockResource] Mock implementation - returning simulated data pointer");
    } else {
        log::info!("[LockResource] Failed to lock resource");
    }
    
    emu.reg_write(X86Register::RAX, data_ptr)?;
    
    Ok(())
}