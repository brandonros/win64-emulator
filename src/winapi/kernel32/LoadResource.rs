use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};

pub fn LoadResource(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    // HGLOBAL LoadResource(
    //   HMODULE hModule,  // RCX
    //   HRSRC   hResInfo  // RDX
    // )
    
    let h_module = emu.reg_read(X86Register::RCX)?;
    let h_res_info = emu.reg_read(X86Register::RDX)?;
    
    log::info!("[LoadResource] hModule: 0x{:x}", h_module);
    log::info!("[LoadResource] hResInfo: 0x{:x}", h_res_info);
    
    // Check for NULL resource handle
    if h_res_info == 0 {
        log::warn!("[LoadResource] NULL resource handle");
        emu.reg_write(X86Register::RAX, 0)?;
        return Ok(());
    }
    
    // In a real implementation, this would:
    // - Use the HRSRC handle from FindResource/FindResourceEx
    // - Load the actual resource data from the PE file
    // - Return a global memory handle to the resource data
    
    // For mock implementation, we'll return a fake global memory handle
    // The handle should be different from the HRSRC handle
    // In Windows, LoadResource doesn't actually load anything - it just
    // returns a handle to the already-mapped resource data
    
    // Generate a mock global memory handle based on the resource handle
    // We'll use a different range to distinguish from HRSRC handles
    let hglobal = if h_res_info >= 0x500000 && h_res_info < 0x700000 {
        // This looks like one of our mock HRSRC handles
        // Convert it to a mock HGLOBAL handle
        h_res_info + 0x1000000  // Offset to different range
    } else {
        // Unknown resource handle
        log::warn!("[LoadResource] Unknown resource handle format: 0x{:x}", h_res_info);
        0
    };
    
    if hglobal != 0 {
        log::info!("[LoadResource] Resource loaded successfully! Returning HGLOBAL: 0x{:x}", hglobal);
        
        // In a real implementation, we'd map the resource data here
        // For mock, we'll just track that this resource was loaded
        log::warn!("[LoadResource] Mock implementation - not actually loading resource data");
    } else {
        log::info!("[LoadResource] Failed to load resource");
    }
    
    emu.reg_write(X86Register::RAX, hglobal)?;
    
    Ok(())
}