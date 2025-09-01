use unicorn_engine::{Unicorn, RegisterX86};

pub fn VirtualLock(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // BOOL VirtualLock(
    //   LPVOID lpAddress,  // RCX
    //   SIZE_T dwSize      // RDX
    // )
    
    let address = emu.reg_read(RegisterX86::RCX)?;
    let size = emu.reg_read(RegisterX86::RDX)?;
    
    log::info!("[VirtualLock] address: 0x{:x}, size: 0x{:x}", address, size);
    
    // Mock implementation - just return success
    // In a real implementation, this would lock pages in physical memory
    // For emulation purposes, we just pretend it succeeded
    
    // Return TRUE (1) for success
    emu.reg_write(RegisterX86::RAX, 1)?;
    
    log::info!("[VirtualLock] Locked {} bytes at 0x{:x} (mock)", size, address);
    
    Ok(())
}