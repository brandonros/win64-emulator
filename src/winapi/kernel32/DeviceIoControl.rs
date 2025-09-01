use unicorn_engine::{Unicorn, RegisterX86};

pub fn DeviceIoControl(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    let h_device = emu.reg_read(RegisterX86::RCX)?;
    let dw_io_control_code = emu.reg_read(RegisterX86::RDX)? as u32;
    let lp_in_buffer = emu.reg_read(RegisterX86::R8)?;
    let n_in_buffer_size = emu.reg_read(RegisterX86::R9)? as u32;
    
    // Read stack parameters
    let rsp = emu.reg_read(RegisterX86::RSP)?;
    let mut lp_out_buffer_bytes = [0u8; 8];
    emu.mem_read(rsp + 0x40, &mut lp_out_buffer_bytes)?;
    let lp_out_buffer = u64::from_le_bytes(lp_out_buffer_bytes);
    
    let mut n_out_buffer_size_bytes = [0u8; 4];
    emu.mem_read(rsp + 0x48, &mut n_out_buffer_size_bytes)?;
    let n_out_buffer_size = u32::from_le_bytes(n_out_buffer_size_bytes);
    
    let mut lp_bytes_returned_bytes = [0u8; 8];
    emu.mem_read(rsp + 0x50, &mut lp_bytes_returned_bytes)?;
    let lp_bytes_returned = u64::from_le_bytes(lp_bytes_returned_bytes);
    
    let mut lp_overlapped_bytes = [0u8; 8];
    emu.mem_read(rsp + 0x58, &mut lp_overlapped_bytes)?;
    let lp_overlapped = u64::from_le_bytes(lp_overlapped_bytes);
    
    log::info!("[DeviceIoControl] hDevice: 0x{:x}, dwIoControlCode: 0x{:08x}", h_device, dw_io_control_code);
    log::info!("[DeviceIoControl] lpInBuffer: 0x{:x}, nInBufferSize: {}", lp_in_buffer, n_in_buffer_size);
    log::info!("[DeviceIoControl] lpOutBuffer: 0x{:x}, nOutBufferSize: {}", lp_out_buffer, n_out_buffer_size);
    log::info!("[DeviceIoControl] lpBytesReturned: 0x{:x}, lpOverlapped: 0x{:x}", lp_bytes_returned, lp_overlapped);
    
    // Panic on overlapped I/O
    if lp_overlapped != 0 {
        panic!("[DeviceIoControl] Overlapped I/O not supported (advanced feature)");
    }
    
    // For most control codes, just return success with 0 bytes
    // In a real implementation, you'd handle specific control codes
    if lp_bytes_returned != 0 {
        emu.mem_write(lp_bytes_returned, &0u32.to_le_bytes())?;
    }
    
    // Log warning for unhandled control codes
    log::warn!("[DeviceIoControl] Control code 0x{:08x} not implemented, returning success", dw_io_control_code);
    
    // Return success
    emu.reg_write(RegisterX86::RAX, 1)?;
    
    Ok(())
}