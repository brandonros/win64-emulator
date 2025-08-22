use unicorn_engine::{RegisterX86, Unicorn};
use crate::emulation::memory;

pub fn FormatMessageW(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // DWORD FormatMessageW(
    //   DWORD   dwFlags,
    //   LPCVOID lpSource,
    //   DWORD   dwMessageId,
    //   DWORD   dwLanguageId,
    //   LPWSTR  lpBuffer,
    //   DWORD   nSize,
    //   va_list *Arguments
    // );
    
    let dw_flags = emu.reg_read(RegisterX86::RCX)? as u32;
    let lp_source = emu.reg_read(RegisterX86::RDX)?;
    let dw_message_id = emu.reg_read(RegisterX86::R8)? as u32;
    let dw_language_id = emu.reg_read(RegisterX86::R9)? as u32;
    
    // Get remaining parameters from stack
    let rsp = emu.reg_read(RegisterX86::RSP)?;
    let lp_buffer_bytes = emu.mem_read_as_vec(rsp + 0x28, 8)?;
    let lp_buffer = u64::from_le_bytes(lp_buffer_bytes.try_into().unwrap());
    
    let n_size_bytes = emu.mem_read_as_vec(rsp + 0x30, 8)?;
    let n_size = u64::from_le_bytes(n_size_bytes.try_into().unwrap()) as u32;
    
    log::info!("[FormatMessageW] dwFlags: 0x{:x}, lpSource: 0x{:x}, dwMessageId: {}, dwLanguageId: {}, lpBuffer: 0x{:x}, nSize: {}",
              dw_flags, lp_source, dw_message_id, dw_language_id, lp_buffer, n_size);

    // Simple generic error message
    let message = "Unknown error occurred\0";
    let wide_message: Vec<u16> = message.encode_utf16().collect();
    
    if lp_buffer != 0 && n_size > 0 {
        let bytes_to_write = std::cmp::min(wide_message.len() * 2, (n_size as usize - 2));
        let bytes: Vec<u8> = wide_message.iter()
            .take(bytes_to_write / 2)
            .flat_map(|&c| c.to_le_bytes())
            .collect();
        
        emu.mem_write(lp_buffer, &bytes)?;
        
        // Null terminate
        if bytes_to_write < (n_size as usize - 2) {
            emu.mem_write(lp_buffer + bytes_to_write as u64, &[0u8, 0u8])?;
        }
    }
    
    // Return number of characters written (excluding null terminator)
    let chars_written = std::cmp::min(wide_message.len() - 1, (n_size as usize / 2).saturating_sub(1));
    emu.reg_write(RegisterX86::RAX, chars_written as u64)?;
    
    log::info!("[FormatMessageW] Returned generic message, {} characters", chars_written);
    
    Ok(())
}