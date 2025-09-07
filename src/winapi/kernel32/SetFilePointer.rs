use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};

use crate::winapi;

pub fn SetFilePointer(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    // DWORD SetFilePointer(
    //   HANDLE hFile,
    //   LONG lDistanceToMove,
    //   PLONG lpDistanceToMoveHigh,
    //   DWORD dwMoveMethod
    // )
    
    let h_file = emu.reg_read(X86Register::RCX)?;
    let l_distance_to_move = emu.reg_read(X86Register::RDX)?;
    let lp_distance_to_move_high = emu.reg_read(X86Register::R8)?;
    let dw_move_method = emu.reg_read(X86Register::R9)?;
    
    log::info!("[SetFilePointer] hFile: 0x{:x}, lDistanceToMove: {}, lpDistanceToMoveHigh: 0x{:x}, dwMoveMethod: {}",
              h_file, l_distance_to_move, lp_distance_to_move_high, dw_move_method);

    // Invalid handle check
    if h_file != 0x14 && h_file != 0x18 && !(h_file >= 0x100 && h_file <= 0x1000) {
        log::warn!("[SetFilePointer] Invalid handle: 0x{:x} ERROR_INVALID_HANDLE", h_file);
        winapi::set_last_error(emu, windows_sys::Win32::Foundation::ERROR_INVALID_HANDLE)?;
        emu.reg_write(X86Register::RAX, 0xFFFFFFFF)?; // INVALID_SET_FILE_POINTER
        return Ok(());
    }
    
    // Standard handles don't support seeking
    if h_file == 0x10 || h_file == 0x14 || h_file == 0x18 {
        log::warn!("[SetFilePointer] Cannot seek on standard handle: 0x{:x}", h_file);
        winapi::set_last_error(emu, windows_sys::Win32::Foundation::ERROR_INVALID_FUNCTION)?;
        emu.reg_write(X86Register::RAX, 0xFFFFFFFF)?;
        return Ok(());
    }
    
    // Just return success with position 0 for simplicity
    if lp_distance_to_move_high != 0 {
        emu.mem_write(lp_distance_to_move_high, &0u32.to_le_bytes())?;
    }
    
    emu.reg_write(X86Register::RAX, 0)?; // Return position 0
    
    log::info!("[SetFilePointer] Set file pointer to position 0");
    
    Ok(())
}
