use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};

pub fn ExitProcess(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    let u_exit_code = emu.reg_read(X86Register::RCX)? as u32;
    
    log::info!("[ExitProcess] Process exiting with code: 0x{:x} ({})", u_exit_code, u_exit_code);
    
    // Stop emulation by panicking - this is the intended behavior when a process exits
    panic!("[ExitProcess] Process terminated with exit code: 0x{:x} ({})", u_exit_code, u_exit_code);
}