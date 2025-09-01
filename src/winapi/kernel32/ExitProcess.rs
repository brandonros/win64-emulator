use unicorn_engine::{Unicorn, RegisterX86};

pub fn ExitProcess(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    let u_exit_code = emu.reg_read(RegisterX86::RCX)? as u32;
    
    log::info!("[ExitProcess] Process exiting with code: 0x{:x} ({})", u_exit_code, u_exit_code);
    
    // Stop emulation by panicking - this is the intended behavior when a process exits
    panic!("[ExitProcess] Process terminated with exit code: 0x{:x} ({})", u_exit_code, u_exit_code);
}