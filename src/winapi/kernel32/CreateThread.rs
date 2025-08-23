use unicorn_engine::{Unicorn, RegisterX86};

pub fn CreateThread(emu: &mut Unicorn<()>) -> Result<(), unicorn_engine::uc_error> {
    // HANDLE CreateThread(
    //   LPSECURITY_ATTRIBUTES   lpThreadAttributes,  // RCX
    //   SIZE_T                  dwStackSize,         // RDX
    //   LPTHREAD_START_ROUTINE  lpStartAddress,      // R8
    //   LPVOID                  lpParameter,         // R9
    //   DWORD                   dwCreationFlags,     // [RSP+40]
    //   LPDWORD                 lpThreadId           // [RSP+48]
    // )
    
    let thread_attributes = emu.reg_read(RegisterX86::RCX)?;
    let stack_size = emu.reg_read(RegisterX86::RDX)?;
    let start_address = emu.reg_read(RegisterX86::R8)?;
    let parameter = emu.reg_read(RegisterX86::R9)?;
    
    // Read stack parameters
    let rsp = emu.reg_read(RegisterX86::RSP)?;
    let mut creation_flags_bytes = [0u8; 4];
    emu.mem_read(rsp + 0x40, &mut creation_flags_bytes)?;
    let creation_flags = u32::from_le_bytes(creation_flags_bytes);
    
    let mut thread_id_ptr_bytes = [0u8; 8];
    emu.mem_read(rsp + 0x48, &mut thread_id_ptr_bytes)?;
    let thread_id_ptr = u64::from_le_bytes(thread_id_ptr_bytes);
    
    log::info!("[CreateThread] lpThreadAttributes: 0x{:x}", thread_attributes);
    log::info!("[CreateThread] dwStackSize: 0x{:x}", stack_size);
    log::info!("[CreateThread] lpStartAddress: 0x{:x}", start_address);
    log::info!("[CreateThread] lpParameter: 0x{:x}", parameter);
    log::info!("[CreateThread] dwCreationFlags: 0x{:x}", creation_flags);
    log::info!("[CreateThread] lpThreadId: 0x{:x}", thread_id_ptr);
    
    // Generate a mock thread handle
    static mut NEXT_THREAD_HANDLE: u64 = 0x200;
    static mut NEXT_THREAD_ID: u32 = 0x2000;
    
    let thread_handle = unsafe {
        NEXT_THREAD_HANDLE += 0x10;
        NEXT_THREAD_HANDLE
    };
    
    let thread_id = unsafe {
        NEXT_THREAD_ID += 4;
        NEXT_THREAD_ID
    };
    
    // If thread ID pointer is provided, write the thread ID
    if thread_id_ptr != 0 {
        emu.mem_write(thread_id_ptr, &thread_id.to_le_bytes())?;
        log::info!("[CreateThread] Wrote thread ID {} to 0x{:x}", thread_id, thread_id_ptr);
    }
    
    // Check for CREATE_SUSPENDED flag
    const CREATE_SUSPENDED: u32 = 0x00000004;
    if (creation_flags & CREATE_SUSPENDED) != 0 {
        log::info!("[CreateThread] Thread created in suspended state (mock)");
    } else {
        log::info!("[CreateThread] Thread started immediately (mock)");
    }
    
    log::warn!("[CreateThread] Returning mock thread handle 0x{:x} (thread not actually created)", thread_handle);
    
    // Return the mock thread handle
    emu.reg_write(RegisterX86::RAX, thread_handle)?;
    
    Ok(())
}