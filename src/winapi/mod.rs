use unicorn_engine::Unicorn;

use crate::emulation::memory::{TEB_BASE, TEB_LAST_ERROR_VALUE_OFFSET};

pub mod structures;
pub mod kernel32;
pub mod module_registry;
pub mod heap_manager;

pub fn handle_winapi_call<D>(emu: &mut Unicorn<D>, dll_name: &str, function_name: &str) {
    // Cast the generic Unicorn to the specific type we need
    let emu_ptr = emu as *mut Unicorn<D> as *mut Unicorn<()>;
    let emu_ref = unsafe { &mut *emu_ptr };
    
    match (dll_name.to_lowercase().as_str(), function_name) {
        ("kernel32.dll", "GetModuleHandleA") => kernel32::GetModuleHandleA(emu_ref).unwrap(),
        ("kernel32.dll", "LoadLibraryA") => kernel32::LoadLibraryA(emu_ref).unwrap(),
        ("kernel32.dll", "GetProcAddress") => kernel32::GetProcAddress(emu_ref).unwrap(),
        ("kernel32.dll", "GetCurrentThreadId") => kernel32::GetCurrentThreadId(emu_ref).unwrap(),
        ("kernel32.dll", "GetStartupInfoA") => kernel32::GetStartupInfoA(emu_ref).unwrap(),
        ("kernel32.dll", "TlsAlloc") => kernel32::TlsAlloc(emu_ref).unwrap(),
        ("kernel32.dll", "TlsGetValue") => kernel32::TlsGetValue(emu_ref).unwrap(),
        ("kernel32.dll", "TlsSetValue") => kernel32::TlsSetValue(emu_ref).unwrap(),        
        ("kernel32.dll", "GetLastError") => kernel32::GetLastError(emu_ref).unwrap(),
        ("kernel32.dll", "SetLastError") => kernel32::SetLastError(emu_ref).unwrap(),
        ("kernel32.dll", "LocalAlloc") => kernel32::LocalAlloc(emu_ref).unwrap(),
        _ => {
            panic!("Unimplemented API call: {}!{}", dll_name, function_name);
        }
    }
}

// Helper function you can add to your module
pub fn set_last_error(emu: &mut Unicorn<()>, error_code: u32) -> Result<(), unicorn_engine::uc_error> {
    let error_addr = TEB_BASE + TEB_LAST_ERROR_VALUE_OFFSET;
    emu.mem_write(error_addr, &error_code.to_le_bytes())
}
