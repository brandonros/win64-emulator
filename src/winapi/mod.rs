use unicorn_engine::Unicorn;

use crate::emulation::memory::{TEB_BASE, TEB_LAST_ERROR_VALUE_OFFSET};

mod locale;
mod kernel32;
mod user32;

pub fn handle_winapi_call<D>(
    emu: &mut Unicorn<D>,
    dll_name: &str,
    function_name: &str,
) -> Result<(), unicorn_engine::uc_error> {
    // Cast the generic Unicorn to the specific type we need
    let emu_ptr = emu as *mut Unicorn<D> as *mut Unicorn<()>;
    let emu_ref = unsafe { &mut *emu_ptr };

    match (dll_name.to_lowercase().as_str(), function_name) {
        // kernel32
        ("kernel32.dll", "GetModuleHandleA") => kernel32::GetModuleHandleA(emu_ref),
        ("kernel32.dll", "LoadLibraryA") => kernel32::LoadLibraryA(emu_ref),
        ("kernel32.dll", "GetProcAddress") => kernel32::GetProcAddress(emu_ref),
        ("kernel32.dll", "GetCurrentThreadId") => kernel32::GetCurrentThreadId(emu_ref),
        ("kernel32.dll", "GetStartupInfoA") => kernel32::GetStartupInfoA(emu_ref),
        ("kernel32.dll", "TlsAlloc") => kernel32::TlsAlloc(emu_ref),
        ("kernel32.dll", "TlsGetValue") => kernel32::TlsGetValue(emu_ref),
        ("kernel32.dll", "TlsSetValue") => kernel32::TlsSetValue(emu_ref),
        ("kernel32.dll", "GetLastError") => kernel32::GetLastError(emu_ref),
        ("kernel32.dll", "SetLastError") => kernel32::SetLastError(emu_ref),
        ("kernel32.dll", "LocalAlloc") => kernel32::LocalAlloc(emu_ref),
        ("kernel32.dll", "InitializeCriticalSection") => kernel32::InitializeCriticalSection(emu_ref),
        ("kernel32.dll", "GetACP") => kernel32::GetACP(emu_ref),
        ("kernel32.dll", "GetStdHandle") => kernel32::GetStdHandle(emu_ref),
        ("kernel32.dll", "GetConsoleCP") => kernel32::GetConsoleCP(emu_ref),
        ("kernel32.dll", "GetConsoleOutputCP") => kernel32::GetConsoleOutputCP(emu_ref),
        ("kernel32.dll", "GetModuleFileNameA") => kernel32::GetModuleFileNameA(emu_ref),
        ("kernel32.dll", "GetProcessHeap") => kernel32::GetProcessHeap(emu_ref),
        ("kernel32.dll", "HeapAlloc") => kernel32::HeapAlloc(emu_ref),
        ("kernel32.dll", "GetCommandLineA") => kernel32::GetCommandLineA(emu_ref),
        ("kernel32.dll", "GetCurrentProcessId") => kernel32::GetCurrentProcessId(emu_ref),
        ("kernel32.dll", "GetCPInfo") => kernel32::GetCPInfo(emu_ref),
        ("kernel32.dll", "GetUserDefaultLCID") => kernel32::GetUserDefaultLCID(emu_ref),
        ("kernel32.dll", "SetThreadLocale") => kernel32::SetThreadLocale(emu_ref),
        ("kernel32.dll", "GetThreadLocale") => kernel32::GetThreadLocale(emu_ref),
        ("kernel32.dll", "GetLocaleInfoA") => kernel32::GetLocaleInfoA(emu_ref),
        ("kernel32.dll", "GetLocaleInfoW") => kernel32::GetLocaleInfoW(emu_ref),
        ("kernel32.dll", "WideCharToMultiByte") => kernel32::WideCharToMultiByte(emu_ref),

        // user32
        ("user32.dll", "GetSystemMetrics") => user32::GetSystemMetrics(emu_ref),

        _ => {
            panic!("Unimplemented API call: {}!{}", dll_name, function_name);
        }
    }
}

// Helper function you can add to your module
pub fn set_last_error(
    emu: &mut Unicorn<()>,
    error_code: u32,
) -> Result<(), unicorn_engine::uc_error> {
    let error_addr = TEB_BASE + TEB_LAST_ERROR_VALUE_OFFSET;
    emu.mem_write(error_addr, &error_code.to_le_bytes())
}
