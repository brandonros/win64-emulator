use unicorn_engine::Unicorn;

use crate::emulation::memory::{TEB_BASE, TEB_LAST_ERROR_VALUE_OFFSET};

mod locale;
mod kernel32;
mod user32;
mod ntdll;

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
        ("kernel32.dll", "EnterCriticalSection") => kernel32::EnterCriticalSection(emu_ref),        
        ("kernel32.dll", "GetACP") => kernel32::GetACP(emu_ref),
        ("kernel32.dll", "GetCommandLineA") => kernel32::GetCommandLineA(emu_ref),
        ("kernel32.dll", "GetConsoleCP") => kernel32::GetConsoleCP(emu_ref),
        ("kernel32.dll", "GetConsoleOutputCP") => kernel32::GetConsoleOutputCP(emu_ref),
        ("kernel32.dll", "GetCPInfo") => kernel32::GetCPInfo(emu_ref),
        ("kernel32.dll", "GetCurrentProcessId") => kernel32::GetCurrentProcessId(emu_ref),
        ("kernel32.dll", "GetCurrentThreadId") => kernel32::GetCurrentThreadId(emu_ref),
        ("kernel32.dll", "GetLastError") => kernel32::GetLastError(emu_ref),
        ("kernel32.dll", "GetLocaleInfoA") => kernel32::GetLocaleInfoA(emu_ref),
        ("kernel32.dll", "GetLocaleInfoW") => kernel32::GetLocaleInfoW(emu_ref),
        ("kernel32.dll", "GetModuleFileNameA") => kernel32::GetModuleFileNameA(emu_ref),
        ("kernel32.dll", "GetModuleHandleA") => kernel32::GetModuleHandleA(emu_ref),
        ("kernel32.dll", "GetProcAddress") => kernel32::GetProcAddress(emu_ref),
        ("kernel32.dll", "GetProcessHeap") => kernel32::GetProcessHeap(emu_ref),
        ("kernel32.dll", "GetStartupInfoA") => kernel32::GetStartupInfoA(emu_ref),
        ("kernel32.dll", "GetStdHandle") => kernel32::GetStdHandle(emu_ref),
        ("kernel32.dll", "GetThreadLocale") => kernel32::GetThreadLocale(emu_ref),
        ("kernel32.dll", "GetUserDefaultLCID") => kernel32::GetUserDefaultLCID(emu_ref),
        ("kernel32.dll", "GetVersionExA") => kernel32::GetVersionExA(emu_ref),
        ("kernel32.dll", "GetWindowsDirectoryA") => kernel32::GetWindowsDirectoryA(emu_ref),
        ("kernel32.dll", "HeapAlloc") => kernel32::HeapAlloc(emu_ref),
        ("kernel32.dll", "HeapCreate") => kernel32::HeapCreate(emu_ref),        
        ("kernel32.dll", "LeaveCriticalSection") => kernel32::LeaveCriticalSection(emu_ref),                
        ("kernel32.dll", "InitializeCriticalSection") => kernel32::InitializeCriticalSection(emu_ref),
        ("kernel32.dll", "LoadLibraryA") => kernel32::LoadLibraryA(emu_ref),
        ("kernel32.dll", "LocalAlloc") => kernel32::LocalAlloc(emu_ref),
        ("kernel32.dll", "SetLastError") => kernel32::SetLastError(emu_ref),
        ("kernel32.dll", "SetThreadLocale") => kernel32::SetThreadLocale(emu_ref),
        ("kernel32.dll", "TlsAlloc") => kernel32::TlsAlloc(emu_ref),
        ("kernel32.dll", "TlsFree") => kernel32::TlsFree(emu_ref),
        ("kernel32.dll", "TlsGetValue") => kernel32::TlsGetValue(emu_ref),
        ("kernel32.dll", "TlsSetValue") => kernel32::TlsSetValue(emu_ref),
        ("kernel32.dll", "WideCharToMultiByte") => kernel32::WideCharToMultiByte(emu_ref),
        ("kernel32.dll", "VirtualAlloc") => kernel32::VirtualAlloc(emu_ref),
        ("kernel32.dll", "VirtualFree") => kernel32::VirtualFree(emu_ref),
        ("kernel32.dll", "GetCurrentProcess") => kernel32::GetCurrentProcess(emu_ref),
        ("kernel32.dll", "ReadProcessMemory") => kernel32::ReadProcessMemory(emu_ref),        
        ("kernel32.dll", "GetSystemTimeAsFileTime") => kernel32::GetSystemTimeAsFileTime(emu_ref),        
        ("kernel32.dll", "QueryPerformanceCounter") => kernel32::QueryPerformanceCounter(emu_ref),                
        ("kernel32.dll", "WriteFile") => kernel32::WriteFile(emu_ref),
        ("kernel32.dll", "ReadFile") => kernel32::ReadFile(emu_ref),
        ("kernel32.dll", "CloseHandle") => kernel32::CloseHandle(emu_ref),
        ("kernel32.dll", "SetFilePointer") => kernel32::SetFilePointer(emu_ref),        
        ("kernel32.dll", "LoadLibraryW") => kernel32::LoadLibraryW(emu_ref),        
        ("kernel32.dll", "FreeLibrary") => kernel32::FreeLibrary(emu_ref),        
        ("kernel32.dll", "FormatMessageW") => kernel32::FormatMessageW(emu_ref),        
        ("kernel32.dll", "CreateFileW") => kernel32::CreateFileW(emu_ref),        
        ("kernel32.dll", "GetOEMCP") => kernel32::GetOEMCP(emu_ref),        
        ("kernel32.dll", "HeapFree") => kernel32::HeapFree(emu_ref),                

        // user32
        ("user32.dll", "GetSystemMetrics") => user32::GetSystemMetrics(emu_ref),

        // ntdll
        ("ntdll.dll", "RtlAddFunctionTable") => ntdll::RtlAddFunctionTable(emu_ref),

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
