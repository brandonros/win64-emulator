use crate::emulation::engine::{EmulatorEngine, EmulatorError};
use crate::emulation::memory::{TEB_BASE, TEB_LAST_ERROR_VALUE_OFFSET};

mod locale;
mod kernel32;
mod user32;
mod ntdll;
mod oleaut32;
mod advapi32;
mod shell32;
mod version;
mod uxtheme;
mod ole32;
mod gdi32;
mod comctl32;
mod ucrtbase;
mod msvcrt;

pub fn handle_winapi_call(
    emu: &mut dyn EmulatorEngine,
    dll_name: &str,
    function_name: &str,
) -> Result<(), EmulatorError> {
    match (dll_name.to_lowercase().as_str(), function_name) {
        // kernel32
        ("kernel32.dll", "CloseHandle") => kernel32::CloseHandle(emu),
        ("kernel32.dll", "CompareStringA") => kernel32::CompareStringA(emu),
        ("kernel32.dll", "CompareStringW") => kernel32::CompareStringW(emu),
        ("kernel32.dll", "CreateEventA") => kernel32::CreateEventA(emu),
        ("kernel32.dll", "CreateFileW") => kernel32::CreateFileW(emu),
        ("kernel32.dll", "CreateThread") => kernel32::CreateThread(emu),
        ("kernel32.dll", "DebugBreak") => kernel32::DebugBreak(emu),
        ("kernel32.dll", "DeleteCriticalSection") => kernel32::DeleteCriticalSection(emu),
        ("kernel32.dll", "EnterCriticalSection") => kernel32::EnterCriticalSection(emu),
        ("kernel32.dll", "EnumCalendarInfoA") => kernel32::EnumCalendarInfoA(emu),
        ("kernel32.dll", "EnumResourceLanguagesA") => kernel32::EnumResourceLanguagesA(emu),
        ("kernel32.dll", "EnumResourceNamesA") => kernel32::EnumResourceNamesA(emu),
        ("kernel32.dll", "EnumResourceTypesA") => kernel32::EnumResourceTypesA(emu),
        ("kernel32.dll", "ExitThread") => kernel32::ExitThread(emu),
        ("kernel32.dll", "FindResourceA") => kernel32::FindResourceA(emu),
        ("kernel32.dll", "FindResourceExA") => kernel32::FindResourceExA(emu),
        ("kernel32.dll", "FormatMessageW") => kernel32::FormatMessageW(emu),
        ("kernel32.dll", "FreeLibrary") => kernel32::FreeLibrary(emu),
        ("kernel32.dll", "FreeResource") => kernel32::FreeResource(emu),
        ("kernel32.dll", "GetACP") => kernel32::GetACP(emu),
        ("kernel32.dll", "GetCommandLineA") => kernel32::GetCommandLineA(emu),
        ("kernel32.dll", "GetConsoleCP") => kernel32::GetConsoleCP(emu),
        ("kernel32.dll", "GetConsoleOutputCP") => kernel32::GetConsoleOutputCP(emu),
        ("kernel32.dll", "GetCPInfo") => kernel32::GetCPInfo(emu),
        ("kernel32.dll", "GetCurrentProcess") => kernel32::GetCurrentProcess(emu),
        ("kernel32.dll", "GetCurrentProcessId") => kernel32::GetCurrentProcessId(emu),
        ("kernel32.dll", "GetCurrentThread") => kernel32::GetCurrentThread(emu),
        ("kernel32.dll", "GetCurrentThreadId") => kernel32::GetCurrentThreadId(emu),
        ("kernel32.dll", "GetLastError") => kernel32::GetLastError(emu),
        ("kernel32.dll", "GetLocaleInfoA") => kernel32::GetLocaleInfoA(emu),
        ("kernel32.dll", "GetLocaleInfoW") => kernel32::GetLocaleInfoW(emu),
        ("kernel32.dll", "GetModuleFileNameA") => kernel32::GetModuleFileNameA(emu),
        ("kernel32.dll", "GetModuleHandleA") => kernel32::GetModuleHandleA(emu),
        ("kernel32.dll", "GetOEMCP") => kernel32::GetOEMCP(emu),
        ("kernel32.dll", "GetComputerNameA") => kernel32::GetComputerNameA(emu),
        ("kernel32.dll", "GetComputerNameW") => kernel32::GetComputerNameW(emu),
        ("kernel32.dll", "GetProcAddress") => kernel32::GetProcAddress(emu),
        ("kernel32.dll", "GetProcessHeap") => kernel32::GetProcessHeap(emu),
        ("kernel32.dll", "GetStartupInfoA") => kernel32::GetStartupInfoA(emu),
        ("kernel32.dll", "GetStdHandle") => kernel32::GetStdHandle(emu),
        ("kernel32.dll", "GetSystemTimeAsFileTime") => kernel32::GetSystemTimeAsFileTime(emu),
        ("kernel32.dll", "GetThreadLocale") => kernel32::GetThreadLocale(emu),
        ("kernel32.dll", "GetThreadPriority") => kernel32::GetThreadPriority(emu),
        ("kernel32.dll", "GetUserDefaultLCID") => kernel32::GetUserDefaultLCID(emu),
        ("kernel32.dll", "GetVersionExA") => kernel32::GetVersionExA(emu),
        ("kernel32.dll", "GetWindowsDirectoryA") => kernel32::GetWindowsDirectoryA(emu),
        ("kernel32.dll", "HeapAlloc") => kernel32::HeapAlloc(emu),
        ("kernel32.dll", "HeapCreate") => kernel32::HeapCreate(emu),
        ("kernel32.dll", "HeapDestroy") => kernel32::HeapDestroy(emu),
        ("kernel32.dll", "HeapFree") => kernel32::HeapFree(emu),
        ("kernel32.dll", "InitializeCriticalSection") => kernel32::InitializeCriticalSection(emu),
        ("kernel32.dll", "IsDebuggerPresent") => kernel32::IsDebuggerPresent(emu),
        ("kernel32.dll", "LeaveCriticalSection") => kernel32::LeaveCriticalSection(emu),
        ("kernel32.dll", "LoadLibraryA") => kernel32::LoadLibraryA(emu),
        ("kernel32.dll", "LoadLibraryW") => kernel32::LoadLibraryW(emu),
        ("kernel32.dll", "LoadResource") => kernel32::LoadResource(emu),
        ("kernel32.dll", "LocalAlloc") => kernel32::LocalAlloc(emu),
        ("kernel32.dll", "LocalFree") => kernel32::LocalFree(emu),
        ("kernel32.dll", "LockResource") => kernel32::LockResource(emu),
        ("kernel32.dll", "MultiByteToWideChar") => kernel32::MultiByteToWideChar(emu),
        ("kernel32.dll", "OpenThread") => kernel32::OpenThread(emu),
        ("kernel32.dll", "QueryPerformanceCounter") => kernel32::QueryPerformanceCounter(emu),
        ("kernel32.dll", "ReadFile") => kernel32::ReadFile(emu),
        ("kernel32.dll", "ReadProcessMemory") => kernel32::ReadProcessMemory(emu),
        ("kernel32.dll", "ResetEvent") => kernel32::ResetEvent(emu),
        ("kernel32.dll", "ResumeThread") => kernel32::ResumeThread(emu),
        ("kernel32.dll", "RtlCaptureContext") => ntdll::RtlCaptureContext(emu), // forward
        ("kernel32.dll", "RtlLookupFunctionEntry") => ntdll::RtlLookupFunctionEntry(emu), // forward
        ("kernel32.dll", "RtlUnwindEx") => ntdll::RtlUnwindEx(emu), // forward
        ("kernel32.dll", "RtlVirtualUnwind") => ntdll::RtlVirtualUnwind(emu), // forward
        ("kernel32.dll", "SetEvent") => kernel32::SetEvent(emu),
        ("kernel32.dll", "SetFilePointer") => kernel32::SetFilePointer(emu),
        ("kernel32.dll", "SetLastError") => kernel32::SetLastError(emu),
        ("kernel32.dll", "SetThreadLocale") => kernel32::SetThreadLocale(emu),
        ("kernel32.dll", "SetThreadPriority") => kernel32::SetThreadPriority(emu),
        ("kernel32.dll", "SizeofResource") => kernel32::SizeofResource(emu),
        ("kernel32.dll", "Sleep") => kernel32::Sleep(emu),
        ("kernel32.dll", "SuspendThread") => kernel32::SuspendThread(emu),
        ("kernel32.dll", "TerminateThread") => kernel32::TerminateThread(emu),
        ("kernel32.dll", "TlsAlloc") => kernel32::TlsAlloc(emu),
        ("kernel32.dll", "TlsFree") => kernel32::TlsFree(emu),
        ("kernel32.dll", "TlsGetValue") => kernel32::TlsGetValue(emu),
        ("kernel32.dll", "TlsSetValue") => kernel32::TlsSetValue(emu),
        ("kernel32.dll", "TryEnterCriticalSection") => kernel32::TryEnterCriticalSection(emu),
        ("kernel32.dll", "VirtualAlloc") => kernel32::VirtualAlloc(emu),
        ("kernel32.dll", "VirtualFree") => kernel32::VirtualFree(emu),
        ("kernel32.dll", "WaitForSingleObject") => kernel32::WaitForSingleObject(emu),
        ("kernel32.dll", "WideCharToMultiByte") => kernel32::WideCharToMultiByte(emu),
        ("kernel32.dll", "WriteFile") => kernel32::WriteFile(emu),
        ("kernel32.dll", "GetSystemInfo") => kernel32::GetSystemInfo(emu),
        ("kernel32.dll", "GetTickCount") => kernel32::GetTickCount(emu),
        ("kernel32.dll", "GetModuleFileNameW") => kernel32::GetModuleFileNameW(emu),
        ("kernel32.dll", "GetCommandLineW") => kernel32::GetCommandLineW(emu),
        ("kernel32.dll", "GetSystemDirectoryW") => kernel32::GetSystemDirectoryW(emu),
        ("kernel32.dll", "GetFullPathNameW") => kernel32::GetFullPathNameW(emu),
        ("kernel32.dll", "GetWindowsDirectoryW") => kernel32::GetWindowsDirectoryW(emu),
        ("kernel32.dll", "GetTempPathW") => kernel32::GetTempPathW(emu),
        ("kernel32.dll", "GetCurrentDirectoryW") => kernel32::GetCurrentDirectoryW(emu),
        ("kernel32.dll", "GetVersion") => kernel32::GetVersion(emu),
        ("kernel32.dll", "VirtualLock") => kernel32::VirtualLock(emu),
        ("kernel32.dll", "VirtualUnlock") => kernel32::VirtualUnlock(emu),
        ("kernel32.dll", "FindFirstFileExW") => kernel32::FindFirstFileExW(emu),
        ("kernel32.dll", "CreateMutexA") => kernel32::CreateMutexA(emu),
        ("kernel32.dll", "GetSystemFirmwareTable") => kernel32::GetSystemFirmwareTable(emu),
        ("kernel32.dll", "GlobalAddAtomA") => kernel32::GlobalAddAtomA(emu),
        ("kernel32.dll", "FileTimeToLocalFileTime") => kernel32::FileTimeToLocalFileTime(emu),
        ("kernel32.dll", "FileTimeToDosDateTime") => kernel32::FileTimeToDosDateTime(emu),
        ("kernel32.dll", "FindClose") => kernel32::FindClose(emu),
        ("kernel32.dll", "CreateFileA") => kernel32::CreateFileA(emu),
        ("kernel32.dll", "DeviceIoControl") => kernel32::DeviceIoControl(emu),        
        ("kernel32.dll", "ExitProcess") => kernel32::ExitProcess(emu),        
        ("kernel32.dll", "AddVectoredExceptionHandler") => kernel32::AddVectoredExceptionHandler(emu),        
        ("kernel32.dll", "SetThreadStackGuarantee") => kernel32::SetThreadStackGuarantee(emu),        
        ("kernel32.dll", "SetThreadDescription") => kernel32::SetThreadDescription(emu),        
        ("kernel32.dll", "WriteConsoleA") => kernel32::WriteConsoleA(emu),        
        ("kernel32.dll", "CheckRemoteDebuggerPresent") => kernel32::CheckRemoteDebuggerPresent(emu),        
        ("kernel32.dll", "CreateToolhelp32Snapshot") => kernel32::CreateToolhelp32Snapshot(emu),        
        ("kernel32.dll", "Module32First") => kernel32::Module32First(emu),        
        ("kernel32.dll", "Module32Next") => kernel32::Module32Next(emu),        
        ("kernel32.dll", "RemoveVectoredExceptionHandler") => kernel32::RemoveVectoredExceptionHandler(emu),        

        // user32
        ("user32.dll", "CharLowerBuffW") => user32::CharLowerBuffW(emu),
        ("user32.dll", "CharUpperBuffW") => user32::CharUpperBuffW(emu),
        ("user32.dll", "EnumDisplayDevicesA") => user32::EnumDisplayDevicesA(emu),                                               
        ("user32.dll", "EnumDisplayMonitors") => user32::EnumDisplayMonitors(emu),                       
        ("user32.dll", "GetDC") => user32::GetDC(emu),        
        ("user32.dll", "GetDesktopWindow") => user32::GetDesktopWindow(emu),        
        ("user32.dll", "GetMonitorInfoA") => user32::GetMonitorInfoA(emu),                                       
        ("user32.dll", "GetSystemMetrics") => user32::GetSystemMetrics(emu),
        ("user32.dll", "LoadCursorA") => user32::LoadCursorA(emu),
        ("user32.dll", "LoadIconA") => user32::LoadIconA(emu),
        ("user32.dll", "MonitorFromPoint") => user32::MonitorFromPoint(emu),       
        ("user32.dll", "MonitorFromRect") => user32::MonitorFromRect(emu),                       
        ("user32.dll", "MonitorFromWindow") => user32::MonitorFromWindow(emu),               
        ("user32.dll", "RegisterClassW") => user32::RegisterClassW(emu),
        ("user32.dll", "ReleaseDC") => user32::ReleaseDC(emu),        
        ("user32.dll", "SystemParametersInfoA") => user32::SystemParametersInfoA(emu),
        ("user32.dll", "GetPropA") => user32::GetPropA(emu),
        ("user32.dll", "DefWindowProcW") => user32::DefWindowProcW(emu),
        ("user32.dll", "RegisterClipboardFormatA") => user32::RegisterClipboardFormatA(emu),
        ("user32.dll", "CharLowerA") => user32::CharLowerA(emu),

        // ntdll
        ("ntdll.dll", "RtlAddFunctionTable") => ntdll::RtlAddFunctionTable(emu),
        ("ntdll.dll", "RtlCaptureContext") => ntdll::RtlCaptureContext(emu),
        ("ntdll.dll", "RtlDosPathNameToNtPathName_U") => ntdll::RtlDosPathNameToNtPathName_U(emu),
        ("ntdll.dll", "RtlFreeUnicodeString") => ntdll::RtlFreeUnicodeString(emu),
        ("ntdll.dll", "RtlLookupFunctionEntry") => ntdll::RtlLookupFunctionEntry(emu),
        ("ntdll.dll", "RtlUnwindEx") => ntdll::RtlUnwindEx(emu),
        ("ntdll.dll", "RtlVirtualUnwind") => ntdll::RtlVirtualUnwind(emu),
        ("ntdll.dll", "ZwClose") => ntdll::ZwClose(emu),  
        ("ntdll.dll", "NtClose") => ntdll::ZwClose(emu), // forward
        ("ntdll.dll", "ZwCreateFile") => ntdll::ZwCreateFile(emu),
        ("ntdll.dll", "ZwReadFile") => ntdll::ZwReadFile(emu),
        ("ntdll.dll", "NtCreateFile") => ntdll::ZwCreateFile(emu), // forward
        ("ntdll.dll", "NtReadFile") => ntdll::ZwReadFile(emu), // forward
        ("ntdll.dll", "ZwSetInformationFile") => ntdll::ZwSetInformationFile(emu),
        ("ntdll.dll", "NtSetInformationThread") => ntdll::NtSetInformationThread(emu),
        ("ntdll.dll", "ZwQueryInformationFile") => ntdll::ZwQueryInformationFile(emu),
        ("ntdll.dll", "RtlInitUnicodeString") => ntdll::RtlInitUnicodeString(emu),

        // oleaut32
        ("oleaut32.dll", "SysReAllocStringLen") => oleaut32::SysReAllocStringLen(emu),
        ("oleaut32.dll", "SysAllocStringLen") => oleaut32::SysAllocStringLen(emu),
        ("oleaut32.dll", "VariantClear") => oleaut32::VariantClear(emu),
        ("oleaut32.dll", "SysFreeString") => oleaut32::SysFreeString(emu),

        // ole32
        ("ole32.dll", "OleInitialize") => ole32::OleInitialize(emu),

        // msvcrt
        ("msvcrt.dll", "memcpy") => msvcrt::memcpy(emu),

        // advapi32
        ("advapi32.dll", "GetUserNameA") => advapi32::GetUserNameA(emu),
        ("advapi32.dll", "GetUserNameW") => advapi32::GetUserNameW(emu),

        // shell32
        ("shell32.dll", "SHGetFolderPathW") => shell32::SHGetFolderPathW(emu),
        ("shfolder.dll", "SHGetFolderPathW") => shell32::SHGetFolderPathW(emu), // forward

        // version
        ("version.dll", "GetFileVersionInfoSizeA") => version::GetFileVersionInfoSizeA(emu),
        ("version.dll", "GetFileVersionInfoA") => version::GetFileVersionInfoA(emu),
        ("version.dll", "VerQueryValueA") => version::VerQueryValueA(emu),

        // uxtheme
        ("uxtheme.dll", "IsAppThemed") => uxtheme::IsAppThemed(emu),
        ("uxtheme.dll", "IsThemeActive") => uxtheme::IsThemeActive(emu),
        ("uxtheme.dll", "GetThemeAppProperties") => uxtheme::GetThemeAppProperties(emu),

        // gdi32
        ("gdi32.dll", "CreateFontIndirectA") => gdi32::CreateFontIndirectA(emu),
        ("gdi32.dll", "GetDeviceCaps") => gdi32::GetDeviceCaps(emu),

        // comctl32
        ("comctl32.dll", "InitCommonControls") => comctl32::InitCommonControls(emu),
        ("comctl32.dll", "InitCommonControlsEx") => comctl32::InitCommonControlsEx(emu),

        // ucrtbase
        ("api-ms-win-crt-runtime-l1-1-0.dll", "_initterm_e") => ucrtbase::_initterm_e(emu),
        ("api-ms-win-crt-runtime-l1-1-0.dll", "_initterm") => ucrtbase::_initterm(emu),
        ("api-ms-win-crt-runtime-l1-1-0.dll", "_get_initial_narrow_environment") => ucrtbase::_get_initial_narrow_environment(emu),
        ("api-ms-win-crt-runtime-l1-1-0.dll", "__p___argv") => ucrtbase::__p___argv(emu),
        ("api-ms-win-crt-runtime-l1-1-0.dll", "__p___argc") => ucrtbase::__p___argc(emu),

        _ => {
            panic!("Unimplemented API call: {}!{}", dll_name, function_name);
        }
    }
}

// Helper function you can add to your module
pub fn set_last_error(
    emu: &mut dyn EmulatorEngine,
    error_code: u32,
) -> Result<(), EmulatorError> {
    log::warn!("set_last_error: error_code = {:x}", error_code);
    let error_addr = TEB_BASE + TEB_LAST_ERROR_VALUE_OFFSET;
    emu.mem_write(error_addr, &error_code.to_le_bytes())
}
