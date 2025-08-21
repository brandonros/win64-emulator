#![allow(non_snake_case)]

// Macro to declare and re-export a WinAPI function module
macro_rules! declare_api {
    ($name:ident) => {
        mod $name;
        pub use $name::*;
    };
}

declare_api!(EnterCriticalSection);
declare_api!(GetACP);
declare_api!(GetCommandLineA);
declare_api!(GetConsoleCP);
declare_api!(GetConsoleOutputCP);
declare_api!(GetCPInfo);
declare_api!(GetCurrentProcessId);
declare_api!(GetCurrentThreadId);
declare_api!(GetLastError);
declare_api!(GetLocaleInfoA);
declare_api!(GetLocaleInfoW);
declare_api!(GetModuleFileNameA);
declare_api!(GetModuleHandleA);
declare_api!(GetProcAddress);
declare_api!(GetProcessHeap);
declare_api!(GetStartupInfoA);
declare_api!(GetStdHandle);
declare_api!(GetThreadLocale);
declare_api!(GetUserDefaultLCID);
declare_api!(GetVersionExA);
declare_api!(GetWindowsDirectoryA);
declare_api!(HeapAlloc);
declare_api!(HeapCreate);
declare_api!(LeaveCriticalSection);
declare_api!(InitializeCriticalSection);
declare_api!(LoadLibraryA);
declare_api!(LocalAlloc);
declare_api!(SetLastError);
declare_api!(SetThreadLocale);
declare_api!(TlsAlloc);
declare_api!(TlsGetValue);
declare_api!(TlsSetValue);
declare_api!(WideCharToMultiByte);
