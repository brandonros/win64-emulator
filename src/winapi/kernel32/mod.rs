#![allow(non_snake_case)]

// Macro to declare and re-export a WinAPI function module
macro_rules! declare_api {
    ($name:ident) => {
        mod $name;
        pub use $name::*;
    };
}

declare_api!(GetModuleHandleA);
declare_api!(LoadLibraryA);
declare_api!(GetProcAddress);
declare_api!(GetCurrentThreadId);
declare_api!(GetStartupInfoA);
declare_api!(TlsAlloc);
declare_api!(TlsGetValue);
declare_api!(GetLastError);
declare_api!(LocalAlloc);
