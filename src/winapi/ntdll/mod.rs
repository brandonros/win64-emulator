#![allow(non_snake_case)]

// Macro to declare and re-export a WinAPI function module
macro_rules! declare_api {
    ($name:ident) => {
        mod $name;
        pub use $name::*;
    };
}

declare_api!(RtlAddFunctionTable);
declare_api!(RtlCaptureContext);
declare_api!(RtlLookupFunctionEntry);
declare_api!(RtlVirtualUnwind);
declare_api!(RtlUnwindEx);
declare_api!(RtlDosPathNameToNtPathName_U);
declare_api!(ZwCreateFile);
