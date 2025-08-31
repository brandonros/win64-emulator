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
declare_api!(RtlFreeUnicodeString);
declare_api!(ZwSetInformationFile);
declare_api!(ZwReadFile);
declare_api!(ZwClose);
declare_api!(NtSetInformationThread);
declare_api!(ZwQueryInformationFile);
