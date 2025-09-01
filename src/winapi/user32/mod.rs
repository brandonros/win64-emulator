#![allow(non_snake_case)]

// Macro to declare and re-export a WinAPI function module
macro_rules! declare_api {
    ($name:ident) => {
        mod $name;
        pub use $name::*;
    };
}

declare_api!(GetSystemMetrics);
declare_api!(CharLowerBuffW);
declare_api!(SystemParametersInfoA);
declare_api!(LoadIconA);
declare_api!(LoadCursorA);
declare_api!(RegisterClassW);
declare_api!(GetDesktopWindow);
declare_api!(GetDC);
declare_api!(ReleaseDC);
