#![allow(non_snake_case)]

// Macro to declare and re-export a WinAPI function module
macro_rules! declare_api {
    ($name:ident) => {
        mod $name;
        pub use $name::*;
    };
}

declare_api!(IsAppThemed);
declare_api!(IsThemeActive);
declare_api!(GetThemeAppProperties);
