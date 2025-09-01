#![allow(non_snake_case)]

// Macro to declare and re-export a WinAPI function module
macro_rules! declare_api {
    ($name:ident) => {
        mod $name;
        pub use $name::*;
    };
}

declare_api!(_initterm_e);
declare_api!(_initterm);
declare_api!(_get_initial_narrow_environment);
declare_api!(__p___argv);
declare_api!(__p___argc);
