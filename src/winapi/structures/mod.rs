#![allow(non_snake_case)]

macro_rules! declare_structure {
    ($name:ident) => {
        mod $name;
        pub use $name::*;
    };
}

declare_structure!(StartupInfo64);
