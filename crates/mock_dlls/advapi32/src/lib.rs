#![allow(non_snake_case)]

mod GetUserNameA;

use windows_sys::{core::BOOL, Win32::Foundation::{HINSTANCE, TRUE}};
use common::types::*;

// entry point
#[unsafe(no_mangle)]
#[allow(non_snake_case, unused_variables)]
pub extern "system" fn DllMain(dll_module: HINSTANCE, call_reason: DWORD, reserved: LPVOID) -> BOOL {
  return TRUE;
}
