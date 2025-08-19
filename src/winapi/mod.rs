use unicorn_engine::Unicorn;

pub mod kernel32;

fn handle_winapi_call<D>(emu: &mut Unicorn<D>, dll_name: &str, function_name: &str) {
    // Cast the generic Unicorn to the specific type we need
    let emu_ptr = emu as *mut Unicorn<D> as *mut Unicorn<()>;
    let emu_ref = unsafe { &mut *emu_ptr };
    
    match (dll_name.to_lowercase().as_str(), function_name) {
        ("kernel32.dll", "GetModuleHandleA") => {
            kernel32::GetModuleHandleA(emu_ref).unwrap();
        }
        _ => {
            panic!("Unimplemented API call: {}!{}", dll_name, function_name);
        }
    }
}
