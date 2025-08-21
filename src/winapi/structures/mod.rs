#![allow(non_snake_case)]

use unicorn_engine::Unicorn;

pub fn write_struct<T>(emu: &mut Unicorn<()>, addr: u64, data: &T) {
    let size = std::mem::size_of::<T>();
    let bytes: &[u8] = unsafe {
        std::slice::from_raw_parts(
            data as *const T as *const u8,
            size
        )
    };
    emu.mem_write(addr, bytes).unwrap();
}
