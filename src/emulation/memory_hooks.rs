use unicorn_engine::{MemType as UcMemType, Unicorn};
use crate::emulation::memory;

pub fn memory_read_hook_callback_unicorn<D>(emu: &mut Unicorn<D>, mem_type: UcMemType, addr: u64, size: usize, value: i64) -> bool {
    let region = memory::determine_memory_region(addr);
    log::trace!("📖 Memory read [{:?}]: 0x{:016x} (size: {} bytes)", region, addr, size);
    true
}

pub fn memory_write_hook_callback_unicorn<D>(emu: &mut Unicorn<D>, mem_type: UcMemType, addr: u64, size: usize, value: i64) -> bool {
    let region = memory::determine_memory_region(addr);
    log::trace!("✏️  Memory write [{:?}]: 0x{:016x} (size: {} bytes, value: 0x{:x})", region, addr, size, value);
    true
}

pub fn memory_invalid_hook_callback_unicorn<D>(emu: &mut Unicorn<D>, mem_type: UcMemType, addr: u64, size: usize, value: i64) -> bool {
    log::info!("❌ Invalid memory access: {:?} at 0x{:016x} (size: {}, value: 0x{:x})", mem_type, addr, size, value);
    false // Don't handle the error, let it propagate
}
