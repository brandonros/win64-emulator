use std::{collections::HashMap, sync::{LazyLock, Mutex}};
use unicorn_engine::Unicorn;

use crate::emulation::memory::{HEAP_BASE, HEAP_SIZE};

// Track heap allocations
pub static HEAP_ALLOCATIONS: LazyLock<Mutex<HeapManager>> = LazyLock::new(|| {
    Mutex::new(HeapManager::new())
});

pub struct HeapManager {
    next_addr: u64,
    allocations: HashMap<u64, usize>, // address -> size
}

impl HeapManager {
    pub fn new() -> Self {
        Self {
            next_addr: HEAP_BASE,
            allocations: HashMap::new(),
        }
    }
    
    pub fn next_addr(&self) -> u64 {
        self.next_addr
    }
    
    pub fn get_allocations(&self) -> &HashMap<u64, usize> {
        &self.allocations
    }
    
    pub fn restore_state(&mut self, next_addr: u64, allocations: HashMap<u64, usize>) {
        self.next_addr = next_addr;
        self.allocations = allocations;
        log::info!("[HeapManager] Restored state: next_addr=0x{:x}, {} allocations", 
                  next_addr, self.allocations.len());
    }
    
    pub fn allocate(&mut self, emu: &mut Unicorn<()>, size: usize) -> Result<u64, String> {
        let addr = self.next_addr;
        
        // Align to 16 bytes for next allocation
        let aligned_size = (size + 15) & !15;
        let new_next = self.next_addr + aligned_size as u64;
        
        // Check if we're about to overflow the heap
        if new_next > HEAP_BASE + HEAP_SIZE as u64 {
            return Err(format!("Heap overflow! Tried to allocate {} bytes at 0x{:x}, but heap ends at 0x{:x}", 
                   size, addr, HEAP_BASE + HEAP_SIZE as u64));
        }
        
        self.allocations.insert(addr, aligned_size as usize);
        self.next_addr = new_next;

        // zero the memory as a test
        let zeros = vec![0u8; size];
        emu.mem_write(addr, &zeros).unwrap(); // TODO: no unwrap
        
        Ok(addr)
    }

    pub fn free(&mut self, addr: u64, emu: &mut Unicorn<()>) -> Result<(), String> {
        // Check if this address was actually allocated
        if let Some(size) = self.allocations.remove(&addr) {
            // Zero out the freed memory to prevent use-after-free
            let zeros = vec![0u8; size];
            emu.mem_write(addr, &zeros).unwrap(); // TODO: no unwrap
            log::info!("[HeapManager] Freed {} bytes at 0x{:x} (zeroed)", size, addr);
            Ok(())
        } else {
            Err(format!("Attempted to free unallocated address: 0x{:x}", addr))
        }
    }
}
