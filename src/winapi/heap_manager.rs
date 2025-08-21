use std::{collections::HashMap, sync::{LazyLock, Mutex}};

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
    
    pub fn allocate(&mut self, size: usize) -> u64 {
        let addr = self.next_addr;
        
        // Align to 16 bytes for next allocation
        let aligned_size = ((size + 15) & !15) as u64;
        let new_next = self.next_addr + aligned_size;
        
        // Panic if we're about to overflow the heap
        if new_next > HEAP_BASE + HEAP_SIZE as u64 {
            panic!("Heap overflow! Tried to allocate {} bytes at 0x{:x}, but heap ends at 0x{:x}", 
                   size, addr, HEAP_BASE + HEAP_SIZE as u64);
        }
        
        self.allocations.insert(addr, size);
        self.next_addr = new_next;
        addr
    }
}
