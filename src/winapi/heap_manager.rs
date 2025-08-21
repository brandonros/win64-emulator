use std::{collections::HashMap, sync::{LazyLock, Mutex}};

use crate::emulation::memory::HEAP_BASE;

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
            next_addr: HEAP_BASE, // Start heap allocations at this address
            allocations: HashMap::new(),
        }
    }
    
    pub fn allocate(&mut self, size: usize) -> u64 {
        let addr = self.next_addr;
        self.allocations.insert(addr, size);
        // Align to 16 bytes for next allocation
        self.next_addr += ((size + 15) & !15) as u64;
        addr
    }
}
