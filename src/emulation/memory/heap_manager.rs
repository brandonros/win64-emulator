use std::{collections::HashMap, sync::{LazyLock, RwLock}};

use crate::emulation::engine::EmulatorEngine;
use crate::emulation::memory::{HEAP_BASE, HEAP_SIZE};

// Track heap allocations
pub static HEAP_ALLOCATIONS: LazyLock<HeapManager> = LazyLock::new(|| {
    HeapManager::new()
});

pub struct HeapManager {
    inner: RwLock<HeapManagerInner>,
}

struct HeapManagerInner {
    next_addr: u64,
    allocations: HashMap<u64, usize>, // address -> size
}

impl HeapManager {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HeapManagerInner {
                next_addr: HEAP_BASE,
                allocations: HashMap::new(),
            }),
        }
    }
    
    pub fn allocate(&self, emu: &mut dyn EmulatorEngine, size: usize) -> Result<u64, String> {
        log::info!("allocate size = {size:x}");

        let addr;
        let aligned_size;
        
        {
            let mut inner = self.inner.write().unwrap();
            addr = inner.next_addr;
            
            // Align to 16 bytes for next allocation
            aligned_size = (size + 15) & !15;
            let new_next = inner.next_addr + aligned_size as u64;
            
            // Check if we're about to overflow the heap
            if new_next > HEAP_BASE + HEAP_SIZE as u64 {
                return Err(format!("Heap overflow! Tried to allocate {} bytes at 0x{:x}, but heap ends at 0x{:x}", 
                       size, addr, HEAP_BASE + HEAP_SIZE as u64));
            }
            
            inner.allocations.insert(addr, aligned_size as usize);
            inner.next_addr = new_next;
        } // Drop the guard here before calling mem_write

        // zero the memory as a test
        let zeros = vec![0u8; size];
        emu.mem_write(addr, &zeros)
            .map_err(|e| format!("Failed to zero allocated memory: {:?}", e))?;
        
        Ok(addr)
    }

    pub fn free(&self, addr: u64, emu: &mut dyn EmulatorEngine) -> Result<(), String> {
        log::info!("allocate free addr = {addr:x}");

        let size;
        
        {
            let mut inner = self.inner.write().unwrap();
            // Check if this address was actually allocated
            match inner.allocations.remove(&addr) {
                Some(s) => size = s,
                None => return Err(format!("Attempted to free unallocated address: 0x{:x}", addr))
            }
        } // Drop the guard here before calling mem_write
        
        // Zero out the freed memory to prevent use-after-free
        let zeros = vec![0u8; size];
        emu.mem_write(addr, &zeros)
            .map_err(|e| format!("Failed to zero freed memory: {:?}", e))?;
        log::info!("[HeapManager] Freed {} bytes at 0x{:x} (zeroed)", size, addr);
        Ok(())
    }
}
