// Memory layout constants
pub const STACK_BASE: u64 = 0x7fff0000;
pub const STACK_SIZE: usize = 0x10000;
pub const HEAP_BASE: u64 = 0x10000000;
pub const HEAP_SIZE: usize = 0x100000;

// Thread Environment Block (TEB) and Process Environment Block (PEB)
pub const TEB_BASE: u64 = 0x7FFE0000;
pub const TEB_SIZE: usize = 0x2000;
pub const PEB_BASE: u64 = 0x7FFE2000;
pub const PEB_SIZE: usize = 0x1000;

// TLS (Thread Local Storage) constants
pub const TEB_TLS_SLOTS_OFFSET: u64 = 0x1480;  // Offset of TlsSlots[64] array in TEB
pub const TLS_MINIMUM_AVAILABLE: usize = 64;    // Number of TLS slots in TEB
pub const TLS_OUT_OF_INDEXES: u32 = 0xFFFFFFFF; // Return value when no slots available

// Error handling
pub const TEB_LAST_ERROR_VALUE_OFFSET: u64 = 0x68;  // Offset of LastErrorValue in TEB