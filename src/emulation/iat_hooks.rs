use iced_x86::{Instruction, Mnemonic, OpKind, Register};
use unicorn_engine::{RegisterX86, Unicorn};

use crate::{emulation::iat::IAT_FUNCTION_MAP, pe::constants::*, winapi};

pub fn intercept_iat_call<D>(emu: &mut Unicorn<D>, instruction: Instruction, addr: u64, count: u64) {
    let mnemonic = instruction.mnemonic();
    
    // Handle both CALL and JMP instructions
    if (mnemonic == Mnemonic::Call || mnemonic == Mnemonic::Jmp) && instruction.op_count() > 0 {
        let instruction_type = if mnemonic == Mnemonic::Call { "CALL" } else { "JMP" };
        log::trace!("{} instruction detected at 0x{:x}: {:?}", instruction_type, addr, instruction);
        
        // Add detailed logging about the call/jmp type
        match instruction.op0_kind() {
            OpKind::Memory => {
                log::debug!("=== INDIRECT {} ANALYSIS at 0x{:x} ===", instruction_type, addr);
                log::debug!("Instruction: {}", instruction);
                log::debug!("Op0 kind: Memory (indirect {})", instruction_type.to_lowercase());
                
                if let Some(target_addr) = get_indirect_call_target(&instruction, emu, addr) {
                    log::debug!("Calculated target address: 0x{:x}", target_addr);
                    handle_potential_iat_call(target_addr, emu, addr, &instruction, count, mnemonic == Mnemonic::Jmp);
                } else {
                    log::warn!("Failed to calculate target address for indirect {} at 0x{:x}", instruction_type.to_lowercase(), addr);
                }
            }
            OpKind::NearBranch64 => {
                //log::debug!("Direct {} to 0x{:x} (not IAT)", instruction_type.to_lowercase(), instruction.near_branch64());
            }
            OpKind::Register => {
                log::debug!("Register {} (not IAT) - register: {:?}", instruction_type.to_lowercase(), instruction.op0_register());
            }
            _ => {
                log::debug!("Other {} type: {:?}", instruction_type.to_lowercase(), instruction.op0_kind());
            }
        }
    }
}

/// Get the target address for an indirect call instruction
fn get_indirect_call_target<D>(
    instruction: &Instruction,
    emu: &mut Unicorn<D>,
    addr: u64,
) -> Option<u64> {
    match instruction.op0_kind() {
        OpKind::Memory => {
            let target = calculate_effective_address(instruction, emu, addr);
            log::debug!("Effective address calculated: 0x{:x}", target);
            Some(target)
        }
        _ => {
            log::debug!("Not a memory operand, skipping IAT check");
            None
        }
    }
}

/// Calculate the effective address for a memory operand
fn calculate_effective_address<D>(
    instruction: &Instruction,
    emu: &mut Unicorn<D>,
    addr: u64,
) -> u64 {
    log::debug!("--- EFFECTIVE ADDRESS CALCULATION ---");
    log::debug!("Instruction: {}", instruction);
    log::debug!("Current address: 0x{:x}", addr);
    log::debug!("Memory base: {:?}", instruction.memory_base());
    log::debug!("Memory index: {:?}", instruction.memory_index());
    log::debug!("Memory scale: {}", instruction.memory_index_scale());
    log::debug!("Memory displacement32: 0x{:x}", instruction.memory_displacement32());
    log::debug!("Memory displacement64: 0x{:x}", instruction.memory_displacement64());
    log::debug!("Is IP relative: {}", instruction.is_ip_rel_memory_operand());
    
    // Check if the instruction uses RIP-relative memory addressing
    if instruction.is_ip_rel_memory_operand() {
        // For x64, we should check if there's a 64-bit displacement first
        let displacement64 = instruction.memory_displacement64();
        
        if displacement64 != 0 {
            // Use the 64-bit displacement directly (absolute address in x64)
            log::debug!("✓ RIP-relative with 64-bit displacement (absolute address)");
            log::debug!("  Displacement64: 0x{:016x}", displacement64);
            log::debug!("  Effective address: 0x{:016x}", displacement64);
            return displacement64;
        }
        
        // Fall back to 32-bit RIP-relative calculation
        let displacement_u32 = instruction.memory_displacement32();
        let displacement = displacement_u32 as i32;  // Treat as signed!
        let rip_value = addr + instruction.len() as u64;
        let effective_addr = (rip_value as i64 + displacement as i64) as u64;
        
        log::debug!("✓ RIP-relative addressing detected (32-bit displacement)");
        log::debug!("  Current RIP: 0x{:016x}", addr);
        log::debug!("  Instruction length: {}", instruction.len());
        log::debug!("  Next RIP: 0x{:016x}", rip_value);
        log::debug!("  Displacement (unsigned): 0x{:08x} ({})", displacement_u32, displacement_u32);
        log::debug!("  Displacement (signed): 0x{:08x} ({})", displacement, displacement);
        log::debug!("  Calculation: 0x{:016x} + {} = 0x{:016x}", rip_value, displacement, effective_addr);
        log::debug!("  Effective address: 0x{:016x}", effective_addr);
        
        return effective_addr;
    }

    // For RIP-relative addressing (common in x64)
    if instruction.memory_base() == Register::RIP {
        let displacement = instruction.memory_displacement32() as i32;
        let rip_value = addr + instruction.len() as u64;
        let effective_addr = (rip_value as i64 + displacement as i64) as u64;
        
        log::debug!("✓ RIP-relative addressing (explicit RIP base):");
        log::debug!("  Current RIP: 0x{:016x}", addr);
        log::debug!("  Instruction length: {}", instruction.len());
        log::debug!("  Next RIP: 0x{:016x}", rip_value);
        log::debug!("  Displacement: 0x{:08x} ({})", displacement, displacement);
        log::debug!("  Effective address: 0x{:016x}", effective_addr);
        
        return effective_addr;
    }
    
    // Direct absolute addressing - when there's no base and no index register
    if instruction.memory_base() == Register::None && 
       instruction.memory_index() == Register::None {
        // For x64, check if this uses 64-bit displacement (absolute address)
        let displacement64 = instruction.memory_displacement64();
        let displacement32 = instruction.memory_displacement32();
        
        if displacement64 != 0 {
            log::debug!("✓ Direct absolute address (64-bit): 0x{:016x}", displacement64);
            return displacement64;
        }
        
        // If displacement64 is 0 but we have a 32-bit displacement,
        // it might be RIP-relative (depends on the encoding)
        if displacement32 != 0 {
            // This is likely RIP-relative addressing in x64
            // In x64, [disp32] is encoded as RIP+disp32
            let disp32 = displacement32 as i32;
            let rip_value = addr + instruction.len() as u64;
            let effective_addr = (rip_value as i64 + disp32 as i64) as u64;
            
            log::debug!("✓ Implicit RIP-relative (x64 [disp32]):");
            log::debug!("  Current RIP: 0x{:016x}", addr);
            log::debug!("  Next RIP: 0x{:016x}", rip_value);
            log::debug!("  Displacement32: 0x{:08x} (signed: {})", displacement32, disp32);
            log::debug!("  Effective address: 0x{:016x}", effective_addr);
            
            return effective_addr;
        }
        
        log::debug!("✓ Zero displacement - should not happen");
        return 0;
    }
    
    // Handle base + index + displacement
    let mut target_addr = 0u64;
    log::debug!("✓ Complex addressing mode detected");
    
    // Get base register value if present
    if instruction.memory_base() != Register::None {
        let base_value = get_base_register_value(instruction.memory_base(), emu, addr, instruction);
        log::debug!("  Base register {:?} = 0x{:016x}", instruction.memory_base(), base_value);
        target_addr = base_value;
    }
    
    // Add index register value if present
    if instruction.memory_index() != Register::None {
        let index_contribution = get_index_register_contribution(instruction, emu);
        log::debug!("  Index contribution = 0x{:016x}", index_contribution);
        target_addr += index_contribution;
    }
    
    // Add displacement
    let displacement = instruction.memory_displacement64();
    let final_addr = (target_addr as i64 + displacement as i64) as u64;
    log::debug!("  Displacement: 0x{:016x}", displacement);
    log::debug!("  Final effective address: 0x{:016x}", final_addr);
    
    final_addr
}

/// Get the value of the base register
fn get_base_register_value<D>(
    base_reg: Register,
    emu: &mut Unicorn<D>,
    addr: u64,
    instruction: &Instruction,
) -> u64 {
    if base_reg == Register::RIP {
        // RIP-relative addressing
        let rip_value = addr + instruction.len() as u64;
        log::debug!("    RIP base register = 0x{:016x}", rip_value);
        return rip_value;
    }
    
    match map_iced_to_unicorn_register(base_reg) {
        Some(unicorn_reg) => {
            let value = emu.reg_read(unicorn_reg).unwrap();
            log::debug!("    Base register {:?} = 0x{:016x}", base_reg, value);
            value
        }
        None => {
            log::warn!("    Unsupported base register: {:?}", base_reg);
            0
        }
    }
}

/// Calculate the contribution of the index register (value * scale)
fn get_index_register_contribution<D>(
    instruction: &Instruction,
    emu: &mut Unicorn<D>,
) -> u64 {
    let index_reg = match map_iced_to_unicorn_register(instruction.memory_index()) {
        Some(reg) => reg,
        None => {
            log::warn!("    Unsupported index register: {:?}", instruction.memory_index());
            return 0;
        }
    };
    
    let index_value = emu.reg_read(index_reg).unwrap();
    let scale = instruction.memory_index_scale();
    let contribution = index_value * scale as u64;
    
    log::debug!("    Index register {:?} = 0x{:016x}, scale = {}, contribution = 0x{:016x}", 
               instruction.memory_index(), index_value, scale, contribution);
    
    contribution
}

/// Map iced_x86 Register to unicorn RegisterX86
fn map_iced_to_unicorn_register(reg: Register) -> Option<RegisterX86> {
    match reg {
        Register::RAX => Some(RegisterX86::RAX),
        Register::RBX => Some(RegisterX86::RBX),
        Register::RCX => Some(RegisterX86::RCX),
        Register::RDX => Some(RegisterX86::RDX),
        Register::RSI => Some(RegisterX86::RSI),
        Register::RDI => Some(RegisterX86::RDI),
        Register::RBP => Some(RegisterX86::RBP),
        Register::RSP => Some(RegisterX86::RSP),
        Register::R8 => Some(RegisterX86::R8),
        Register::R9 => Some(RegisterX86::R9),
        Register::R10 => Some(RegisterX86::R10),
        Register::R11 => Some(RegisterX86::R11),
        Register::R12 => Some(RegisterX86::R12),
        Register::R13 => Some(RegisterX86::R13),
        Register::R14 => Some(RegisterX86::R14),
        Register::R15 => Some(RegisterX86::R15),
        _ => None,
    }
}

/// Handle a potential IAT call by checking if the target points to mock functions
fn handle_potential_iat_call<D>(
    target_addr: u64,
    emu: &mut Unicorn<D>,
    addr: u64,
    instruction: &Instruction,
    count: u64,
    is_jmp: bool
) {
    log::debug!("=== IAT {} HANDLER ===", if is_jmp { "JMP" } else { "CALL" });
    log::debug!("Target address to read from: 0x{:x}", target_addr);
    
    // Check if the target address is in valid memory range
    if !is_valid_memory_address(emu, target_addr) {
        log::error!("Target address 0x{:x} is not in valid memory range!", target_addr);
        log::error!("Memory regions should be checked here");
        return;
    }
    
    // Read the function pointer from the calculated address
    let func_ptr = match read_function_pointer(emu, target_addr) {
        Some(ptr) => {
            log::debug!("✓ Successfully read function pointer 0x{:x} from [0x{:x}]", ptr, target_addr);
            ptr
        },
        None => {
            log::error!("✗ Failed to read function pointer from [0x{:x}]", target_addr);
            
            // Additional debugging for memory read failure
            let mut test_bytes = [0u8; 8];
            match emu.mem_read(target_addr, &mut test_bytes) {
                Ok(_) => {
                    let value = u64::from_le_bytes(test_bytes);
                    log::error!("  Raw memory read succeeded, got: 0x{:016x}", value);
                    log::error!("  This suggests the read_function_pointer function has a bug");
                }
                Err(e) => {
                    log::error!("  Raw memory read failed: {:?}", e);
                    log::error!("  Memory address 0x{:x} is not accessible", target_addr);
                    
                    // Try to read nearby addresses to understand the memory layout
                    for offset in [-16i64, -8, 0, 8, 16] {
                        let test_addr = (target_addr as i64 + offset) as u64;
                        let mut nearby_bytes = [0u8; 8];
                        match emu.mem_read(test_addr, &mut nearby_bytes) {
                            Ok(_) => {
                                let nearby_value = u64::from_le_bytes(nearby_bytes);
                                log::error!("  [0x{:x}] = 0x{:016x} ✓", test_addr, nearby_value);
                            }
                            Err(_) => {
                                log::error!("  [0x{:x}] = <unreadable> ✗", test_addr);
                            }
                        }
                    }
                }
            }
            return;
        }
    };
    
    // Check if this points to our mock function area (IAT call)
    log::debug!("Checking if 0x{:x} is in mock function range [0x{:x} - 0x{:x}]", 
               func_ptr, MOCK_FUNCTION_BASE, MOCK_FUNCTION_BASE + MOCK_FUNCTION_SIZE as u64);
    
    if !is_mock_function_address(func_ptr) {
        log::debug!("✗ Function pointer 0x{:x} is NOT in mock function range, skipping IAT handling", func_ptr);
        return;
    }
    
    log::info!("✓ Detected IAT call through [0x{:016x}] -> 0x{:016x} (in mock range)", target_addr, func_ptr);
    
    // Look up and handle the API function
    if let Some((dll_name, func_name)) = lookup_iat_function(func_ptr) {
        let instruction_type = if is_jmp { "JMP" } else { "CALL" };
        log::info!("[{}:{:x}] 🔷 API {}: {}!{}", count, addr, instruction_type, dll_name, func_name);
        execute_api_call(emu, addr, instruction, &dll_name, &func_name);
    } else {
        log::error!("✗ Mock function at 0x{:016x} not found in IAT_FUNCTION_MAP", func_ptr);
        log::error!("Available functions in IAT_FUNCTION_MAP:");
        let iat_map = IAT_FUNCTION_MAP.read().unwrap();
        for (addr, (dll, func)) in iat_map.iter() {
            log::error!("  0x{:016x} -> {}!{}", addr, dll, func);
        }
    }
}

/// Check if a memory address is valid/accessible
fn is_valid_memory_address<D>(emu: &mut Unicorn<D>, addr: u64) -> bool {
    let mut test_byte = [0u8; 1];
    emu.mem_read(addr, &mut test_byte).is_ok()
}

/// Read a 64-bit function pointer from memory
fn read_function_pointer<D>(emu: &mut Unicorn<D>, address: u64) -> Option<u64> {
    let mut func_ptr_bytes = [0u8; 8];
    match emu.mem_read(address, &mut func_ptr_bytes) {
        Ok(_) => {
            let value = u64::from_le_bytes(func_ptr_bytes);
            log::debug!("  Memory read successful: [0x{:x}] = 0x{:016x}", address, value);
            Some(value)
        }
        Err(e) => {
            log::error!("  Memory read failed at 0x{:x}: {:?}", address, e);
            None
        }
    }
}

/// Check if an address points to the mock function area
fn is_mock_function_address(addr: u64) -> bool {
    let in_range = addr >= MOCK_FUNCTION_BASE && addr < MOCK_FUNCTION_BASE + MOCK_FUNCTION_SIZE as u64;
    log::debug!("Mock function check: 0x{:x} in range [0x{:x}, 0x{:x}) = {}", 
               addr, MOCK_FUNCTION_BASE, MOCK_FUNCTION_BASE + MOCK_FUNCTION_SIZE as u64, in_range);
    in_range
}

/// Look up function information from the IAT function map
fn lookup_iat_function(func_ptr: u64) -> Option<(String, String)> {
    let result = IAT_FUNCTION_MAP
        .read()
        .unwrap()
        .get(&func_ptr)
        .map(|info| (info.0.clone(), info.1.clone()));
    
    match &result {
        Some((dll, func)) => {
            log::debug!("✓ Found IAT function: 0x{:x} -> {}!{}", func_ptr, dll, func);
        }
        None => {
            log::debug!("✗ IAT function not found for address 0x{:x}", func_ptr);
        }
    }
    
    result
}

/// Execute an API call by setting up the stack and calling the handler
fn execute_api_call<D>(
    emu: &mut Unicorn<D>,
    addr: u64,
    instruction: &Instruction,
    dll_name: &str,
    func_name: &str,
) {
    let return_addr = addr + instruction.len() as u64;
    log::debug!("=== EXECUTING API CALL ===");
    log::debug!("Function: {}!{}", dll_name, func_name);
    log::debug!("Call address: 0x{:x}", addr);
    log::debug!("Return address: 0x{:x}", return_addr);
    
    // Push return address onto stack (as a real CALL would)
    push_return_address(emu, return_addr);
    
    // Handle the API call
    match winapi::handle_winapi_call(emu, dll_name, func_name) {
        Ok(_) => {
            log::debug!("✓ API call completed successfully");
            // Set RIP to return address and pop stack
            finalize_api_call(emu, return_addr);
        }
        Err(err) => {
            log::error!("✗ API call failed: {:?}", err);
            panic!(
                "handle_winapi_call failed for {}!{}: {:?}",
                dll_name, func_name, err
            );
        }
    }
}

/// Push the return address onto the stack
fn push_return_address<D>(emu: &mut Unicorn<D>, return_addr: u64) {
    let rsp = emu.reg_read(RegisterX86::RSP).unwrap();
    let new_rsp = rsp - 8;
    log::debug!("Pushing return address 0x{:x} onto stack: RSP 0x{:x} -> 0x{:x}", 
               return_addr, rsp, new_rsp);
    emu.reg_write(RegisterX86::RSP, new_rsp).unwrap();
    emu.mem_write(new_rsp, &return_addr.to_le_bytes()).unwrap();
}

/// Finalize API call by setting RIP and adjusting stack
fn finalize_api_call<D>(emu: &mut Unicorn<D>, return_addr: u64) {
    let rax = emu.reg_read(RegisterX86::RAX).unwrap();
    log::debug!("Finalizing API call - RAX return value: 0x{:x}", rax);
    
    // Set RIP to the return address
    emu.reg_write(RegisterX86::RIP, return_addr).unwrap();
    log::debug!("Set RIP to return address: 0x{:x}", return_addr);
    
    // Pop the return address from stack (as a RET would)
    let rsp = emu.reg_read(RegisterX86::RSP).unwrap();
    let new_rsp = rsp + 8;
    emu.reg_write(RegisterX86::RSP, new_rsp).unwrap();
    log::debug!("Popped stack: RSP 0x{:x} -> 0x{:x}", rsp, new_rsp);
}
