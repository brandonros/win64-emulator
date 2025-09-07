/*
GlobalAddAtomA function (winbase.h)
02/08/2023
Adds a character string to the global atom table and returns a unique value (an atom) identifying the string.

Syntax
C++

Copy
ATOM GlobalAddAtomA(
  [in] LPCSTR lpString
);
Parameters
[in] lpString

Type: LPCTSTR

The null-terminated string to be added. The string can have a maximum size of 255 bytes. Strings that differ only in case are considered identical. The case of the first string of this name added to the table is preserved and returned by the GlobalGetAtomName function.

Alternatively, you can use an integer atom that has been converted using the MAKEINTATOM macro. See the Remarks for more information.

Return value
Type: ATOM

If the function succeeds, the return value is the newly created atom.

If the function fails, the return value is zero. To get extended error information, call GetLastError.

Remarks
If the string already exists in the global atom table, the atom for the existing string is returned and the atom's reference count is incremented.

The string associated with the atom is not deleted from memory until its reference count is zero. For more information, see the GlobalDeleteAtom function.

Global atoms are not deleted automatically when the application terminates. For every call to the GlobalAddAtom function, there must be a corresponding call to the GlobalDeleteAtom function.

If the lpString parameter has the form "#1234", GlobalAddAtom returns an integer atom whose value is the 16-bit representation of the decimal number specified in the string (0x04D2, in this example). If the decimal value specified is 0x0000 or is greater than or equal to 0xC000, the return value is zero, indicating an error. If lpString was created by the MAKEINTATOM macro, the low-order word must be in the range 0x0001 through 0xBFFF. If the low-order word is not in this range, the function fails.

If lpString has any other form, GlobalAddAtom returns a string atom.
*/

use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};
use crate::emulation::memory;
use crate::winapi;
use std::collections::HashMap;
use std::sync::{LazyLock, RwLock};

// Atom table entry
struct AtomEntry {
    atom: u16,
    string: String,
    ref_count: u32,
}

// Global atom table
struct GlobalAtomTable {
    atoms: HashMap<u16, AtomEntry>,
    string_to_atom: HashMap<String, u16>,
    next_atom: u16,
}

impl GlobalAtomTable {
    fn new() -> Self {
        Self {
            atoms: HashMap::new(),
            string_to_atom: HashMap::new(),
            next_atom: 0xC000, // Start at 0xC000 for string atoms
        }
    }
    
    fn add_atom(&mut self, string: String) -> u16 {
        // Convert to uppercase for case-insensitive comparison
        let key = string.to_uppercase();
        
        // Check if already exists
        if let Some(&atom) = self.string_to_atom.get(&key) {
            // Increment reference count
            if let Some(entry) = self.atoms.get_mut(&atom) {
                entry.ref_count += 1;
                log::debug!("[GlobalAddAtomA] Incrementing ref count for atom 0x{:04x} ({}), new count: {}", 
                    atom, entry.string, entry.ref_count);
            }
            return atom;
        }
        
        // Create new atom
        let atom = self.next_atom;
        self.next_atom += 1;
        
        // Wrap around if we hit the limit (unlikely in practice)
        if self.next_atom >= 0xFFFF {
            self.next_atom = 0xC000;
        }
        
        let entry = AtomEntry {
            atom,
            string: string.clone(), // Preserve original case
            ref_count: 1,
        };
        
        self.atoms.insert(atom, entry);
        self.string_to_atom.insert(key, atom);
        
        log::debug!("[GlobalAddAtomA] Created new atom 0x{:04x} for string \"{}\"", atom, string);
        
        atom
    }
}

static GLOBAL_ATOM_TABLE: LazyLock<RwLock<GlobalAtomTable>> = LazyLock::new(|| {
    RwLock::new(GlobalAtomTable::new())
});

pub fn GlobalAddAtomA(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    // ATOM GlobalAddAtomA(
    //   LPCSTR lpString  // RCX
    // )
    
    let string_ptr = emu.reg_read(X86Register::RCX)?;
    
    // Check for null pointer
    if string_ptr == 0 {
        log::warn!("[GlobalAddAtomA] NULL string pointer");
        winapi::set_last_error(emu, windows_sys::Win32::Foundation::ERROR_INVALID_PARAMETER)?;
        emu.reg_write(X86Register::RAX, 0)?; // Return 0 for error
        return Ok(());
    }
    
    // Check if this is an integer atom (MAKEINTATOM)
    if string_ptr < 0x10000 {
        // This is an integer atom
        let atom_value = string_ptr as u16;
        
        // Validate range (0x0001 through 0xBFFF)
        if atom_value == 0 || atom_value >= 0xC000 {
            log::warn!("[GlobalAddAtomA] Invalid integer atom value: 0x{:04x}", atom_value);
            winapi::set_last_error(emu, windows_sys::Win32::Foundation::ERROR_INVALID_PARAMETER)?;
            emu.reg_write(X86Register::RAX, 0)?;
            return Ok(());
        }
        
        log::info!("[GlobalAddAtomA] Returning integer atom: 0x{:04x}", atom_value);
        emu.reg_write(X86Register::RAX, atom_value as u64)?;
        return Ok(());
    }
    
    // Read the string
    let string = memory::read_string_from_memory(emu, string_ptr)?;
    
    log::info!("[GlobalAddAtomA] String: \"{}\"", string);
    
    // Check for "#1234" format (integer atom in string form)
    if string.starts_with('#') {
        if let Ok(value) = string[1..].parse::<u32>() {
            // Convert to 16-bit atom
            if value == 0 || value >= 0xC000 {
                log::warn!("[GlobalAddAtomA] Invalid integer atom value from string: {}", value);
                winapi::set_last_error(emu, windows_sys::Win32::Foundation::ERROR_INVALID_PARAMETER)?;
                emu.reg_write(X86Register::RAX, 0)?;
                return Ok(());
            }
            
            let atom = value as u16;
            log::info!("[GlobalAddAtomA] Parsed integer atom from string: 0x{:04x}", atom);
            emu.reg_write(X86Register::RAX, atom as u64)?;
            return Ok(());
        }
    }
    
    // Check string length (max 255 bytes)
    if string.len() > 255 {
        log::warn!("[GlobalAddAtomA] String too long: {} bytes", string.len());
        winapi::set_last_error(emu, windows_sys::Win32::Foundation::ERROR_INVALID_PARAMETER)?;
        emu.reg_write(X86Register::RAX, 0)?;
        return Ok(());
    }
    
    // Add to atom table
    let atom = {
        let mut table = GLOBAL_ATOM_TABLE.write().unwrap();
        table.add_atom(string.clone())
    };
    
    log::info!("[GlobalAddAtomA] Returning atom: 0x{:04x} for string \"{}\"", atom, string);
    
    // Return the atom
    emu.reg_write(X86Register::RAX, atom as u64)?;
    
    Ok(())
}