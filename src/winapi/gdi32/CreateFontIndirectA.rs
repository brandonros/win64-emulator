/*
CreateFontIndirectA function (wingdi.h)
02/22/2024
The CreateFontIndirect function creates a logical font that has the specified characteristics. The font can subsequently be selected as the current font for any device context.

Syntax
C++

Copy
HFONT CreateFontIndirectA(
  [in] const LOGFONTA *lplf
);
Parameters
[in] lplf

A pointer to a LOGFONT structure that defines the characteristics of the logical font.

Return value
If the function succeeds, the return value is a handle to a logical font.

If the function fails, the return value is NULL.
*/

use crate::emulation::engine::{EmulatorEngine, EmulatorError, X86Register};
use std::sync::atomic::{AtomicU64, Ordering};

// LOGFONTA structure
#[repr(C)]
#[derive(Debug)]
struct LOGFONTA {
    lf_height: i32,
    lf_width: i32,
    lf_escapement: i32,
    lf_orientation: i32,
    lf_weight: i32,
    lf_italic: u8,
    lf_underline: u8,
    lf_strikeout: u8,
    lf_charset: u8,
    lf_out_precision: u8,
    lf_clip_precision: u8,
    lf_quality: u8,
    lf_pitch_and_family: u8,
    lf_face_name: [u8; 32], // LF_FACESIZE = 32
}

// Global handle counter for font handles
static NEXT_FONT_HANDLE: AtomicU64 = AtomicU64::new(0x8000);

pub fn CreateFontIndirectA(emu: &mut dyn EmulatorEngine) -> Result<(), EmulatorError> {
    // HFONT CreateFontIndirectA(
    //   const LOGFONTA *lplf  // RCX
    // )
    
    let logfont_ptr = emu.reg_read(X86Register::RCX)?;
    
    log::info!("[CreateFontIndirectA] LOGFONTA ptr: 0x{:x}", logfont_ptr);
    
    if logfont_ptr == 0 {
        log::warn!("[CreateFontIndirectA] NULL LOGFONTA pointer");
        emu.reg_write(X86Register::RAX, 0)?; // Return NULL
        return Ok(());
    }
    
    // Read LOGFONTA structure
    let mut logfont_bytes = vec![0u8; std::mem::size_of::<LOGFONTA>()];
    emu.mem_read(logfont_ptr, &mut logfont_bytes)?;
    
    // Parse the structure (we'll just log the key fields)
    let height = i32::from_le_bytes([logfont_bytes[0], logfont_bytes[1], logfont_bytes[2], logfont_bytes[3]]);
    let width = i32::from_le_bytes([logfont_bytes[4], logfont_bytes[5], logfont_bytes[6], logfont_bytes[7]]);
    let weight = i32::from_le_bytes([logfont_bytes[16], logfont_bytes[17], logfont_bytes[18], logfont_bytes[19]]);
    
    // Extract face name (null-terminated string at offset 28)
    let face_name_offset = 28;
    let face_name_bytes = &logfont_bytes[face_name_offset..face_name_offset + 32];
    let face_name = std::str::from_utf8(face_name_bytes)
        .unwrap_or("")
        .trim_end_matches('\0');
    
    log::info!(
        "[CreateFontIndirectA] Creating font - Height: {}, Width: {}, Weight: {}, Face: \"{}\"",
        height, width, weight, face_name
    );
    
    // Create a mock font handle
    let font_handle = NEXT_FONT_HANDLE.fetch_add(0x10, Ordering::SeqCst);
    
    log::info!("[CreateFontIndirectA] Created font handle: 0x{:x}", font_handle);
    
    // Return the font handle
    emu.reg_write(X86Register::RAX, font_handle)?;
    
    Ok(())
}