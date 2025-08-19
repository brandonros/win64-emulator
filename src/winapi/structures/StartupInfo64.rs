use unicorn_engine::Unicorn;

use crate::emulation::memory;

#[derive(Debug)]
pub struct StartupInfo64 {
    cb: u32,
    reserved: u64,
    desktop: u64,
    title: u64,
    x: u32,
    y: u32,
    x_size: u32,
    y_size: u32,
    x_count_chars: u32,
    y_count_chars: u32,
    fill_attribute: u32,
    flags: u32,
    show_window: u16,
    cb_reserved2: u16,
    lp_reserved2: u64,
    std_input: u32,
    std_output: u32,
    std_error: u32,
}

impl Default for StartupInfo64 {
    fn default() -> Self {
        Self::new()
    }
}

impl StartupInfo64 {
    pub fn new() -> StartupInfo64 {
        StartupInfo64 {
            cb: 84,
            reserved: 0,
            desktop: 0,
            title: 0,
            x: 10,
            y: 10,
            x_size: 300,
            y_size: 200,
            x_count_chars: 0,
            y_count_chars: 0,
            fill_attribute: 0,
            flags: 0,
            show_window: 1,
            cb_reserved2: 0,
            lp_reserved2: 0,
            std_input: 0,
            std_output: 0,
            std_error: 0,
        }
    }

    pub fn save(&self, emu: &mut Unicorn<()>, addr: u64) {
        memory::write_dword_le(emu, addr, self.cb);
        memory::write_qword_le(emu, addr + 4, self.reserved);
        memory::write_qword_le(emu, addr + 12, self.desktop);
        memory::write_qword_le(emu, addr + 20, self.title);
        memory::write_dword_le(emu, addr + 28, self.x);
        memory::write_dword_le(emu, addr + 32, self.y);
        memory::write_dword_le(emu, addr + 36, self.x_size);
        memory::write_dword_le(emu, addr + 40, self.y_size);
        memory::write_dword_le(emu, addr + 44, self.x_count_chars);
        memory::write_dword_le(emu, addr + 48, self.y_count_chars);
        memory::write_dword_le(emu, addr + 52, self.fill_attribute);
        memory::write_dword_le(emu, addr + 56, self.flags);
        memory::write_word_le(emu, addr + 60, self.show_window);
        memory::write_word_le(emu, addr + 62, self.cb_reserved2);
        memory::write_qword_le(emu, addr + 64, self.lp_reserved2);
        memory::write_dword_le(emu, addr + 72, self.std_input);
        memory::write_dword_le(emu, addr + 76, self.std_output);
        memory::write_dword_le(emu, addr + 80, self.std_error);
    }
}
