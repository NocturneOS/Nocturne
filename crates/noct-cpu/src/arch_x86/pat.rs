use core::arch::asm;

pub fn write_pat() {
    let uncacheable = 0b000; // UC
    let write_combining = 0b001; // WC
    let write_through = 0b100; // WT
    let write_back = 0b110; // WB
    let uncached = 0b111; // UC-

    let low = u32::from_le_bytes([write_back, write_through, uncached, uncacheable]);
    let high = u32::from_le_bytes([write_combining, write_through, uncached, uncacheable]);

    unsafe {
        asm!("wrmsr", in("ecx") 0x277, in("eax") low, in("edx") high);
    }
}
