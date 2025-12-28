const BIOS_VGA_BASE: usize = 0xB8000;

pub fn clear_screen() {
    let width = 80;
    let height = 25;

    for i in (BIOS_VGA_BASE..BIOS_VGA_BASE + (width * height * 2)).step_by(2) {
        let ptr = i as *mut u16;

        unsafe { ptr.write(0) };
    }
}

pub fn test_write() {
    let data = "Hello World!";

    for (n, i) in data.bytes().enumerate() {
        let ptr = (BIOS_VGA_BASE + (n * 2)) as *mut u16;

        unsafe { ptr.write(i as u16 | 0x0E00) };
    }
}