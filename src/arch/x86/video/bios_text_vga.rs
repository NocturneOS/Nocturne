use crate::arch::x86::video::CURRENT_VIDEO_MODE;

pub fn clear_screen() {
    let base = CURRENT_VIDEO_MODE.lock().buffer_ptr;
    let size = {
        let binding = CURRENT_VIDEO_MODE.lock();

        // 2 = character (1 byte) + attribute (1 byte)
        binding.resolution.width * binding.resolution.height * 2
    };

    for i in (base..base + size).step_by(2) {
        let ptr = i as *mut u16;

        unsafe { ptr.write(0) };
    }
}

pub fn test_write() {
    let data = "Hello World!";

    let base = CURRENT_VIDEO_MODE.lock().buffer_ptr;

    for (n, i) in data.bytes().enumerate() {
        let ptr = (base + (n * 2)) as *mut u16;

        unsafe { ptr.write(i as u16 | 0x0E00) };
    }
}
