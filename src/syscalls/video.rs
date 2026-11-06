use noct_descriptor::{ResourceDescriptor, video::VideoHandle};
use noct_io::error::{Error, FromPrimitive};
use noct_logger::qemu_log;
use noct_mem::paging::PageFlags;

#[repr(C, packed)]
pub struct VideoModeInfo {
    width: u32,
    height: u32,

    bpp: u8, // in bits

    red_offset: u8,   // in bits
    green_offset: u8, // in bits
    blue_offset: u8,  // in bits

    framebuffer_address: u64, // physical address of framebuffer (may be 0)
}

/// Acquires lock on video buffer.
///
/// On success a descriptor is being created and video info is being written into the [`VideoModeInfo`] pointer.
///
/// Returns a file descriptor if everything's okay,
/// Returns -errno if error is encountered.
pub fn video_acquire(
    out_mode_info: usize,
    _: usize,
    _: usize,
    _: usize,
    _: usize,
) -> Result<usize, Error> {
    let Some(modeinfo) = crate::mem::usermem::verify_ptr_mut::<VideoModeInfo>(out_mode_info) else {
        return Err(Error::MemoryError);
    };

    let Some(real_mode_info) = noct_video::CURRENT_VIDEO_MODE.try_lock() else {
        return Err(Error::Busy);
    };

    let binding = real_mode_info.as_ref().unwrap();

    let phys = binding.buffer_phys();
    let virt = binding.buffer().as_ptr().addr();
    let size = binding.buffer_size();

    qemu_log!("P{phys:x} -> V{virt:x} with size of {size} bytes.");

    let Some(vm_addr) = (unsafe {
        noct_sched::this_process()
            .address_space
            .pseudo_lock()
            .alloc_virt_region(size)
    }) else {
        return Err(Error::MemoryError as _);
    };

    let map_ctx = noct_mem::paging::MappingContext::map(
        phys,
        vm_addr,
        size,
        PageFlags::Writeable | PageFlags::CacheDisable | PageFlags::Userspace,
    );

    qemu_log!(
        "Allocated video buffer at V{vm_addr:x} with size of {size} bytes. ({v1:x} - {v2:x})",
        v1 = vm_addr,
        v2 = (vm_addr + size)
    );

    let vmi = VideoModeInfo {
        width: binding.resolution().width as _,
        height: binding.resolution().height as _,
        bpp: (binding.bpp().unwrap() << 3) as u8,

        red_offset: binding.color_layout().red_offset(),
        green_offset: binding.color_layout().green_offset(),
        blue_offset: binding.color_layout().blue_offset(),

        framebuffer_address: vm_addr as u64,
    };

    unsafe { modeinfo.write(vmi) };

    // Make a descriptor for lock, because video buffer is a resource too.
    let fd = {
        let process = &noct_sched::this_thread().process;

        let mut reslock = process.resources.lock();

        reslock
            .make(ResourceDescriptor::VideoLock(VideoHandle::from_lock(
                real_mode_info,
                map_ctx,
            )))
            .id()
    };

    Ok(fd)
}

#[repr(usize)]
#[derive(FromPrimitive)]
enum VideoCommand {
    GetVideoInfo = 0,
}

pub fn video_control(
    command: usize,
    data1: usize,
    _data2: usize,
    _data3: usize,
    _data4: usize,
) -> Result<usize, Error> {
    let command = VideoCommand::from_usize(command).ok_or(Error::InvalidArgument)?;

    match command {
        VideoCommand::GetVideoInfo => {
            let modeinfo = {
                crate::mem::usermem::verify_ptr_mut::<VideoModeInfo>(data1)
                    .ok_or(Error::MemoryError)
            }?;

            let process = &noct_sched::this_thread().process;

            let reslock = process.resources.lock();

            let handle = reslock
                .iter()
                .filter_map(|x| match x.res {
                    ResourceDescriptor::VideoLock(ref lk) => Some(lk),
                    _ => None,
                })
                .next();

            let binding = handle.ok_or(Error::InvalidHandle)?;

            let vm_addr = binding.map_ctx().vm_addr();

            let bind = binding.get_lock().as_ref().unwrap();

            let vmi = VideoModeInfo {
                width: bind.resolution().width as _,
                height: bind.resolution().height as _,
                bpp: (bind.bpp().unwrap() << 3) as u8,

                red_offset: bind.color_layout().red_offset(),
                green_offset: bind.color_layout().green_offset(),
                blue_offset: bind.color_layout().blue_offset(),

                framebuffer_address: vm_addr as u64,
            };

            unsafe { modeinfo.write(vmi) };
        }
    };

    todo!()
}

/// Releases a video lock.
///
/// Returns -1 if the lock wasn't acquired by the process before.
/// Returns 0 if lock was acquired before and it was successfully closed.
pub fn video_release(_: usize, _: usize, _: usize, _: usize, _: usize) -> Result<usize, Error> {
    let process = &noct_sched::this_thread().process;
 
    let mut reslock = process.resources.lock();

    let handle = reslock
        .iter()
        .filter_map(|x| match x.res {
            ResourceDescriptor::VideoLock(_) => Some(x.id()),
            _ => None,
        })
        .next();

    if let Some(fd) = handle {
        reslock.close(fd);

        return Ok(0);
    }

    Ok(-1isize as usize)
}
