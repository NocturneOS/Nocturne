use noct_io::error::Error;
use x86::cpuid;

pub fn fillrandom(
    buffer: usize,
    size: usize,
    _: usize,
    _: usize,
    _: usize,
) -> Result<usize, Error> {
    let buf =
        crate::mem::usermem::verify_ptr_range_mut::<u8>(buffer, size).ok_or(Error::MemoryError)?;

    let slice = unsafe { core::slice::from_raw_parts_mut(buf, size) };

    // Move that to noct-random
    {
        let rdrand_supported = cpuid::CpuId::new().get_feature_info().unwrap().has_rdrand();

        if rdrand_supported {
            for _ in 0..16 {
                if unsafe { x86::random::rdrand_slice(slice) } {
                    break;
                }
            }
        }
    }

    Ok(size)
}
