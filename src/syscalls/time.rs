use core::time::Duration;

use noct_io::error::Error;

pub fn sleep_millis(millis: usize, _: usize, _: usize, _: usize, _: usize) -> Result<usize, Error> {
    noct_sched::sleep(Duration::from_millis(millis as _));

    Ok(0)
}

pub fn sleep_nanos(
    nanos_high: usize,
    nanos_low: usize,
    _: usize,
    _: usize,
    _: usize,
) -> Result<usize, Error> {
    let nanos: u128 = ((nanos_high as u128) << 32) | (nanos_low as u128);

    noct_sched::sleep(Duration::from_nanos_u128(nanos));

    Ok(0)
}

pub fn gettimeofday(tv_ptr: usize, tz_ptr: usize, _: usize, _: usize, _: usize) -> Result<usize, Error> {
    #[repr(C)]
    struct TimeValue {
        tv_sec: u64,  // time_t
        tv_usec: i32, // suseconds_t
    }

    let tv = {
        crate::mem::usermem::verify_ptr_mut::<TimeValue>(tv_ptr)
            .and_then(|x| unsafe { x.as_mut() })
            .ok_or(Error::MemoryError)
    }?;

    let human_time = noct_rtc::read();

    let timestamp = human_time.to_unix_timestamp().unwrap() as usize;

    tv.tv_sec = timestamp as _;
    tv.tv_usec = (human_time.millis() as i32 * 1000) as _;

    Ok(0)
}
