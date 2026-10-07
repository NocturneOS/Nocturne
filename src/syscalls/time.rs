use core::time::Duration;

pub fn time(_: usize, _: usize, _: usize, _: usize, _: usize) -> Option<usize> {
    let human_time = noct_cmos::read();

    // SAFETY: It seems always return Ok(...)
    let timestamp = human_time.to_unix_timestamp().unwrap() as usize;

    Some(timestamp)
}

pub fn sleep_millis(millis: usize, _: usize, _: usize, _: usize, _: usize) -> Option<usize> {
    noct_sched::sleep(Duration::from_millis(millis as _));

    None
}

pub fn sleep_nanos(nanos_high: usize, nanos_low: usize, _: usize, _: usize, _: usize) -> Option<usize> {
    let nanos: u128 = ((nanos_high as u128) << 32) | (nanos_low as u128);

    noct_sched::sleep(Duration::from_nanos_u128(nanos));
    
    None
}