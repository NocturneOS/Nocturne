use core::io::Write;

use alloc::vec::Vec;
use bitflags::bitflags;
use noct_io::error::Error;
use noct_sched::process::Process;

bitflags! {
    #[derive(PartialEq)]
    pub struct MetricFlags: u32 {
        const MemoryUsage = 1 << 0;
        const ProcessInfo = 1 << 1;
    }

    #[derive(PartialEq)]
    pub struct ExtendedMetricFlags: u32 {
        // ...
    }
}

trait Serializable {
    fn write(&self, buffer: &mut Vec<u8>);
}

#[repr(C)]
struct MemoryUsageMetric {
    heap_used: u64,

    system_free: u64,
}

impl Serializable for MemoryUsageMetric {
    fn write(&self, buffer: &mut Vec<u8>) {
        buffer.write(&self.heap_used.to_le_bytes()).unwrap();
        buffer.write(&self.system_free.to_le_bytes()).unwrap();
    }
}

#[repr(C)]
struct ProcessInfoMetric {
    pid: u64,

    thread_count: u64,
}

impl Serializable for ProcessInfoMetric {
    fn write(&self, buffer: &mut Vec<u8>) {
        buffer.write(&self.pid.to_le_bytes()).unwrap();
        buffer.write(&self.thread_count.to_le_bytes()).unwrap();
    }
}

/// Gets process/system metrics.
///
/// Returns number of written metrics.
///
/// If process_id is 0, only global metrics will be gathered.
/// If process_id is -1, the calling process will be used.
pub fn getmetrics(
    process_id: usize,
    metrics_mask: usize,
    extended_metrics_mask: usize,
    out_buffer: usize,
    buffer_size: usize,
) -> Result<usize, Error> {
    let mut buffer: Vec<u8> = Vec::with_capacity(core::cmp::min(64, buffer_size));
    let mut count = 0;

    // All metrics flags are in u32, because the minimal machine word size is 32 bit.
    // If I even make more than 32 possible flags there, I won't be able to use them in x86.
    // This is also a reason that I added the `extended_metrics_mask` field.
    let metrics_mask = MetricFlags::from_bits_truncate(metrics_mask as u32);
    let extended_metrics_mask = MetricFlags::from_bits_truncate(extended_metrics_mask as u32);

    for i in metrics_mask {
        let metric: &dyn Serializable;

        if i == MetricFlags::MemoryUsage {
            metric = &MemoryUsageMetric {
                heap_used: 0,
                system_free: 0,
            };

            count += 1;
        } else if i == MetricFlags::ProcessInfo {
            metric = &ProcessInfoMetric {
                pid: 0,
                thread_count: 0,
            };

            count += 1;
        } else {
            todo!("More metric kinds");
        }

        metric.write(&mut buffer);
    }

    for i in extended_metrics_mask {
        // ...
    }

    let out_buf = crate::mem::usermem::verify_ptr_range_mut::<u8>(out_buffer, buffer_size)
        .ok_or(Error::MemoryError)?;

    unsafe { out_buf.copy_from_nonoverlapping(buffer.as_ptr(), buffer_size.min(buffer.len())) };

    Ok(count)
}
