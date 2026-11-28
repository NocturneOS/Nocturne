use core::{io::Write, sync::atomic::Ordering};

use alloc::{boxed::Box, vec::Vec};
use bitflags::bitflags;
use noct_io::error::Error;

bitflags! {
    /// Common metric flags.
    #[derive(PartialEq)]
    pub struct MetricFlags: u32 {
        const MemoryUsage = 1 << 0;
        const ProcessInfo = 1 << 1;
    }

    /// Extended metric flags that didn't get into the [`MetricFlags`].
    #[derive(PartialEq)]
    pub struct ExtendedMetricFlags: u32 {
        // ...
    }
}

/// An item that implements that trait can serialize itself into raw data.
trait Serializable {
    fn write(&self, buffer: &mut Vec<u8>);
    fn raw_len(&self) -> u16;
}

#[repr(C)]
struct MemoryUsageMetric {
    heap_used: u64,

    system_total: u64,
    system_free: u64,
}

impl Serializable for MemoryUsageMetric {
    fn write(&self, buffer: &mut Vec<u8>) {
        buffer.write(&self.heap_used.to_le_bytes()).unwrap();
        buffer.write(&self.system_total.to_le_bytes()).unwrap();
        buffer.write(&self.system_free.to_le_bytes()).unwrap();
    }
    
    fn raw_len(&self) -> u16 {
        24
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

    fn raw_len(&self) -> u16 {
        16
    }
}

/// Gets process/system metrics.
///
/// Returns number of written metrics.
///
/// If process_id is 0, only global metrics will be gathered.
/// If process_id is -1, the calling process will be used.
/// 
/// If the operation is successful it will write chunks to the buffer.
/// Each chunk has its header and data.
/// 
/// The structure of the header is:
/// ```
/// header_id: u8,
/// data_size: u16,
/// ```
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
    // If I even make more than 32 possible flags there (e.g. 64-bit), I won't be able to use them in x86.
    // This is also a reason that I added the `extended_metrics_mask` field.
    let metrics_mask = MetricFlags::from_bits_truncate(metrics_mask as u32);
    let extended_metrics_mask = MetricFlags::from_bits_truncate(extended_metrics_mask as u32);

    for i in metrics_mask {
        let metric: Box<dyn Serializable>;
        let id: u8;

        let proc = noct_sched::this_process();

        if i == MetricFlags::MemoryUsage {
            let heap_lock = proc.heap.lock();
            let system_total = noct_physmem_alloc::total_page_count() as u64;
            let system_free = system_total - noct_physmem_alloc::used_page_count() as u64;

            metric = Box::new(MemoryUsageMetric {
                heap_used: heap_lock.as_ref().unwrap().len() as _,
                
                system_total,
                system_free,
            });

            drop(heap_lock);

            id = 0;

            count += 1;
        } else if i == MetricFlags::ProcessInfo {
            metric = Box::new(ProcessInfoMetric {
                pid: proc.id as _,
                thread_count: proc.thread_count.load(Ordering::Relaxed) as _,
            });

            id = 1;

            count += 1;
        } else {
            todo!("More metric kinds");
        }

        buffer.write(&id.to_le_bytes()).unwrap();
        buffer.write(&metric.raw_len().to_le_bytes()).unwrap();
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
