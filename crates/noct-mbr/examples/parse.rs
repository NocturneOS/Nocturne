use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
};

use noct_mbr::{PartitionRecord, PartitionType};

fn scan_partitions(
    disk: &mut File,
    block_size: usize,
    container_base: Option<u32>,
    ebr_location: Option<u32>,
) -> Vec<PartitionRecord> {
    let mut raw_buffer = [0u8; 512];
    let read_at = ebr_location.unwrap_or(0) as u64 * block_size as u64;

    disk.seek(SeekFrom::Start(read_at)).expect("Seek failed");
    disk.read_exact(&mut raw_buffer).expect("Read failed");

    let mut records: Vec<PartitionRecord> = noct_mbr::parse_from_sector(&raw_buffer);
    let mut filtered_records = Vec::new();

    for record in records.iter_mut() {
        if record.partition_type == PartitionType::Free {
            continue;
        }

        // Adjust partition address if inside extended container
        if let Some(base) = container_base {
            record.start_sector_lba += base;
        }

        match record.partition_type {
            PartitionType::Extended | PartitionType::ExtendedLBA => {
                if container_base.is_none() {
                    // Primary extended partition - add and recurse
                    filtered_records.push(record.clone());
                    let new_base = Some(record.start_sector_lba);
                    let sub = scan_partitions(disk, block_size, new_base, new_base);
                    filtered_records.extend(sub);
                } else {
                    // Extended link record - recurse without adding to output
                    let next_ebr = Some(record.start_sector_lba);
                    let sub = scan_partitions(disk, block_size, container_base, next_ebr);
                    filtered_records.extend(sub);
                }
            }
            _ => {
                // Regular partition - add to output
                filtered_records.push(record.clone());
            }
        }
    }

    filtered_records
}

fn main() {
    let filename = std::env::args().nth(1).expect("No disk specified");
    let mut file = File::open(&filename).expect("Failed to open file");
    let partitions = scan_partitions(&mut file, 512, None, None);

    for (n, i) in partitions.iter().enumerate() {
        println!(
            "{n}. {:?} => {:?}",
            i.partition_type,
            i.start_sector_lba..(i.start_sector_lba + i.num_sectors)
        );
    }
    // println!("{records:#?}");
}
