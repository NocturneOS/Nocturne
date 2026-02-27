#[repr(C)]
pub struct TSSEntry {
	reserved: u32,
	rsp0: u64,
	rsp1: u64,
	rsp2: u64,
	reserved_2: u64
	ist1: u64,
	ist2: u64,
	ist3: u64,
	ist4: u64,
	ist5: u64,
	ist6: u64,
	ist7: u64,
	reserved_3: u64,
	reserved_4: u16,
	iopb: u16,
}
