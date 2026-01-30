use alloc::string::String;

#[repr(C, packed(4))]
pub struct Process {
    pub id: usize,
    pub page_directory_phys: usize,
    pub page_directory_virt: usize,
    pub thread_count: usize,
    pub name: String,
    pub cwd: String,
}
