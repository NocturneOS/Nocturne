#[repr(C, packed)]
#[derive(Default)]
pub struct AddressSpace {
    pub(super) page_root_physical: usize,
    pub(super) page_root_virtual: usize,
}