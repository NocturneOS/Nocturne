pub mod interrupt_locker;
pub mod without_interrupts;

#[inline]
pub fn align_value(value: usize, alignment: usize) -> usize {
    if value.is_multiple_of(alignment) {
        return value;
    }

    (value + alignment - 1) & !(alignment - 1)
}

#[inline]
pub fn align_down(addr: usize, align: usize) -> usize {
    addr & !(align - 1)
}
