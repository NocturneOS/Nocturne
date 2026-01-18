#[inline]
pub fn align_value(value: usize, alignment: usize) -> usize {
    (value + alignment - 1) & !(alignment - 1)
}
