use crate::arch;

pub fn without_interrupts<T>(f: impl FnOnce() -> T) -> T {
    arch::disable_interrupts();

    let result = f();

    arch::enable_interrupts();

    result
}