#![no_std]

use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(any(target_arch = "x86"))] {
        mod x86;
        pub use x86::*;
    } else if #[cfg(target_arch = "x86_64")] {
        mod x86_64;
        pub use x86_64::*;

        mod x86;
        pub use x86::{gdt, idt, halt};
    }
}
