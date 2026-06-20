#![no_std]

use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(any(target_arch = "x86"))] {
        mod arch_x86;
        pub use arch_x86::*;
    } else if #[cfg(target_arch = "x86_64")] {
        mod arch_x86_64;
        pub use arch_x86_64::*;

        mod arch_x86;
        pub use arch_x86::{gdt, idt, halt};

        pub use x86_64;
    }
}
