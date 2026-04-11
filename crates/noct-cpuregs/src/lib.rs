#![no_std]

use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(any(target_arch = "x86"))] {
        pub mod x86;
        pub use x86::CPURegisters;
    } else if #[cfg(target_arch = "x86_64")] {
        pub mod x86_64;
        pub use x86_64::CPURegisters;
    }
}
