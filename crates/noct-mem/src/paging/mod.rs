cfg_if::cfg_if! {
    if #[cfg(target_arch = "x86")] {
        mod x86_common;
        pub use x86_common::*;

        mod x86;
        pub use x86::*;
    } else if #[cfg(target_arch = "x86_64")] {
        mod x86_common;
        pub use x86_common::*;

        mod x86_64;
        pub use x86_64::*;
    }
}

pub trait PagingHierarchy {
    /// How much paging levels architecture have?
    const LEVELS: usize;

    /// How much entried per one paging table
    const ENTRIES: usize;

    /// Where is the recursive paging index?
    const RECURSIVE_INDEX: usize;

    /// Fetches the index of the table at index level where vaddr belongs to
    fn index_at_level(vaddr: usize, level: usize) -> usize;

    /// How many root entried user owned
    fn user_root_entry_count() -> usize;

    /// Gets paging root (for x86 is PD, for x86_64 it's a PML4T)
    fn root() -> &'static [Page];
}

// Good for temporary mappings
pub struct MappingContext {
    virtual_addr: usize,
    byte_count: usize,
}

impl MappingContext {
    pub fn map(phys_addr: usize, virt_addr: usize, byte_count: usize, flags: PageFlags) -> Self {
        map_pages(
            phys_addr,
            virt_addr,
            byte_count,
            flags,
        );

        Self {
            virtual_addr: virt_addr,
            byte_count
        }
    }
}

impl Drop for MappingContext {
    fn drop(&mut self) {
        unmap_pages(
            self.virtual_addr,
            self.byte_count,
        );
    }
}

pub fn with_mapping_cx<T>(phys_addr: usize, virt_addr: usize, byte_count: usize, flags: PageFlags, f: impl FnOnce() -> T) -> T {
    let cx = MappingContext::map(phys_addr, virt_addr, byte_count, flags);

    let value = f();

    drop(cx);

    value
}