#![no_std]

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
    fn root() -> &'static [usize];
}