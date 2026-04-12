#![no_std]

pub trait PagingHierarchy {
    const LEVELS: usize;

    /// Per one table
    const ENTRIES: usize;

    /// Fetches the index of the table at index level where vaddr belongs to
    fn index_at_level(vaddr: usize, level: usize) -> usize;

    /// How many root entried user owned
    fn user_root_entry_count() -> usize;
}