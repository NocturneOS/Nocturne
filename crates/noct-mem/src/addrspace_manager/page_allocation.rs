use alloc::vec::Vec;

/// Represents how pages were allocated.
#[derive(Debug)]
pub enum PageAllocation {
    /// Multiple pages were allocated in a contiguous block.
    Bulk { addr: usize, page_count: usize },
    /// Multiple pages were allocated in multiple operations one page each.
    Multiple(Vec<usize>),
}

impl PageAllocation {
    pub fn page_count(&self) -> usize {
        match self {
            Self::Bulk { page_count, .. } => *page_count,
            // Since each vec element is a page, length of that vector is page count.
            Self::Multiple(items) => items.len(),
        }
    }

    pub fn pages(&self) -> PAPages<'_> {
        PAPages {
            pa: self,
            page_count_bulk: if matches!(self, Self::Bulk{..}) { Some(0) } else { None },
            vector_position: if matches!(self, Self::Multiple(..)) { Some(0) } else { None },
        }
    }
}

pub struct PAPages<'pa> {
    pa: &'pa PageAllocation,

    page_count_bulk: Option<usize>,
    vector_position: Option<usize>,
}

impl<'pa> Iterator for PAPages<'pa> {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        match self.pa {
            PageAllocation::Bulk { addr, page_count } => {
                if self.page_count_bulk.unwrap() < *page_count {
                    let count = self.page_count_bulk.unwrap();

                    *self.page_count_bulk.as_mut().unwrap() += 1;

                    return Some(*addr + (crate::paging::PAGE_SIZE * count));
                }

                None
            }
            PageAllocation::Multiple(items) => {
                let position = self.vector_position.unwrap();

                if position < items.len() {
                    *self.vector_position.as_mut().unwrap() += 1;

                    return items.get(position).copied();
                }

                None
            },
        }
    }
}
