#![no_std]

pub struct MemoryInfo {
    lower: usize,
    higher: usize,
}

impl MemoryInfo {
    pub fn new(lower: usize, higher: usize) -> Self {
        Self { lower, higher }
    }

    pub fn lower(&self) -> usize {
        self.lower
    }

    pub fn higher(&self) -> usize {
        self.higher
    }

    pub fn total(&self) -> usize {
        self.lower() + self.higher()
    }
}

pub trait Module {
    fn cmdline(&self) -> Option<&str>;
    fn start(&self) -> usize;
    fn end(&self) -> usize;

    fn size(&self) -> usize {
        self.end() - self.start()
    }
}

pub struct ModuleIterator<T: Module> {
    modules_addr: *const T,
    modules_count: usize,
    position: usize,
}

impl<T: Module> ModuleIterator<T> {
    pub fn new(addr: *const T, count: usize) -> Self {
        Self {
            modules_addr: addr,
            modules_count: count,
            position: 0,
        }
    }
}

impl<T: Module> Iterator for ModuleIterator<T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        if self.position == self.modules_count {
            return None;
        }

        let data = unsafe { self.modules_addr.add(self.position).read() };

        self.position += 1;

        Some(data)
    }
}

#[derive(Debug)]
pub struct BootVideoInfo {
    pub fb_addr: u64,
    pub fb_pitch: u32,
    pub fb_width: u32,
    pub fb_height: u32,
    pub fb_bpp: u8,
    pub fb_type: u8,
}

pub trait BootInfo {
    type ModuleType;

    fn memory(&self) -> MemoryInfo;
    fn cmdline(&self) -> &str;
    fn modules(&self) -> ModuleIterator<Self::ModuleType>
    where
        <Self as BootInfo>::ModuleType: Module;
    fn video(&self) -> BootVideoInfo;
}
