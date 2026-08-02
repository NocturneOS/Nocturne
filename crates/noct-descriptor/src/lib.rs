#![no_std]

use alloc::vec::Vec;

extern crate alloc;

#[derive(Debug)]
pub enum ResourceDescriptor {
    Null,
    // TODO: Use real I/O between terminal and program

    // Emulates stdin
    TerminalInput,
    
    // Emulates stdout / stderr
    TerminalOutput,
    
    FileStream(noct_fsman::handles::file::FileHandle),
    DirectoryHandle(noct_fsman::handles::directory::DirectoryHandle),

    EventQueue(noct_input::EventQueue)
}

impl ResourceDescriptor {
    pub fn as_filestream(&self) -> Option<&noct_fsman::handles::file::FileHandle> {
        if let Self::FileStream(fh) = self {
            Some(fh)
        } else {
            None
        }
    }

    pub fn as_event_queue(&self) -> Option<&noct_input::EventQueue> {
        if let Self::EventQueue(eq) = self {
            Some(eq)
        } else {
            None
        }
    }

    pub fn as_event_queue_mut(&mut self) -> Option<&mut noct_input::EventQueue> {
        if let Self::EventQueue(eq) = self {
            Some(eq)
        } else {
            None
        }
    }
}

pub struct Descriptor {
    id: usize,
    pub res: ResourceDescriptor
}

impl Descriptor {
    pub fn id(&self) -> usize {
        self.id
    }
}

#[derive(Default)]
struct DescriptorFactory {
    current_id: usize
}

impl DescriptorFactory {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn make(&mut self, res: ResourceDescriptor) -> Descriptor {
        let next_id = self.current_id;

        self.current_id += 1;

        Descriptor { id: next_id, res }
    }
}

#[derive(Default)]
pub struct Descriptors {
    factory: DescriptorFactory,
    descriptors: Vec<Descriptor>
}

impl Descriptors {
    pub fn new() -> Self {
        let mut descriptors = Self::default();

        // Create basic descriptors

        // Stdin
        descriptors.make(ResourceDescriptor::TerminalInput);
        // Stdout
        descriptors.make(ResourceDescriptor::TerminalOutput);
        // Stderr
        descriptors.make(ResourceDescriptor::TerminalOutput);

        descriptors
    }

    pub fn iter(&self) -> core::slice::Iter<'_, Descriptor> {
        self.descriptors.iter()
    }

    pub fn iter_mut(&mut self) -> core::slice::IterMut<'_, Descriptor> {
        self.descriptors.iter_mut()
    }

    pub fn make(&mut self, res: ResourceDescriptor) -> &mut Descriptor {
        let descriptor = self.factory.make(res);

        self.descriptors.push_mut(descriptor)
    }

    pub fn find(&self, id: usize) -> Option<&Descriptor> {
        self.descriptors.iter().find(|x| x.id == id)
    }

    pub fn find_mut(&mut self, id: usize) -> Option<&mut Descriptor> {
        self.descriptors.iter_mut().find(|x| x.id == id)
    }

    pub fn close(&mut self, id: usize) {
        self.descriptors.retain(|hdl| hdl.id != id);
    }
}