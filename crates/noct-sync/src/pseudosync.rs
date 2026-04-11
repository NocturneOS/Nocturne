use core::{cell::UnsafeCell};

pub struct PseudoSync<T> {
    data: UnsafeCell<T>
}

impl<T> PseudoSync<T> {
    pub fn new(data: T) -> Self {
        Self {
            data: UnsafeCell::new(data)
        }
    }

    pub fn get(&self) -> &T {
        unsafe { &*self.data.get() }
    }

    pub unsafe fn get_mut(&self) -> &mut T {
        unsafe { &mut *self.data.get() }
    }
}

impl<T> From<T> for PseudoSync<T> {
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

unsafe impl<T> Sync for PseudoSync<T> {}
unsafe impl<T> Send for PseudoSync<T> {}