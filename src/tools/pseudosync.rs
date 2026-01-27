use core::ptr::addr_of_mut;

pub struct PseudoSync<T>(T);

impl<T> PseudoSync<T> {
    pub fn new(t: T) -> Self {
        Self(t)
    }

    pub fn get(&self) -> &T {
        &self.0
    }

    pub unsafe fn get_mut(&self) -> &mut T {
        unsafe { &mut *(&raw const self.0 as *mut T) }
    }
}

impl<T> From<T> for PseudoSync<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

unsafe impl<T> Sync for PseudoSync<T> {}
unsafe impl<T> Send for PseudoSync<T> {}