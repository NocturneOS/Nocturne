pub struct PseudoSync<T>(T);

impl<T> PseudoSync<T> {
    pub fn new(t: T) -> Self {
        Self(t)
    }
}

impl<T> From<T> for PseudoSync<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

impl<T> AsRef<T> for PseudoSync<T> {
    fn as_ref(&self) -> &T {
        &self.0
    }
}

impl<T> AsMut<T> for PseudoSync<T> {
    fn as_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

unsafe impl<T> Sync for PseudoSync<T> {}
unsafe impl<T> Send for PseudoSync<T> {}