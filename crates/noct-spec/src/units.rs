#[derive(Debug)]
pub struct Point<T> {
    pub x: T,
    pub y: T,
}

#[derive(Debug)]
pub struct Size<T> {
    pub width: T,
    pub height: T,
}

impl<T> From<(T, T)> for Size<T> {
    fn from(value: (T, T)) -> Self {
        Self {
            width: value.0,
            height: value.1,
        }
    }
}

#[derive(Debug)]
pub struct Rectangle<T> {
    pub x: T,
    pub y: T,
    pub width: T,
    pub height: T,
}
