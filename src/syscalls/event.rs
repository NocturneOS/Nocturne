use noct_io::error::Error;

pub fn open(_: usize, _: usize, _: usize, _: usize, _: usize) -> Result<usize, Error> {
    Ok(noct_input_dispatcher::register_this())
}
