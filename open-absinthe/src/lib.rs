use std::error::Error;
use std::fmt::{Display, Formatter};

pub mod nac;

#[derive(Debug)]
pub struct AbsintheError(i32);

impl Display for AbsintheError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Error for AbsintheError {}
