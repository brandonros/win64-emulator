use std::fmt;

use unicorn_engine::uc_error;
use crate::emulation::engine::EmulatorError;

// Custom error type that can handle both object parsing and unicorn errors
#[derive(Debug)]
pub enum LoaderError {
    ObjectError(object::Error),
    UnicornError(uc_error),
    EmulatorError(EmulatorError),
    IoError(std::io::Error),
    InvalidFormat(String),
    Other(String),
}

impl fmt::Display for LoaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoaderError::ObjectError(e) => write!(f, "Object parsing error: {}", e),
            LoaderError::UnicornError(e) => write!(f, "Unicorn emulation error: {:?}", e),
            LoaderError::EmulatorError(e) => write!(f, "Emulator error: {}", e),
            LoaderError::IoError(e) => write!(f, "IO error: {}", e),
            LoaderError::InvalidFormat(msg) => write!(f, "Invalid format: {}", msg),
            LoaderError::Other(msg) => write!(f, "Error: {}", msg),
        }
    }
}

impl std::error::Error for LoaderError {}

impl From<object::Error> for LoaderError {
    fn from(err: object::Error) -> Self {
        LoaderError::ObjectError(err)
    }
}

impl From<uc_error> for LoaderError {
    fn from(err: uc_error) -> Self {
        LoaderError::UnicornError(err)
    }
}

impl From<std::io::Error> for LoaderError {
    fn from(err: std::io::Error) -> Self {
        LoaderError::IoError(err)
    }
}

impl From<&str> for LoaderError {
    fn from(msg: &str) -> Self {
        LoaderError::InvalidFormat(msg.to_string())
    }
}

impl From<String> for LoaderError {
    fn from(msg: String) -> Self {
        LoaderError::InvalidFormat(msg)
    }
}

impl From<EmulatorError> for LoaderError {
    fn from(err: EmulatorError) -> Self {
        LoaderError::EmulatorError(err)
    }
}