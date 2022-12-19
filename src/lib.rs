use std::io::{Read, Seek};

use der::Decodable;
use pkcs7::{ContentInfo, ContentType};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CtlError {
    #[error("I/O error")]
    Io(#[from] std::io::Error),

    #[error("bad DER encoding")]
    Der(#[from] der::Error),

    #[error("bad PKCS#7 ContentType: expected SignedData, got {0:?}")]
    ContentType(ContentType),
}

#[derive(Debug)]
pub struct Ctl {}

impl Ctl {
    /// Load a `Ctl` from the given source, which is expected to be a
    /// [Cabinet Format](https://learn.microsoft.com/en-us/windows/win32/msi/cabinet-files)
    /// encoded stream.
    #[cfg(feature = "cab")]
    pub fn from_cab<R: Read + Seek>(source: R) -> Result<Self, CtlError> {
        let mut cabinet = cab::Cabinet::new(source)?;

        // We expect the actual STL to be at "authroot.stl" inside an STL
        // cabinet file, and nowhere else.
        Self::from_der(cabinet.read_file("authroot.stl")?)
    }

    /// Load a `Ctl` from the given source, which is expected to be a DER-encoded
    /// PKCS#7 stream.
    pub fn from_der<R: Read + Seek>(mut source: R) -> Result<Self, CtlError> {
        // TODO: Micro-optimize: could pre-allocate `der` here using the stream's
        // size (since we have the `Seek` bound).
        let mut der = vec![];
        source.read_to_end(&mut der)?;

        let body = ContentInfo::from_der(&der)?;
        let ContentInfo::Other((ContentType::SignedData, _)) = body else {
            return Err(CtlError::ContentType(body.content_type()))
        };

        unimplemented!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
}
