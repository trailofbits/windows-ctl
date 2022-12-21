use std::io::{Read, Seek};

use der::asn1::{Any, ObjectIdentifier, OctetString, SetOfVec};
use der::Decode;
use der::Sequence;
use pkcs7::{ContentInfo, ContentType};
use thiserror::Error;

pub const MS_CERT_TRUST_LIST_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.10.1");

#[derive(Debug, Error)]
pub enum CtlError {
    #[error("I/O error")]
    Io(#[from] std::io::Error),

    #[error("bad DER encoding")]
    Der(#[from] der::Error),

    #[error("bad PKCS#7 ContentType: expected SignedData, got {0:?}")]
    ContentType(ContentType),

    #[error("missing SignedData encapsulated content")]
    MissingSignedData,

    #[error("bad SignedData ContentType: expected {MS_CERT_TRUST_LIST_OID}, got {0}")]
    Content(ObjectIdentifier),

    #[error("missing SignedData inner content")]
    MissingSignedDataContent,
}

// NOTE(ww): Each certificate entry in the CTL looks something like this:
//
// ```
// SEQUENCE (2 elem)
//   OCTET STRING (20 byte)
//   SET (7 elem)
//     SEQUENCE (2 elem)
//       OBJECT IDENTIFIER 1.3.6.1.4.1.311.10.11.104
//       SET (1 elem)
//         OCTET STRING (8 byte)
//     SEQUENCE (2 elem)
//       OBJECT IDENTIFIER 1.3.6.1.4.1.311.10.11.126
//       SET (1 elem)
//         OCTET STRING (8 byte)
//     SEQUENCE (2 elem)
//       OBJECT IDENTIFIER 1.3.6.1.4.1.311.10.11.105
//       SET (1 elem)
//         OCTET STRING (14 byte)
//           SEQUENCE (1 elem)
//             OBJECT IDENTIFIER 1.3.6.1.4.1.311.60.3.2
//     SEQUENCE (2 elem)
//       OBJECT IDENTIFIER 1.3.6.1.4.1.311.10.11.29 certSubjectNameMd5HashPropId (Microsoft)
//       SET (1 elem)
//         OCTET STRING (16 byte)
//     SEQUENCE (2 elem)
//       OBJECT IDENTIFIER 1.3.6.1.4.1.311.10.11.20 certKeyIdentifierPropId (Microsoft)
//       SET (1 elem)
//         OCTET STRING (20 byte)
//     SEQUENCE (2 elem)
//       OBJECT IDENTIFIER 1.3.6.1.4.1.311.10.11.98
//       SET (1 elem)
//         OCTET STRING (32 byte)
//     SEQUENCE (2 elem)
//       OBJECT IDENTIFIER 1.3.6.1.4.1.311.10.11.11
//       SET (1 elem)
//         OCTET STRING (74 byte)
// ```
//
// ...where that first `OCTET STRING` is an identifier for the corresponding
// certificate (it's probably a SHA-1 or similar digest).
/// Represents a single entry in the certificate trust list.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct CertEntry {
    cert_id: OctetString,
    unknown: SetOfVec<Any>,
}

impl CertEntry {
    /// Returns the certificate's ID, as a hex-encoded string.
    pub fn cert_id(&self) -> String {
        hex::encode(self.cert_id.as_bytes())
    }
}

// NOTE(ww): The certTrustList SEQUENCE looks something like this:
//
// ```
// SEQUENCE (5 elem)
//   SEQUENCE (1 elem)
//     OBJECT IDENTIFIER 1.3.6.1.4.1.311.10.3.9 rootListSigner
//   INTEGER (69 bit) 369068011719060212218
//   UTCTime 2022-11-15 22:21:26 UTC
//   SEQUENCE (2 elem)
//     OBJECT IDENTIFIER 1.3.14.3.2.26 sha1
//     NULL
//   SEQUENCE (447 elem)
// ```
//
// ...where that last inner `SEQUENCE` actually contains the list of trusted certificates.
// We don't really care about the other fields for now, since we don't know how
// to interpret them.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct Ctl {
    // SEQUENCE
    //   OBJECT IDENTIFIER
    unknown0: Any,

    // INTEGER
    unknown1: Any,

    /// UTCTime
    unknown2: Any,

    // SEQUENCE
    //   OBJECT IDENTIFIER
    //   NULL
    unknown3: Any,

    pub cert_list: Vec<CertEntry>,
}

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
        let signed_data = match body {
            ContentInfo::SignedData(Some(signed_data)) => signed_data,
            ContentInfo::SignedData(_) => return Err(CtlError::MissingSignedData),
            _ => return Err(CtlError::ContentType(body.content_type())),
        };

        // Our actual SignedData content should be a MS-specific `certTrustList`.
        if signed_data.encap_content_info.e_content_type != MS_CERT_TRUST_LIST_OID {
            return Err(CtlError::Content(
                signed_data.encap_content_info.e_content_type,
            ));
        }

        let Some(content) = signed_data.encap_content_info.e_content else {
            return Err(CtlError::MissingSignedDataContent);
        };

        Ok(content.decode_into()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
}
