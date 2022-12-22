use std::io::{Read, Seek};

use der::asn1::{Any, ObjectIdentifier, OctetString};
use der::{Decode, Enumerated, Sequence};
use pkcs7::{ContentInfo, ContentType};
use spki::AlgorithmIdentifier;
use thiserror::Error;
use x509_cert::attr::Attributes;
use x509_cert::ext::pkix::ExtendedKeyUsage;
use x509_cert::time::Time;

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

type SubjectIdentifier = OctetString;

/// Represents a single entry in the certificate trust list.
///
/// From MS-CAESO:
///
/// ```asn1
/// TrustedSubject ::= SEQUENCE {
///   subjectIdentifier SubjectIdentifier,
///   subjectAttributes Attributes OPTIONAL
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TrustedSubject {
    identifier: SubjectIdentifier,
    attributes: Option<Attributes>,
}

impl TrustedSubject {
    /// Returns the certificate's ID, as a hex-encoded string.
    pub fn cert_id(&self) -> String {
        hex::encode(self.identifier.as_bytes())
    }
}

/// Version identifier for CertificateTrustList.
#[derive(Clone, Debug, Copy, PartialEq, Eq, Enumerated)]
#[asn1(type = "INTEGER")]
#[repr(u8)]
pub enum CtlVersion {
    /// CtlVersion 1 (default)
    V1 = 0,
}

impl Default for CtlVersion {
    fn default() -> Self {
        CtlVersion::V1
    }
}

type SubjectUsage = ExtendedKeyUsage;

/// The certificate trust list.
///
/// From [MS-CAESO], pages 47-48:
///
/// ```asn1
/// CertificateTrustList ::= SEQUENCE {
///   version CTLVersion DEFAULT v1,
///   subjectUsage SubjectUsage,
///   listIdentifier ListIdentifier OPTIONAL,
///   sequenceNumber HUGEINTEGER OPTIONAL,
///   ctlThisUpdate ChoiceOfTime,
///   ctlNextUpdate ChoiceOfTime OPTIONAL,
///   subjectAlgorithm AlgorithmIdentifier,
///   trustedSubjects TrustedSubjects OPTIONAL,
///   ctlExtensions [0] EXPLICIT Extensions OPTIONAL
/// }
/// ```
///
/// [MS-CAESO]: https://download.microsoft.com/download/C/8/8/C8862966-5948-444D-87BD-07B976ADA28C/%5BMS-CAESO%5D.pdf
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct CertificateTrustList {
    #[asn1(default = "Default::default")]
    pub version: CtlVersion,
    pub subject_usage: SubjectUsage,
    pub list_identifier: Option<OctetString>,
    // TODO: Better type here? UintRef<'_> doesn't fit, since it's borrowed
    // in an owning struct.
    pub sequence_number: Option<Any>,
    // NOTE: MS doesn't bother to document `ChoiceOfTime`, but experimentally
    // it's the same thing as an X.509 `Time` (See <https://www.rfc-editor.org/rfc/rfc5280#section-4.1>)
    pub this_update: Time,
    pub next_update: Option<Time>,
    pub subject_algorithm: AlgorithmIdentifier<Any>,
    pub trusted_subjects: Option<Vec<TrustedSubject>>,
    // TODO: Similar to `sequence_number`: this should really be `x509_cert::ext::Extensions`
    // but that's a borrowed type and this struct is owning.
    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    pub ctl_extensions: Option<Any>,
}

impl CertificateTrustList {
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
