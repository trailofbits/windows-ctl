//! A crate for parsing Windows Certificate Trust Lists (CTLs).
//!
//! Certificate Trust Lists are how Windows distributes the metadata needed
//! to bootstrap trusted certificate stores.

#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_docs)]
#![allow(clippy::redundant_field_names)]
#![forbid(unsafe_code)]

use std::io::{Read, Seek};

use der::asn1::{Any, ObjectIdentifier, OctetString};
use der::{Decode, Enumerated, Sequence};
use pkcs7::{ContentInfo, ContentType};
use spki::AlgorithmIdentifier;
use thiserror::Error;
use x509_cert::attr::Attributes;
use x509_cert::ext::pkix::ExtendedKeyUsage;
use x509_cert::time::Time;

/// The object identifier for [`CertificateTrustList`].
pub const MS_CERT_TRUST_LIST_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.10.1");

/// Possible errors while parsing a certificate trust list.
#[derive(Debug, Error)]
pub enum CtlError {
    /// I/O errors.
    #[error("I/O error")]
    Io(#[from] std::io::Error),

    /// Invalid DER.
    #[error("bad DER encoding")]
    Der(#[from] der::Error),

    /// Valid PKCS#7, but the wrong `content-type`.
    #[error("bad PKCS#7 content-type: expected SignedData, got {0:?}")]
    ContentType(ContentType),

    /// Valid PKCS#7, but no encapsulated `signed-data`.
    #[error("missing SignedData encapsulated content")]
    MissingSignedData,

    /// Valid PKCS#7 with `signed-data`, but not a `CertificateTrustList`.
    #[error("bad SignedData ContentType: expected {MS_CERT_TRUST_LIST_OID}, got {0}")]
    Content(ObjectIdentifier),

    /// Valid PKCS#7 that claims to have a `CertificateTrustList`, but not present.
    #[error("missing SignedData inner content")]
    MissingSignedDataContent,
}

/// ```asn1
/// SubjectIdentifier ::= OCTETSTRING
/// ```
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
    /// Any X.509 attributes attached to this [`TrustedSubject`].
    pub attributes: Option<Attributes>,
}

impl TrustedSubject {
    /// Returns the certificate's ID, as a hex-encoded string.
    pub fn cert_id(&self) -> String {
        hex::encode(self.identifier.as_bytes())
    }
}

/// Version identifier for CertificateTrustList.
///
/// ```asn1
/// CTLVersion ::= INTEGER {v1(0)}
/// ```
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

/// NOTE: MS calls X.509's [`ExtendedKeyUsage`] "`EnhancedKeyUsage`".
///
/// ```asn1
/// SubjectUsage ::= EnhancedKeyUsage
/// ```
pub type SubjectUsage = ExtendedKeyUsage;

/// ```asn1
/// ListIdentifier ::= OCTETSTRING
/// ```
pub type ListIdentifier = OctetString;

/// ```asn1
/// TrustedSubjects ::= SEQUENCE OF TrustedSubject
/// ```
pub type TrustedSubjects = Vec<TrustedSubject>;

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
/// [MS-CAESO]: https://yossarian.net/junk/hard_to_find/ms-caeso-v20090709.pdf
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct CertificateTrustList {
    /// This trust list's version. The default version is 1.
    #[asn1(default = "Default::default")]
    pub version: CtlVersion,

    /// X.509-style usage.
    pub subject_usage: SubjectUsage,

    /// See [MS-CAESO](https://yossarian.net/junk/hard_to_find/ms-caeso-v20090709.pdf) page 48.
    pub list_identifier: Option<ListIdentifier>,

    // TODO: Better type here? UintRef<'_> doesn't fit, since it's borrowed
    // in an owning struct.
    /// Some kind of sequence number; purpose unknown.
    pub sequence_number: Option<Any>,

    // NOTE: MS doesn't bother to document `ChoiceOfTime`, but experimentally
    // it's the same thing as an X.509 `Time` (See <https://www.rfc-editor.org/rfc/rfc5280#section-4.1>)
    /// X.509-style time for when this CTL was produced/released.
    pub this_update: Time,

    /// X.509-style time for when the next CTL will be produced/released.
    pub next_update: Option<Time>,

    /// Presumably the digest algorithm used to compute each [`TrustedSubjects`]'s identifier.
    pub subject_algorithm: AlgorithmIdentifier<Any>,

    /// The list of trusted subjects in this CTL.
    pub trusted_subjects: Option<TrustedSubjects>,

    // TODO: Similar to `sequence_number`: this should really be `x509_cert::ext::Extensions`
    // but that's a borrowed type and this struct is owning.
    /// Any X.509 style extensions.
    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    pub ctl_extensions: Option<Any>,
}

impl CertificateTrustList {
    /// Load a `CertificateTrustList` from the given source, which is expected to be a
    /// [Cabinet Format](https://learn.microsoft.com/en-us/windows/win32/msi/cabinet-files)
    /// encoded stream.
    #[cfg(feature = "cab")]
    pub fn from_cab<R: Read + Seek>(source: R) -> Result<Self, CtlError> {
        let mut cabinet = cab::Cabinet::new(source)?;

        // We expect the actual STL to be at "authroot.stl" inside an STL
        // cabinet file, and nowhere else.
        Self::from_der(cabinet.read_file("authroot.stl")?)
    }

    /// Load a `CertificateTrustList` from the given source, which is expected to be a DER-encoded
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
