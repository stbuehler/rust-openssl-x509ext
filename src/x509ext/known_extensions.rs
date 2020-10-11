use openssl::nid::Nid;
use openssl::stack::Stack;

use crate::asn1::Asn1Object;
use crate::x509::GeneralName;

use super::ExtensionMark;

/// Marker type to decode `SubjectAltName`
pub struct ExtSubjectAltName;
unsafe impl ExtensionMark for ExtSubjectAltName {
    type Data = Stack<GeneralName>;
    const NID: Nid = Nid::SUBJECT_ALT_NAME;
}

/// Marker type to decode `IssuerAltName`
pub struct ExtIssuerAltName;
unsafe impl ExtensionMark for ExtIssuerAltName {
    type Data = Stack<GeneralName>;
    const NID: Nid = Nid::ISSUER_ALT_NAME;
}

/// Marker type to decode `ExtKeyUsage`
pub struct ExtExtKeyUsage;
unsafe impl ExtensionMark for ExtExtKeyUsage {
    // typedef STACK_OF(ASN1_OBJECT) EXTENDED_KEY_USAGE;
    type Data = Stack<Asn1Object>;
    const NID: Nid = Nid::EXT_KEY_USAGE;
}
