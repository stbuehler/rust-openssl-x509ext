pub use openssl::asn1::*;

// wrap `Asn1Object` so we can stack it
pub struct Asn1Object(pub openssl::asn1::Asn1Object);

impl foreign_types::ForeignType for Asn1Object {
    type CType = ffi::ASN1_OBJECT;

    type Ref = openssl::asn1::Asn1ObjectRef;

    unsafe fn from_ptr(ptr: *mut Self::CType) -> Self {
        Self(openssl::asn1::Asn1Object::from_ptr(ptr))
    }

    fn as_ptr(&self) -> *mut Self::CType {
        self.0.as_ptr()
    }
}

#[cfg(ossl110)]
#[allow(non_camel_case_types)]
pub enum stack_st_ASN1_OBJECT {}
#[cfg(not(ossl110))]
#[repr(C)]
#[allow(non_camel_case_types)]
pub struct stack_st_ASN1_OBJECT {
    pub stack: ffi::_STACK,
}

impl openssl::stack::Stackable for Asn1Object {
    type StackType = stack_st_ASN1_OBJECT;
}
