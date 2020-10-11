pub use openssl::x509::*;

use foreign_types::{ForeignType, ForeignTypeRef};
use libc::{c_int};
use std::mem;

use openssl::asn1::{Asn1IntegerRef, Asn1TimeRef};
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::pkey::{HasPrivate, HasPublic, PKeyRef};
use openssl::stack::{StackRef, Stackable};

use crate::hash::DigestBytes;
use crate::{cvt, cvt_n, cvt_p};

foreign_type_and_impl_send_sync! {
    type CType = ffi::X509_REVOKED;
    fn drop = ffi::X509_REVOKED_free;

    /// An X509 certificate revocation.
    pub struct X509Revoked;
    /// Reference to `X509Revoked`
    pub struct X509RevokedRef;
}

impl Stackable for X509Revoked {
    type StackType = ffi::stack_st_X509_REVOKED;
}

impl X509Revoked {
    /// Create new (empty) revocation
    pub fn new_empty() -> Result<Self, ErrorStack> {
        unsafe {
            ffi::init();
            crate::cvt_p(ffi::X509_REVOKED_new()).map(Self)
        }
    }

    from_der! {
        /// Deserializes a DER-encoded X509 certificate revocation.
        ///
        /// This corresponds to [`d2i_X509_REVOKED`].
        ///
        /// [`d2i_X509_REVOKED`]: https://www.openssl.org/docs/man1.1.0/man3/d2i_X509_REVOKED.html
        from_der,
        X509Revoked,
        ffi::d2i_X509_REVOKED
    }
}

impl X509RevokedRef {
    /// Get serial number of revoked certificate
    pub fn serial_number(&self) -> &Asn1IntegerRef {
        unsafe { Asn1IntegerRef::from_ptr(X509_REVOKED_get0_serialNumber(self.as_ptr()) as *mut _) }
    }

    /// Set serial number of revoked certificate
    pub fn set_serial_number(&mut self, serial: &Asn1IntegerRef) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::X509_REVOKED_set_serialNumber(
                self.as_ptr(),
                serial.as_ptr(),
            ))?;
        }
        Ok(())
    }

    /// Get when certificate was revoked
    pub fn revocation_date(&self) -> &Asn1TimeRef {
        unsafe { Asn1TimeRef::from_ptr(X509_REVOKED_get0_revocationDate(self.as_ptr()) as *mut _) }
    }

    /// Set when certificate was revoked
    pub fn set_revocation_date(&mut self, tm: &Asn1TimeRef) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::X509_REVOKED_set_revocationDate(
                self.as_ptr(),
                tm.as_ptr(),
            ))?;
        }
        Ok(())
    }

    /// Get extensions for revocation
    pub fn extensions(&self) -> &StackRef<X509Extension> {
        unsafe { StackRef::from_ptr(X509_REVOKED_get0_extensions(self.as_ptr()) as *mut _) }
    }

    to_der! {
        /// Serializes the revocation into a DER-encoded X509 revocation structure.
        ///
        /// This corresponds to [`i2d_X509_REVOKED`].
        ///
        /// [`i2d_X509_REVOKED`]: https://www.openssl.org/docs/man1.1.0/crypto/i2d_X509_REVOKED.html
        to_der,
        ffi::i2d_X509_REVOKED
    }
}

cfg_if! {
    if #[cfg(any(ossl110, libressl270))] {
        use ffi::{
            X509_REVOKED_get0_serialNumber,
            X509_REVOKED_get0_revocationDate,
            X509_REVOKED_get0_extensions,
        };
    } else {
        #[allow(bad_style)]
        unsafe fn X509_REVOKED_get0_serialNumber(r: *const ffi::X509_REVOKED) -> *const ffi::ASN1_INTEGER {
            (*r).serialNumber
        }
        #[allow(bad_style)]
        unsafe fn X509_REVOKED_get0_revocationDate(r: *const ffi::X509_REVOKED) -> *const ffi::ASN1_TIME {
            (*r).revocationDate
        }
        #[allow(bad_style)]
        unsafe fn X509_REVOKED_get0_extensions(r: *const ffi::X509_REVOKED) -> *const ffi::stack_st_X509_EXTENSION {
            (*r).extensions
        }
    }
}

/// The status of a serial / certificate in a revoction list
///
/// Corresponds to the return value from the [`X509_CRL_get0_by_*`] methods.
///
/// [`X509_CRL_get0_by_*`]: https://www.openssl.org/docs/man1.1.0/man3/X509_CRL_get0_by_serial.html
pub enum X509CrlRevocation<'a> {
    /// The serial / certificate is not present in the list
    NotRevoked,
    /// The serial / certificate is in the list and is revoked
    Revoked(&'a X509RevokedRef),
    /// The serial / certificate is in the list, but has the "removeFromCrl" reason code
    ///
    /// This must only occur in a delta CRL and means an entry should be removed.
    ///
    /// See [RFC 5280 5.3.1. Reason Code] for when this can happen.
    ///
    /// [RFC 5280 5.3.1. Reason Code]: https://tools.ietf.org/html/rfc5280#section-5.3.1
    RemoveFromCrl(&'a X509RevokedRef),
}

impl X509CrlRevocation<'_> {
    unsafe fn _from_result(ptr: *mut ffi::X509_REVOKED, code: c_int) -> Result<Self, ErrorStack> {
        match code {
            0 => Ok(Self::NotRevoked),
            1 => {
                assert!(!ptr.is_null());
                Ok(Self::Revoked(X509RevokedRef::from_ptr(ptr)))
            }
            2 => {
                assert!(!ptr.is_null());
                Ok(Self::RemoveFromCrl(X509RevokedRef::from_ptr(ptr)))
            }
            _ => Err(ErrorStack::get()),
        }
    }
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::X509_CRL;
    fn drop = ffi::X509_CRL_free;

    /// An X509 certificate revocation list.
    pub struct X509Crl;
    /// Reference to `X509Crl`
    pub struct X509CrlRef;
}

impl Stackable for X509Crl {
    type StackType = ffi::stack_st_X509_CRL;
}

impl X509Crl {
    /// Returns a new builder.
    pub fn builder() -> Result<X509CrlBuilder, ErrorStack> {
        X509CrlBuilder::new()
    }

    from_pem! {
        /// Deserializes a PEM-encoded X509 certificate revocation list structure.
        ///
        /// The input should have a header of `-----BEGIN X509 CRL-----`.
        ///
        /// This corresponds to [`PEM_read_bio_X509_CRL`].
        ///
        /// [`PEM_read_bio_X509_CRL`]: https://www.openssl.org/docs/man1.0.2/crypto/PEM_read_bio_X509_CRL.html
        from_pem,
        X509Crl,
        ffi::PEM_read_bio_X509_CRL
    }

    from_der! {
        /// Deserializes a DER-encoded X509 certificate revocation list structure.
        ///
        /// This corresponds to [`d2i_X509_CRL`].
        ///
        /// [`d2i_X509_CRL`]: https://www.openssl.org/docs/man1.0.2/man3/d2i_X509_CRL.html
        from_der,
        X509Crl,
        ffi::d2i_X509_CRL
    }
}

impl X509CrlRef {
    /// Returns a digest of the DER representation of the certificate revocation list.
    ///
    /// This corresponds to [`X509_CRL_digest`].
    ///
    /// [`X509_CRL_digest`]: https://www.openssl.org/docs/man1.1.0/man3/X509_CRL_digest.html
    pub fn digest(&self, hash_type: MessageDigest) -> Result<DigestBytes, ErrorStack> {
        unsafe {
            let mut digest = DigestBytes {
                buf: [0; ffi::EVP_MAX_MD_SIZE as usize],
                len: ffi::EVP_MAX_MD_SIZE as usize,
            };
            let mut len = ffi::EVP_MAX_MD_SIZE;
            cvt(ffi::X509_CRL_digest(
                self.as_ptr(),
                hash_type.as_ptr(),
                digest.buf.as_mut_ptr() as *mut _,
                &mut len,
            ))?;
            digest.len = len as usize;

            Ok(digest)
        }
    }

    /// Check if the certificate revocation list is signed using the given public key.
    ///
    /// Only the signature is checked.
    ///
    /// Returns `true` if verification succeeds.
    ///
    /// This corresponds to [`X509_CRL_verify"].
    ///
    /// [`X509_CRL_verify`]: https://www.openssl.org/docs/man1.1.0/crypto/X509_CRL_verify.html
    pub fn verify<T>(&self, key: &PKeyRef<T>) -> Result<bool, ErrorStack>
    where
        T: HasPublic,
    {
        unsafe { cvt_n(ffi::X509_CRL_verify(self.as_ptr(), key.as_ptr())).map(|n| n != 0) }
    }

    /// Get revocation entry for a certificate
    ///
    /// This corresponds to [`X509_CRL_get0_by_cert"].
    ///
    /// [`X509_CRL_get0_by_cert`]: https://www.openssl.org/docs/man1.1.0/crypto/X509_CRL_get0_by_cert.html
    pub fn get_revocation_by_certificate<'a>(
        &'a self,
        cert: &X509Ref,
    ) -> Result<X509CrlRevocation<'a>, ErrorStack> {
        unsafe {
            let mut ptr: *mut ffi::X509_REVOKED = std::ptr::null_mut();
            let code = ffi::X509_CRL_get0_by_cert(self.as_ptr(), &mut ptr, cert.as_ptr());
            X509CrlRevocation::_from_result(ptr, code)
        }
    }

    /// Get revocation entry for a certificate
    ///
    /// This corresponds to [`X509_CRL_get0_by_serial"].
    ///
    /// [`X509_CRL_get0_by_serial`]: https://www.openssl.org/docs/man1.1.0/crypto/X509_CRL_get0_by_serial.html
    pub fn get_revocation_by_serial<'a>(
        &'a self,
        serial: &Asn1IntegerRef,
    ) -> Result<X509CrlRevocation<'a>, ErrorStack> {
        unsafe {
            let mut ptr: *mut ffi::X509_REVOKED = std::ptr::null_mut();
            let code = ffi::X509_CRL_get0_by_serial(self.as_ptr(), &mut ptr, serial.as_ptr());
            X509CrlRevocation::_from_result(ptr, code)
        }
    }

    /// Get revocation entries
    ///
    /// This corresponds to [`X509_CRL_get_REVOKED"].
    ///
    /// [`X509_CRL_get_REVOKED`]: https://www.openssl.org/docs/man1.1.0/crypto/X509_CRL_get_REVOKED.html
    pub fn revoked(&self) -> Option<&StackRef<X509Revoked>> {
        unsafe {
            let revoked = X509_CRL_get_REVOKED(self.as_ptr());
            if revoked.is_null() {
                None
            } else {
                Some(StackRef::from_ptr(revoked))
            }
        }
    }

    /// Get the time the next update is required (i.e. "valid until")
    ///
    /// This corresponds to [`X509_CRL_get0_nextUpdate"].
    ///
    /// [`X509_CRL_get0_nextUpdate`]: https://www.openssl.org/docs/man1.1.0/crypto/X509_CRL_get0_nextUpdate.html
    pub fn next_update(&self) -> Option<&Asn1TimeRef> {
        unsafe {
            let next_update = X509_CRL_get0_nextUpdate(self.as_ptr());
            if next_update.is_null() {
                None
            } else {
                Some(Asn1TimeRef::from_ptr(next_update as *mut _))
            }
        }
    }

    /// Get the time the CRL was signed.
    ///
    /// This corresponds to [`X509_CRL_get0_lastUpdate"].
    ///
    /// [`X509_CRL_get0_lastUpdate`]: https://www.openssl.org/docs/man1.1.0/crypto/X509_CRL_get0_lastUpdate.html
    pub fn last_update(&self) -> &Asn1TimeRef {
        unsafe {
            let last_update = X509_CRL_get0_lastUpdate(self.as_ptr());
            assert!(
                !last_update.is_null(),
                "last_update is null (but is a required field)"
            );
            Asn1TimeRef::from_ptr(last_update as *mut _)
        }
    }

    /// Get the issuer name
    ///
    /// Identifies the certificate used to sign the CRL.
    ///
    /// This corresponds to [`X509_CRL_get_issuer"].
    ///
    /// [`X509_CRL_get_issuer`]: https://www.openssl.org/docs/man1.1.0/crypto/X509_CRL_get_issuer.html
    pub fn issuer_name(&self) -> &X509NameRef {
        unsafe {
            let issuer = X509_CRL_get_issuer(self.as_ptr());
            assert!(
                !issuer.is_null(),
                "issuer is null (but is a required field)"
            );
            X509NameRef::from_ptr(issuer)
        }
    }

    to_pem! {
        /// Serializes the certificate revocation list into a PEM-encoded X509 CRL structure.
        ///
        /// The output will have a header of `-----BEGIN X509 CRL-----`.
        ///
        /// This corresponds to [`PEM_write_bio_X509`].
        ///
        /// [`PEM_write_bio_X509`]: https://www.openssl.org/docs/man1.0.2/crypto/PEM_write_bio_X509.html
        to_pem,
        ffi::PEM_write_bio_X509_CRL
    }

    to_der! {
        /// Serializes the certificate revocation list into a DER-encoded X509 CRL structure.
        ///
        /// This corresponds to [`i2d_X509_CRL`].
        ///
        /// [`i2d_X509_CRL`]: https://www.openssl.org/docs/man1.0.2/crypto/i2d_X509_CRL.html
        to_der,
        ffi::i2d_X509_CRL
    }
}

cfg_if! {
    if #[cfg(any(ossl110, libressl281))] {
        use ffi::{
            X509_CRL_get_REVOKED,
            X509_CRL_get0_nextUpdate,
            X509_CRL_get0_lastUpdate,
            X509_CRL_get_issuer,
        };
    } else {
        #[allow(bad_style)]
        unsafe fn X509_CRL_get_REVOKED(crl: *mut ffi::X509_CRL) -> *mut ffi::stack_st_X509_REVOKED {
            (*crl).revoked
        }
        #[allow(bad_style)]
        unsafe fn X509_CRL_get0_nextUpdate(crl: *const ffi::X509_CRL) -> *const ffi::ASN1_TIME {
            (*crl).nextUpdate
        }
        #[allow(bad_style)]
        unsafe fn X509_CRL_get0_lastUpdate(crl: *const ffi::X509_CRL) -> *const ffi::ASN1_TIME {
            (*crl).lastUpdate
        }
        #[allow(bad_style)]
        unsafe fn X509_CRL_get_issuer(crl: *const ffi::X509_CRL) -> *mut ffi::X509_NAME {
            (*crl).issuer
        }
    }
}

pub struct X509CrlBuilder(pub(crate) X509Crl);

impl X509CrlBuilder {
    pub fn new() -> Result<Self, ErrorStack> {
        unsafe {
            ffi::init();
            cvt_p(ffi::X509_CRL_new()).map(X509Crl).map(X509CrlBuilder)
        }
    }

    /// Signs the CRL with a private key.
    pub fn sign<T>(&mut self, key: &PKeyRef<T>, hash: MessageDigest) -> Result<(), ErrorStack>
    where
        T: HasPrivate,
    {
        unsafe {
            cvt(ffi::X509_CRL_sign(
                self.0.as_ptr(),
                key.as_ptr(),
                hash.as_ptr(),
            ))
            .map(|_| ())
        }
    }

    /// Consumes the builder, returning the CRL.
    pub fn build(self) -> X509Crl {
        self.0
    }

    /// Sets the version of the CRL.
    ///
    /// Note that the version is zero-indexed; that is, a CRL corresponding to version 2 of
    /// the X.509 standard should pass `1` to this method.
    ///
    /// This corresponds to [`X509_CRL_set_version"].
    ///
    /// [`X509_CRL_set_version`]: https://www.openssl.org/docs/man1.1.0/crypto/X509_CRL_set_version.html
    pub fn set_version(&mut self, version: i32) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::X509_CRL_set_version(self.0.as_ptr(), version.into())).map(|_| ()) }
    }

    /// Sets the issuer name of the certificate.
    ///
    /// This corresponds to [`X509_CRL_set_issuer_name"].
    ///
    /// [`X509_CRL_set_issuer_name`]: https://www.openssl.org/docs/man1.1.0/crypto/X509_CRL_set_issuer_name.html
    pub fn set_issuer_name(&mut self, issuer_name: &X509NameRef) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::X509_CRL_set_issuer_name(
                self.0.as_ptr(),
                issuer_name.as_ptr(),
            ))
            .map(|_| ())
        }
    }

    /// Sort the revoked entries into ascending serial number order
    ///
    /// This corresponds to [`X509_CRL_sort"].
    ///
    /// [`X509_CRL_sort`]: https://www.openssl.org/docs/man1.1.0/crypto/X509_CRL_sort.html
    pub fn sort(&mut self) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::X509_CRL_sort(self.0.as_ptr())).map(|_| ()) }
    }

    /// Add revocation entry to list.
    ///
    /// This corresponds to [`X509_CRL_add0_revoked"].
    ///
    /// [`X509_CRL_add0_revoked`]: https://www.openssl.org/docs/man1.1.0/crypto/X509_CRL_add0_revoked.html
    pub fn add_revoked(&mut self, rev: X509Revoked) -> Result<(), ErrorStack> {
        // on success the revoked entry is owned by the CRL
        let rev = mem::ManuallyDrop::new(rev);
        let result = unsafe { cvt(ffi::X509_CRL_add0_revoked(self.0.as_ptr(), rev.as_ptr())) };
        match result {
            Err(e) => {
                // failed to add; drop entry here (sadly not documented)
                mem::ManuallyDrop::into_inner(rev);
                Err(e)
            }
            Ok(_) => Ok(()),
        }
    }

    /// Set time of signing
    ///
    /// This corresponds to [`X509_CRL_set1_lastUpdate"].
    ///
    /// [`X509_CRL_set1_lastUpdate`]: https://www.openssl.org/docs/man1.1.0/crypto/X509_CRL_set1_lastUpdate.html
    pub fn set_last_update(&mut self, tm: &Asn1TimeRef) -> Result<(), ErrorStack> {
        unsafe { cvt(X509_CRL_set1_lastUpdate(self.0.as_ptr(), tm.as_ptr())).map(|_| ()) }
    }

    /// Set time next update must be available (i.e. "valid until")
    ///
    /// This corresponds to [`X509_CRL_set1_nextUpdate"].
    ///
    /// [`X509_CRL_set1_nextUpdate`]: https://www.openssl.org/docs/man1.1.0/crypto/X509_CRL_set1_nextUpdate.html
    pub fn set_next_update(&mut self, tm: &Asn1TimeRef) -> Result<(), ErrorStack> {
        unsafe { cvt(X509_CRL_set1_nextUpdate(self.0.as_ptr(), tm.as_ptr())).map(|_| ()) }
    }

    /// Get (mutable) revocation entries
    ///
    /// This corresponds to [`X509_CRL_get_REVOKED"].
    ///
    /// [`X509_CRL_get_REVOKED`]: https://www.openssl.org/docs/man1.1.0/crypto/X509_CRL_get_REVOKED.html
    pub fn revoked(&mut self) -> Option<&mut StackRef<X509Revoked>> {
        unsafe {
            let revoked = X509_CRL_get_REVOKED(self.0.as_ptr());
            if revoked.is_null() {
                None
            } else {
                Some(StackRef::from_ptr_mut(revoked))
            }
        }
    }

    /// Get the time the next update is required (i.e. "valid until")
    ///
    /// This corresponds to [`X509_CRL_get0_nextUpdate"].
    ///
    /// [`X509_CRL_get0_nextUpdate`]: https://www.openssl.org/docs/man1.1.0/crypto/X509_CRL_get0_nextUpdate.html
    pub fn next_update(&self) -> Option<&Asn1TimeRef> {
        self.0.next_update()
    }

    /// Get the time the CRL was signed.
    ///
    /// This corresponds to [`X509_CRL_get0_lastUpdate"].
    ///
    /// [`X509_CRL_get0_lastUpdate`]: https://www.openssl.org/docs/man1.1.0/crypto/X509_CRL_get0_lastUpdate.html
    pub fn last_update(&self) -> &Asn1TimeRef {
        self.0.last_update()
    }

    /// Get the issuer name
    ///
    /// Identifies the certificate used to sign the CRL.
    ///
    /// This corresponds to [`X509_CRL_get_issuer"].
    ///
    /// [`X509_CRL_get_issuer`]: https://www.openssl.org/docs/man1.1.0/crypto/X509_CRL_get_issuer.html
    pub fn issuer_name(&self) -> &X509NameRef {
        self.0.issuer_name()
    }
}

cfg_if! {
    if #[cfg(any(ossl110, libressl270))] {
        use ffi::{
            X509_CRL_set1_lastUpdate,
            X509_CRL_set1_nextUpdate,
        };
    } else {
        use ffi::{
            X509_CRL_set_lastUpdate as X509_CRL_set1_lastUpdate,
            X509_CRL_set_nextUpdate as X509_CRL_set1_nextUpdate,
        };
    }
}
