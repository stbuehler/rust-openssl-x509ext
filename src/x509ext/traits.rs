use libc::{c_int, c_ulong, c_void};
use std::marker::PhantomData;
use std::ptr;

use openssl::asn1::Asn1ObjectRef;
use openssl::error::ErrorStack;
use foreign_types::{ForeignType, ForeignTypeRef};
use openssl::nid::Nid;
use crate::x509::X509ExtensionRef;

use super::sealed;

/// Bind NID to foreign type used by openssl to represent extension data
///
/// Implemented on marker types for use in `ExtensionAccess`.
pub unsafe trait ExtensionMark: Send + 'static {
    /// Type used by openssl to represent extension data
    type Data: ForeignType;
    /// NID used for the extension
    const NID: Nid;
}

pub trait RawExtensionAccess: sealed::ExtensionAccess {
    /// Corresponds to *_get_ext_count
    fn raw_get_ext_count(&self) -> c_int;
    /// Corresponds to *_get_ext_by_NID
    fn raw_get_ext_by_nid(&self, nid: c_int, lastpos: c_int) -> c_int;
    /// Corresponds to *_get_ext_by_OBJ
    unsafe fn raw_get_ext_by_obj(&self, obj: *const ffi::ASN1_OBJECT, lastpos: c_int) -> c_int;
    /// Corresponds to *_get_ext_by_critical
    fn raw_get_ext_by_critical(&self, crit: c_int, lastpos: c_int) -> c_int;
    /// Corresponds to *_get_ext (returns just a reference to the extension)
    fn raw_get_ext(&self, loc: c_int) -> *mut ffi::X509_EXTENSION;
    /// Corresponds to *_get_ext_d2i
    unsafe fn raw_get_ext_d2i(&self, nid: c_int, crit: *mut c_int, idx: *mut c_int) -> *mut c_void;
}
// e.g. `X509` wrapper assumes immutable data (even with `&mut X509`), so we need to split this.
pub trait RawExtensionModify: RawExtensionAccess {
    /// Corresponds to *_delete_ext (returns deleted extension ownership)
    fn raw_delete_ext(&mut self, loc: c_int) -> *mut ffi::X509_EXTENSION;
    /// Corresponds to *_add_ext (takes extension by reference; gets duplicated internally)
    unsafe fn raw_add_ext(&mut self, ex: *mut ffi::X509_EXTENSION, loc: c_int) -> bool;
    /// Corresponds to *_add1_i2d (value gets "duplicated" internally using `X509V3_EXT_i2d` to create the actual extension)
    unsafe fn raw_add1_i2d(
        &mut self,
        nid: c_int,
        value: *mut c_void,
        crit: c_int,
        flags: c_ulong,
    ) -> c_int;
}

fn lastpos_to_raw(index: Option<usize>) -> Option<c_int> {
    match index {
        None => Some(-1),
        Some(index) => {
            if index >= c_int::MAX as usize {
                // prevent overflow in openssl "lastpos++"
                None
            } else {
                Some(index as c_int)
            }
        }
    }
}

/// Trait implemented by types which contain an X509 extension stack and have
/// direct accessor methods (see [`X509V3_get_d2i`]).
///
/// Types providing access to an extension stack might need to parse / create it
/// first; this step should be cached, and therefor no shortcut should be
/// provided here.
///
/// [`X509V3_get_d2i`]: https://www.openssl.org/docs/man1.1.0/crypto/X509V3_get_d2i.html
pub trait ExtensionAccess: RawExtensionAccess {
    /// Number of extensions
    fn extension_count(&self) -> usize {
        let count = self.raw_get_ext_count();
        // make sure we don't cast negative numbers to usize
        std::cmp::max(0, count) as usize
    }

    /// Find index of next extension with given `nid` as type after `lastpos`
    ///
    /// Use `lastpos = None` to find first extension
    fn locate_extension_by_nid(&self, nid: Nid, lastpos: Option<usize>) -> Option<usize> {
        let lastpos = lastpos_to_raw(lastpos)?;
        let pos = self.raw_get_ext_by_nid(nid.as_raw(), lastpos);
        if pos < 0 {
            // Nid to ASN1_OBJECT might fail with error (might return -2 for that).
            // But might not always have an error stack:
            //   https://github.com/openssl/openssl/issues/13008
            // simply ignore error, but clear stack.
            let _err = ErrorStack::get();
            None
        } else {
            Some(pos as usize)
        }
    }

    /// Find index of next extension with given `obj` as type after `lastpos`
    ///
    /// Use `lastpos = None` to find first extension
    fn locate_extension_by_obj(
        &self,
        obj: &Asn1ObjectRef,
        lastpos: Option<usize>,
    ) -> Option<usize> {
        let lastpos = lastpos_to_raw(lastpos)?;
        let pos = unsafe { self.raw_get_ext_by_obj(obj.as_ptr(), lastpos) };
        if pos < 0 {
            None
        } else {
            Some(pos as usize)
        }
    }

    /// Find index of next extension with given `crit` status after `lastpos`
    ///
    /// Use `lastpos = None` to find first extension
    fn locate_extension_by_critical(&self, crit: bool, lastpos: Option<usize>) -> Option<usize> {
        let lastpos = lastpos_to_raw(lastpos)?;
        let crit: c_int = if crit { 1 } else { 0 };
        let pos = self.raw_get_ext_by_critical(crit, lastpos);
        if pos < 0 {
            None
        } else {
            Some(pos as usize)
        }
    }

    /// Get extension at given index
    fn get_extension(&self, index: usize) -> Option<&X509ExtensionRef> {
        if index > c_int::MAX as usize {
            return None;
        }
        let ptr = self.raw_get_ext(index as c_int);
        if ptr.is_null() {
            None
        } else {
            Some(unsafe { X509ExtensionRef::from_ptr(ptr) })
        }
    }

    /// Iterate over all extensions
    fn iter_extensions(&self) -> ExtensionsIterator<'_, Self> {
        ExtensionsIterator {
            exts: self,
            current: 0,
            len: self.extension_count(),
        }
    }

    /// Iterate over all extensions of given `nid` type
    fn iter_extensions_by_nid(&self, nid: Nid) -> ExtensionsIteratorByNid<'_, Self> {
        ExtensionsIteratorByNid {
            exts: self,
            nid,
            lastpos: None,
        }
    }

    /// Iterate over all extensions of given `obj` type
    fn iter_extensions_by_obj<'a>(
        &'a self,
        obj: &'a Asn1ObjectRef,
    ) -> ExtensionsIteratorByObj<'a, Self> {
        ExtensionsIteratorByObj {
            exts: self,
            obj,
            lastpos: None,
        }
    }

    /// Iterate over all extensions with given `critical` flag
    fn iter_extensions_by_critical(&self, crit: bool) -> ExtensionsIteratorByCritical<'_, Self> {
        ExtensionsIteratorByCritical {
            exts: self,
            crit,
            lastpos: None,
        }
    }

    /// Iterate over data of extensions of given type
    fn iterate_extensions_data<E: ExtensionMark>(&self) -> ExtensionsDataIterator<'_, Self, E> {
        ExtensionsDataIterator {
            exts: self,
            _mark: PhantomData,
            previous: -1,
        }
    }

    /// Decode extension data
    ///
    /// Use `previous = Some(&mut -1)` to find the first of multiple instances; `None` only finds single instances.
    fn find_extension_data<E: ExtensionMark>(
        &self,
        previous: Option<&mut c_int>,
    ) -> Result<Option<(E::Data, bool)>, ErrorStack> {
        Ok(self
            ._find_extension_data_raw(E::NID, previous)?
            .map(|(ptr, crit)| (unsafe { E::Data::from_ptr(ptr as *mut _) }, crit)))
    }

    #[doc(hidden)]
    fn _find_extension_data_raw(
        &self,
        nid: Nid,
        previous: Option<&mut c_int>,
    ) -> Result<Option<(*mut c_void, bool)>, ErrorStack> {
        let mut crit: c_int = -1;
        let result = unsafe {
            self.raw_get_ext_d2i(
                nid.as_raw(),
                &mut crit,
                previous.map_or(ptr::null_mut(), |prev| prev as *mut _),
            )
        };
        if result.is_null() {
            let err = ErrorStack::get();
            if err.errors().is_empty() {
                return Ok(None);
            } else {
                return Err(err);
            }
        }
        Ok(Some((result, crit == 1)))
    }
}

impl<T: RawExtensionAccess> ExtensionAccess for T {}

/// Iterator to iterate over all extensions
pub struct ExtensionsIterator<'a, EA: ?Sized + ExtensionAccess + 'a> {
    exts: &'a EA,
    current: usize,
    len: usize,
}

impl<'a, EA: ExtensionAccess + 'a> Iterator for ExtensionsIterator<'a, EA> {
    type Item = &'a X509ExtensionRef;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current >= self.len {
            return None;
        }
        let item = self.exts.get_extension(self.current);
        assert!(
            item.is_some(),
            "no extension found at index {} (within range)",
            self.current
        );
        self.current += 1;
        item
    }
}

impl<'a, EA: ExtensionAccess + 'a> std::iter::FusedIterator for ExtensionsIterator<'a, EA> {}

impl<'a, EA: ExtensionAccess + 'a> DoubleEndedIterator for ExtensionsIterator<'a, EA> {
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.current >= self.len {
            return None;
        }
        let item = self.exts.get_extension(self.len - 1);
        assert!(
            item.is_some(),
            "no extension found at index {} (within range)",
            self.current
        );
        self.len -= 1;
        item
    }
}

/// Iterator to iterate over all extensions with specific `Nid` type.
pub struct ExtensionsIteratorByNid<'a, EA: ?Sized + ExtensionAccess + 'a> {
    exts: &'a EA,
    nid: Nid,
    lastpos: Option<usize>,
}

impl<'a, EA: ExtensionAccess + 'a> Iterator for ExtensionsIteratorByNid<'a, EA> {
    type Item = &'a X509ExtensionRef;

    fn next(&mut self) -> Option<Self::Item> {
        let pos = self.exts.locate_extension_by_nid(self.nid, self.lastpos)?;
        let item = self.exts.get_extension(pos);
        assert!(item.is_some());
        self.lastpos = Some(pos);
        item
    }
}

impl<'a, EA: ExtensionAccess + 'a> std::iter::FusedIterator for ExtensionsIteratorByNid<'a, EA> {}

/// Iterator to iterate over all extensions with specific `obj` type.
pub struct ExtensionsIteratorByObj<'a, EA: ?Sized + ExtensionAccess + 'a> {
    exts: &'a EA,
    obj: &'a Asn1ObjectRef,
    lastpos: Option<usize>,
}

impl<'a, EA: ExtensionAccess + 'a> Iterator for ExtensionsIteratorByObj<'a, EA> {
    type Item = &'a X509ExtensionRef;

    fn next(&mut self) -> Option<Self::Item> {
        let pos = self.exts.locate_extension_by_obj(self.obj, self.lastpos)?;
        let item = self.exts.get_extension(pos);
        assert!(item.is_some());
        self.lastpos = Some(pos);
        item
    }
}

impl<'a, EA: ExtensionAccess + 'a> std::iter::FusedIterator for ExtensionsIteratorByObj<'a, EA> {}

/// Iterator to iterate over all extensions with specific `critical` flag.
pub struct ExtensionsIteratorByCritical<'a, EA: ?Sized + ExtensionAccess + 'a> {
    exts: &'a EA,
    crit: bool,
    lastpos: Option<usize>,
}

impl<'a, EA: ExtensionAccess + 'a> Iterator for ExtensionsIteratorByCritical<'a, EA> {
    type Item = &'a X509ExtensionRef;

    fn next(&mut self) -> Option<Self::Item> {
        let pos = self
            .exts
            .locate_extension_by_critical(self.crit, self.lastpos)?;
        let item = self.exts.get_extension(pos);
        assert!(item.is_some());
        self.lastpos = Some(pos);
        item
    }
}

impl<'a, EA: ExtensionAccess + 'a> std::iter::FusedIterator
    for ExtensionsIteratorByCritical<'a, EA>
{
}

/// Iterator to decode all extensions of specific type.
pub struct ExtensionsDataIterator<'a, EA: ?Sized + ExtensionAccess + 'a, E: ExtensionMark> {
    exts: &'a EA,
    _mark: PhantomData<*const E>,
    previous: c_int,
}

impl<'a, EA: ExtensionAccess + 'a, E: ExtensionMark> Iterator
    for ExtensionsDataIterator<'a, EA, E>
{
    type Item = Result<(E::Data, bool), ErrorStack>;

    fn next(&mut self) -> Option<Self::Item> {
        self.exts
            .find_extension_data::<E>(Some(&mut self.previous))
            .transpose()
    }
}
