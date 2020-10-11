use std::fmt;
use std::ops::{Deref, DerefMut};

/// The resulting bytes of a digest.
///
/// This type derefs to a byte slice - it exists to avoid allocating memory to
/// store the digest data.
#[derive(Copy)]
pub struct DigestBytes {
    pub(crate) buf: [u8; ffi::EVP_MAX_MD_SIZE as usize],
    pub(crate) len: usize,
}

impl Clone for DigestBytes {
    #[inline]
    fn clone(&self) -> DigestBytes {
        *self
    }
}

impl Deref for DigestBytes {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

impl DerefMut for DigestBytes {
    #[inline]
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.buf[..self.len]
    }
}

impl AsRef<[u8]> for DigestBytes {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.deref()
    }
}

impl fmt::Debug for DigestBytes {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&**self, fmt)
    }
}
