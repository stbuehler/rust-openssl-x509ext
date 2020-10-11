pub extern crate openssl;
pub extern crate openssl_sys as ffi;

#[macro_use]
extern crate cfg_if;

#[macro_use]
extern crate foreign_types;

#[macro_use]
mod macros;

mod bio;
pub mod asn1;
pub mod hash;
pub mod x509;
pub mod x509ext;

fn cvt_p<T>(r: *mut T) -> Result<*mut T, openssl::error::ErrorStack> {
    if r.is_null() {
        Err(openssl::error::ErrorStack::get())
    } else {
        Ok(r)
    }
}

fn cvt(r: libc::c_int) -> Result<libc::c_int, openssl::error::ErrorStack> {
    if r <= 0 {
        Err(openssl::error::ErrorStack::get())
    } else {
        Ok(r)
    }
}

fn cvt_n(r: libc::c_int) -> Result<libc::c_int, openssl::error::ErrorStack> {
    if r < 0 {
        Err(openssl::error::ErrorStack::get())
    } else {
        Ok(r)
    }
}
