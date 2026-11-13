// SPDX-License-Identifier: LGPL-2.1-or-later
//! Shared libraries loaded at run time.
//!
//! A program does not have to link against a library it can do without.
//! It can load the library with dlopen() the first time it needs it, and
//! go on without it when that fails. systemd loads most of its optional
//! dependencies this way (src/basic/dlfcn-util.c).
//!
//! [`Library`] is a library loaded with dlopen(). A type that implements
//! [`Symbols`] holds the functions a program calls from one library, and
//! [`symbols!`] declares such a type. [`Lazy`] keeps one in a `static` and
//! loads it on first use. A failure is an [`io::Error`] with what dlerror()
//! says.
//!
//! dlopen() is called with RTLD_NOW and RTLD_NODELETE, as systemd's
//! dlopen_safe() does: every symbol is resolved when the library is
//! loaded, and the library is never unloaded. So a function that was
//! looked up stays valid for as long as the process lives, also after its
//! [`Library`] was dropped. In a statically linked program,
//! [`Library::open`] fails without calling dlopen(), as dlopen_safe() does
//! in a static build of systemd: the library would bring a second C
//! library into the process.

#![deny(unsafe_code)]
#![warn(missing_docs)]

use std::ffi::{c_int, c_void, CStr};
use std::io;
use std::ptr::NonNull;
use std::sync::OnceLock;

/// How dlopen() loads a library: every symbol is resolved now, and the
/// library is never unloaded.
const FLAGS: c_int = libc::RTLD_NOW | libc::RTLD_NODELETE;

/// The error dlerror() holds for the calling thread, which reading it
/// clears. None when there is none.
#[allow(unsafe_code)]
fn dlerror() -> Option<io::Error> {
    // SAFETY: no arguments.
    let message = unsafe { libc::dlerror() };
    if message.is_null() {
        return None;
    }
    // SAFETY: dlerror() returned a NUL terminated string, which stays
    // valid until the next call of dlopen(), dlsym() or dlerror() in this
    // thread. It is copied before that.
    let message = unsafe { CStr::from_ptr(message) };
    Some(io::Error::other(message.to_string_lossy().into_owned()))
}

/// The type of a pointer to a C function, an `unsafe extern "C" fn` of up
/// to twelve arguments. [`Library::function`] looks up nothing else.
///
/// Nothing can check that such a pointer has the prototype of the function
/// it points to. Calling it is unsafe, and that is where the caller vouches
/// for the prototype.
pub trait Function: sealed::Sealed {}

mod sealed {
    use std::ffi::c_void;
    use std::ptr::NonNull;

    /// A [`super::Function`]. No other type can be made from an address.
    pub trait Sealed: Copy {
        /// The pointer to the function at `address`.
        fn from_address(address: NonNull<c_void>) -> Self;
    }
}

/// Implements [`Function`] for pointers to functions of these arguments.
macro_rules! function {
    ($($arg:ident),*) => {
        impl<R, $($arg),*> sealed::Sealed for unsafe extern "C" fn($($arg),*) -> R {
            #[allow(unsafe_code)]
            fn from_address(address: NonNull<c_void>) -> Self {
                // SAFETY: the address is not NULL, which is all a pointer to
                // a function has to be. Calling it is unsafe, and the caller
                // vouches there that it points to a function of this
                // prototype.
                unsafe { std::mem::transmute::<*mut c_void, Self>(address.as_ptr()) }
            }
        }

        impl<R, $($arg),*> Function for unsafe extern "C" fn($($arg),*) -> R {}
    };
}

/// [`function!`] for each number of arguments up to the length of the
/// list.
macro_rules! functions {
    () => {
        function!();
    };
    ($first:ident $(, $rest:ident)*) => {
        function!($first $(, $rest)*);
        functions!($($rest),*);
    };
}

functions!(A, B, C, D, E, F, G, H, I, J, K, L);

/// A shared library loaded with dlopen(). Dropping it calls dlclose(),
/// which leaves the library loaded.
#[derive(Debug)]
pub struct Library {
    handle: NonNull<c_void>,
}

impl Library {
    /// Loads the library `soname`. dlopen() finds it the way the dynamic
    /// linker finds the libraries a program links against, and runs the
    /// initializers of the library and of the libraries it needs.
    #[allow(unsafe_code)]
    pub fn open(soname: &CStr) -> io::Result<Library> {
        let name = soname.to_string_lossy();
        if cfg!(target_feature = "crt-static") {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("{}: a statically linked program cannot load it", name),
            ));
        }
        // SAFETY: a NUL terminated name. The initializers dlopen() runs set
        // up the state of their own library.
        let handle = unsafe { libc::dlopen(soname.as_ptr(), FLAGS) };
        match NonNull::new(handle) {
            Some(handle) => Ok(Library { handle }),
            None => Err(dlerror().unwrap_or_else(|| io::Error::other(format!("{}: cannot be loaded", name)))),
        }
    }

    /// Looks up the function `name` and returns the pointer to it as an
    /// `F`, the type of a pointer to a C function. For `int foo(int)` that
    /// is `unsafe extern "C" fn(c_int) -> c_int`.
    pub fn function<F: Function>(&self, name: &CStr) -> io::Result<F> {
        // dlsym() returns NULL for a symbol that is missing and for one
        // whose value is NULL. Only the first sets the error dlerror()
        // reports, so an earlier error is cleared before.
        dlerror();
        let address = self.address(name);
        if let Some(e) = dlerror() {
            return Err(e);
        }
        NonNull::new(address)
            .map(F::from_address)
            .ok_or_else(|| io::Error::other(format!("{}: the symbol is NULL", name.to_string_lossy())))
    }

    /// The address of the symbol `name`, as dlsym() gives it.
    #[allow(unsafe_code)]
    fn address(&self, name: &CStr) -> *mut c_void {
        // SAFETY: a handle dlopen() returned and a NUL terminated name.
        unsafe { libc::dlsym(self.handle.as_ptr(), name.as_ptr()) }
    }
}

impl Drop for Library {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: a handle dlopen() returned, closed once. RTLD_NODELETE
        // keeps the library loaded, so the functions looked up in it stay
        // valid.
        let r = unsafe { libc::dlclose(self.handle.as_ptr()) };
        debug_assert_eq!(r, 0, "dlclose() failed");
    }
}

/// The functions a program calls from one library, as a struct of
/// pointers to them. [`symbols!`] declares one.
pub trait Symbols: Sized {
    /// The names of the library, as [`Library::open`] takes them, in the
    /// order they are tried. Some libraries have several, such as
    /// libcrypt.so.2 and libcrypt.so.1.
    const SONAMES: &'static [&'static CStr];

    /// Looks the functions up in `library`.
    fn resolve(library: &Library) -> io::Result<Self>;

    /// Loads the first library of [`Symbols::SONAMES`] that loads and has
    /// all of the functions, and looks them up in it. When none does, the
    /// error says why for each.
    fn load() -> io::Result<Self> {
        let mut errors = Vec::new();
        for soname in Self::SONAMES {
            match Library::open(soname).and_then(|library| Self::resolve(&library)) {
                Ok(symbols) => return Ok(symbols),
                Err(e) => errors.push(e.to_string()),
            }
        }
        if errors.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "no library to load"));
        }
        Err(io::Error::other(errors.join("; ")))
    }
}

/// The functions of a library, kept in a `static` and loaded the first
/// time they are asked for. When that fails, the failure is kept, and the
/// library is not tried again. Threads that ask while the functions are
/// loaded wait for them.
pub struct Lazy<T> {
    cell: OnceLock<io::Result<T>>,
}

impl<T> Lazy<T> {
    /// Functions that are not loaded yet.
    pub const fn new() -> Lazy<T> {
        Lazy { cell: OnceLock::new() }
    }
}

impl<T> Default for Lazy<T> {
    fn default() -> Lazy<T> {
        Lazy::new()
    }
}

impl<T: Symbols> Lazy<T> {
    /// The functions, loaded on the first call of this or of
    /// [`Lazy::try_get`]. None when the library or one of the functions
    /// cannot be loaded.
    pub fn get(&self) -> Option<&T> {
        self.try_get().ok()
    }

    /// The functions, loaded on the first call of this or of
    /// [`Lazy::get`], or why they cannot be loaded.
    pub fn try_get(&self) -> Result<&T, &io::Error> {
        self.cell.get_or_init(T::load).as_ref()
    }
}

/// Declares a struct of the functions a program calls from one library,
/// and implements [`Symbols`] for it.
///
/// The names of the library follow `from`, separated by commas. The first
/// one that loads and has every function is used. Each field holds the
/// pointer to the function of the field's name, and its type is the
/// prototype of the function, as the header of the library declares it. A
/// call through the pointer is unsafe, as nothing checks that prototype.
///
/// ```
/// use std::ffi::c_char;
///
/// dlopen::symbols! {
///     /// The function of the C library the example calls, with the
///     /// prototype of string.h.
///     struct Libc from c"libc.so.6" {
///         strlen: unsafe extern "C" fn(*const c_char) -> usize,
///     }
/// }
///
/// static LIBC: dlopen::Lazy<Libc> = dlopen::Lazy::new();
///
/// // A statically linked program has none.
/// if let Some(libc) = LIBC.get() {
///     let s = c"four";
///     // SAFETY: the prototype of string.h, and a NUL terminated string.
///     assert_eq!(unsafe { (libc.strlen)(s.as_ptr()) }, s.count_bytes());
/// }
/// ```
#[macro_export]
macro_rules! symbols {
    (
        $(#[$attr:meta])*
        $vis:vis struct $name:ident from $($soname:tt),+ {
            $($(#[$field_attr:meta])* $field:ident: $type:ty),+ $(,)?
        }
    ) => {
        $(#[$attr])*
        $vis struct $name {
            $($(#[$field_attr])* $field: $type,)+
        }

        impl $crate::Symbols for $name {
            const SONAMES: &'static [&'static ::std::ffi::CStr] = &[$($soname),+];

            fn resolve(library: &$crate::Library) -> ::std::io::Result<$name> {
                ::std::result::Result::Ok($name {
                    $(
                        $field: library.function(const { $crate::symbol_name(concat!(stringify!($field), "\0")) })?,
                    )+
                })
            }
        }
    };
}

/// The name of a symbol as [`symbols!`] looks it up: the name of a field
/// and a NUL.
#[doc(hidden)]
pub const fn symbol_name(name: &'static str) -> &'static CStr {
    match CStr::from_bytes_with_nul(name.as_bytes()) {
        Ok(name) => name,
        Err(_) => panic!("a symbol name has no NUL but the one that ends it"),
    }
}

#[cfg(test)]
#[allow(unsafe_code)]
mod tests {
    use super::*;
    use std::ffi::c_char;

    /// The C library, which every dynamically linked program on glibc has
    /// loaded.
    const LIBC: &CStr = c"libc.so.6";
    /// A library no system has.
    const MISSING: &CStr = c"libufat-missing.so.0";
    /// What the tests have strlen() count.
    const FOUR: &CStr = c"four";

    symbols! {
        /// A function of the C library, with the prototype of string.h.
        struct Libc from LIBC {
            strlen: unsafe extern "C" fn(*const c_char) -> usize,
        }
    }

    symbols! {
        /// A function the C library does not have.
        #[allow(dead_code)]
        struct MissingFunction from LIBC {
            ufat_missing_function: unsafe extern "C" fn(),
        }
    }

    symbols! {
        /// A function of a library no system has.
        #[allow(dead_code)]
        struct MissingLibrary from MISSING {
            ufat_missing_function: unsafe extern "C" fn(),
        }
    }

    symbols! {
        /// A function of the C library, which is the second name, with the
        /// prototype of string.h.
        struct SecondName from MISSING, LIBC {
            strlen: unsafe extern "C" fn(*const c_char) -> usize,
        }
    }

    symbols! {
        /// A function that neither library has.
        #[allow(dead_code)]
        struct NeitherName from MISSING, LIBC {
            ufat_missing_function: unsafe extern "C" fn(),
        }
    }

    /// Whether `e` names `what`.
    fn names(e: &io::Error, what: &CStr) -> bool {
        e.to_string().contains(what.to_str().unwrap())
    }

    #[test]
    fn a_missing_library_says_why() {
        let e = Library::open(MISSING).unwrap_err();
        assert!(names(&e, MISSING), "{}", e);
    }

    /// A statically linked program loads nothing, not even the C library
    /// it holds.
    #[test]
    #[cfg(target_feature = "crt-static")]
    fn a_static_program_loads_nothing() {
        let e = Library::open(LIBC).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::Unsupported);
        assert!(names(&e, LIBC), "{}", e);
        static LOADED: Lazy<Libc> = Lazy::new();
        assert!(LOADED.get().is_none());
    }

    #[test]
    #[cfg_attr(
        target_feature = "crt-static",
        ignore = "a statically linked program cannot load a library"
    )]
    fn functions_are_looked_up_by_name() {
        let libc = Library::open(LIBC).unwrap();
        let strlen: unsafe extern "C" fn(*const c_char) -> usize = libc.function(c"strlen").unwrap();
        let e = libc
            .function::<unsafe extern "C" fn()>(c"ufat_missing_function")
            .unwrap_err();
        assert!(names(&e, c"ufat_missing_function"), "{}", e);
        drop(libc);
        // The function stays valid after the library is closed.
        // SAFETY: the prototype of string.h, and a NUL terminated string.
        assert_eq!(unsafe { strlen(FOUR.as_ptr()) }, FOUR.count_bytes());
    }

    #[test]
    #[cfg_attr(
        target_feature = "crt-static",
        ignore = "a statically linked program cannot load a library"
    )]
    fn functions_are_loaded_once() {
        static LOADED: Lazy<Libc> = Lazy::new();
        let libc = LOADED.get().unwrap();
        assert!(std::ptr::eq(libc, LOADED.get().unwrap()));
        assert!(std::ptr::eq(libc, LOADED.try_get().unwrap()));
        // SAFETY: the prototype of string.h, and a NUL terminated string.
        assert_eq!(unsafe { (libc.strlen)(FOUR.as_ptr()) }, FOUR.count_bytes());
    }

    #[test]
    #[cfg_attr(
        target_feature = "crt-static",
        ignore = "a statically linked program cannot load a library"
    )]
    fn a_failure_is_kept() {
        static NO_LIBRARY: Lazy<MissingLibrary> = Lazy::new();
        static NO_FUNCTION: Lazy<MissingFunction> = Lazy::new();
        assert!(NO_LIBRARY.get().is_none());
        let e = NO_LIBRARY.try_get().err().unwrap();
        assert!(std::ptr::eq(e, NO_LIBRARY.try_get().err().unwrap()));
        assert!(names(e, MISSING), "{}", e);
        assert!(NO_FUNCTION.get().is_none());
        let e = NO_FUNCTION.try_get().err().unwrap();
        assert!(names(e, c"ufat_missing_function"), "{}", e);
    }

    /// The names of a library are tried in order, and when none works,
    /// the error says why for each.
    #[test]
    #[cfg_attr(
        target_feature = "crt-static",
        ignore = "a statically linked program cannot load a library"
    )]
    fn every_name_is_tried() {
        assert_eq!(SecondName::SONAMES, [MISSING, LIBC]);
        let libc = SecondName::load().unwrap();
        // SAFETY: the prototype of string.h, and a NUL terminated string.
        assert_eq!(unsafe { (libc.strlen)(FOUR.as_ptr()) }, FOUR.count_bytes());
        let e = NeitherName::load().err().unwrap();
        let message = e.to_string();
        let (first, second) = message.split_once("; ").unwrap();
        assert!(first.contains(MISSING.to_str().unwrap()), "{}", e);
        assert!(second.contains("ufat_missing_function"), "{}", e);
    }
}
