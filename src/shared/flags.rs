// SPDX-License-Identifier: LGPL-2.1-or-later
//! Sets of flags.

/// Declares a type that holds any of the flags it names. Each flag is a
/// constant of the type and one bit of the integer behind it:
///
/// ```
/// shared::flags! {
///     /// What is known of a file.
///     pub struct Known: u8 {
///         /// Its size.
///         const SIZE = 1 << 0;
///         /// Its time.
///         const TIME = 1 << 1;
///     }
/// }
///
/// let mut known = Known::SIZE;
/// known |= Known::TIME;
/// assert!(known.contains(Known::SIZE | Known::TIME));
/// assert_eq!(known, Known::all());
/// assert!(Known::empty().is_empty());
/// ```
///
/// A function takes such a type where it would take several `bool`
/// parameters otherwise, and a struct holds one in the place of several
/// `bool` fields.
#[macro_export]
macro_rules! flags {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident: $repr:ty {
            $(
                $(#[$flag_meta:meta])*
                const $flag:ident = $value:expr;
            )*
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
        $vis struct $name($repr);

        // Not every set of flags needs every one of these.
        #[allow(dead_code)]
        impl $name {
            $(
                $(#[$flag_meta])*
                $vis const $flag: $name = $name($value);
            )*

            /// No flag.
            $vis const fn empty() -> $name {
                $name(0)
            }

            /// Every flag.
            $vis const fn all() -> $name {
                $name(0 $(| $value)*)
            }

            /// Whether no flag is set.
            $vis const fn is_empty(self) -> bool {
                self.0 == 0
            }

            /// Whether every flag of `flags` is set.
            $vis const fn contains(self, flags: $name) -> bool {
                self.0 & flags.0 == flags.0
            }

            /// Whether any flag of `flags` is set.
            $vis const fn intersects(self, flags: $name) -> bool {
                self.0 & flags.0 != 0
            }

            /// Sets the flags of `flags`.
            $vis fn insert(&mut self, flags: $name) {
                self.0 |= flags.0;
            }

            /// Clears the flags of `flags`.
            $vis fn remove(&mut self, flags: $name) {
                self.0 &= !flags.0;
            }

            /// These flags, and those of `flags` when `condition` holds.
            #[must_use]
            $vis const fn with_if(self, flags: $name, condition: bool) -> $name {
                if condition {
                    $name(self.0 | flags.0)
                } else {
                    self
                }
            }
        }

        impl ::core::ops::BitOr for $name {
            type Output = $name;

            fn bitor(self, flags: $name) -> $name {
                $name(self.0 | flags.0)
            }
        }

        impl ::core::ops::BitOrAssign for $name {
            fn bitor_assign(&mut self, flags: $name) {
                self.0 |= flags.0;
            }
        }

        impl ::core::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                let mut set = f.debug_set();
                $(
                    if self.contains($name::$flag) {
                        set.entry(&::core::format_args!("{}", ::core::stringify!($flag)));
                    }
                )*
                set.finish()
            }
        }
    };
}

#[cfg(test)]
mod tests {
    flags! {
        /// What a test knows.
        struct Known: u8 {
            /// The first thing.
            const FIRST = 1 << 0;
            /// The second thing.
            const SECOND = 1 << 1;
            /// The third thing.
            const THIRD = 1 << 2;
        }
    }

    #[test]
    fn flags_are_set_cleared_and_asked_for() {
        let mut known = Known::empty();
        assert!(known.is_empty());
        assert_eq!(known, Known::default());
        assert!(known.contains(Known::empty()));
        assert!(!known.contains(Known::FIRST));
        known.insert(Known::FIRST);
        known |= Known::THIRD;
        assert!(known.contains(Known::FIRST));
        assert!(known.contains(Known::FIRST | Known::THIRD));
        assert!(!known.contains(Known::FIRST | Known::SECOND));
        assert!(known.intersects(Known::FIRST | Known::SECOND));
        assert!(!known.intersects(Known::SECOND));
        assert_eq!(known, Known::FIRST | Known::THIRD);
        known.remove(Known::FIRST | Known::SECOND);
        assert_eq!(known, Known::THIRD);
        assert_eq!(known.with_if(Known::FIRST, false), Known::THIRD);
        assert_eq!(known.with_if(Known::FIRST, true), Known::FIRST | Known::THIRD);
        assert_eq!(Known::all(), Known::FIRST | Known::SECOND | Known::THIRD);
        assert!(!Known::all().is_empty());
    }

    #[test]
    fn flags_show_their_names() {
        assert_eq!(format!("{:?}", Known::empty()), "{}");
        assert_eq!(format!("{:?}", Known::SECOND), "{SECOND}");
        assert_eq!(format!("{:?}", Known::THIRD | Known::FIRST), "{FIRST, THIRD}");
    }
}
