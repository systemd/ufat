// SPDX-License-Identifier: LGPL-2.1-or-later
//! Paths inside a volume.
//!
//! A path is a sequence of names separated by slashes. Leading, trailing
//! and repeated slashes carry no meaning. "." and ".." are rejected: there
//! is no working directory to resolve them against, and a FAT directory
//! stores them as entries of their own.

use crate::errno::*;
use crate::{Detail, NameProblem};
use crate::{Error, Result};

/// What separates the names of a path.
pub(crate) const SEPARATOR: char = '/';

/// Longest path accepted, in bytes: Linux's PATH_MAX without the NUL. A
/// longer path could not be opened on the mounted volume in one go, and
/// without a bound the paths a tree walk builds grow with the tree.
pub(crate) const MAX_PATH: usize = 4095;

/// Splits `path` into its names.
pub(crate) fn components(path: &str) -> Result<Vec<&str>> {
    check_length(path)?;
    let mut out = Vec::new();
    for name in path.split(SEPARATOR).filter(|name| !name.is_empty()) {
        if is_dot_name(name) {
            return Err(dot_component(path, name));
        }
        out.push(name);
    }
    Ok(out)
}

/// The names of `path`, the first one first, checked as [`components`]
/// checks them but not collected.
pub(crate) fn names(path: &str) -> Result<impl DoubleEndedIterator<Item = &str> + Clone> {
    check_length(path)?;
    let names = path.split(SEPARATOR).filter(|name| !name.is_empty());
    if let Some(name) = names.clone().find(|name| is_dot_name(name)) {
        return Err(dot_component(path, name));
    }
    Ok(names)
}

/// The path of the directory `path` is in, as `path` spells it, and the
/// last name of `path`, where that is all [`names`] has to check of it:
/// `path` fits [`MAX_PATH`], and its last name is not empty, "." or "..".
/// The names of `path` are then those of the directory and the last name,
/// and [`names`] refuses `path` only where it refuses the directory. None
/// for every other path.
pub(crate) fn parent_and_name(path: &str) -> Option<(&str, &str)> {
    let (parent, name) = path.rsplit_once(SEPARATOR)?;
    (fits(path) && !name.is_empty() && !is_dot_name(name)).then_some((parent, name))
}

/// Whether `path` is not longer than [`MAX_PATH`].
fn fits(path: &str) -> bool {
    path.len() <= MAX_PATH
}

/// Refuses a path longer than [`MAX_PATH`].
fn check_length(path: &str) -> Result<()> {
    if !fits(path) {
        bail!(
            ENAMETOOLONG,
            Detail::Name {
                name: path.to_string(),
                problem: NameProblem::TooLong,
            },
            "path is longer than {} bytes",
            MAX_PATH
        );
    }
    Ok(())
}

/// Whether `name` is "." or "..", which a path must not have.
fn is_dot_name(name: &str) -> bool {
    name == "." || name == ".."
}

/// The error of `path` for its name `name`, "." or "..".
fn dot_component(path: &str, name: &str) -> Error {
    err!(
        EINVAL,
        Detail::Name {
            name: path.to_string(),
            problem: NameProblem::DotComponent,
        },
        "path '{}' contains a '{}' component",
        path,
        name
    )
}

/// Appends `name` to the directory path `dir`.
pub(crate) fn join(dir: &str, name: &str) -> String {
    format!("{}{}{}", dir.trim_end_matches(SEPARATOR), SEPARATOR, name)
}

/// The path of the directory `path` is in: "/a/b" and "/a/b/" are in
/// "/a", "/b" and "b" in "", which is the root to [`join`].
pub(crate) fn parent(path: &str) -> &str {
    path.trim_end_matches(SEPARATOR)
        .rsplit_once(SEPARATOR)
        .map_or("", |(parent, _)| parent)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splitting_and_joining() {
        assert_eq!(components("/").unwrap(), Vec::<&str>::new());
        assert_eq!(components("").unwrap(), Vec::<&str>::new());
        assert_eq!(components("/EFI//Linux/").unwrap(), vec!["EFI", "Linux"]);
        assert_eq!(components("EFI/Linux").unwrap(), vec!["EFI", "Linux"]);
        assert_eq!(components("/EFI/./x").unwrap_err().errno(), EINVAL);
        assert_eq!(components("../x").unwrap_err().errno(), EINVAL);
        assert_eq!(names("/EFI//Linux/").unwrap().next_back(), Some("Linux"));
        assert_eq!(names("/EFI/..").err().map(|e| e.errno()), Some(EINVAL));
        let longest = format!("/{}", "x".repeat(MAX_PATH - 1));
        let too_long = format!("{}x", longest);
        for (path, split) in [
            ("/EFI/Linux", Some(("/EFI", "Linux"))),
            ("/EFI", Some(("", "EFI"))),
            ("EFI/Linux", Some(("EFI", "Linux"))),
            ("/EFI//Linux", Some(("/EFI/", "Linux"))),
            ("/./x", Some(("/.", "x"))),
            (longest.as_str(), Some(("", &longest[1..]))),
            ("EFI", None),
            ("/EFI/", None),
            ("/EFI/.", None),
            ("/EFI/..", None),
            (too_long.as_str(), None),
        ] {
            assert_eq!(parent_and_name(path), split, "{}", path);
            if let Some((parent, name)) = split {
                // names() agrees, also where it refuses the directory.
                let parent_names = names(parent).map(|names| names.chain([name]).collect::<Vec<_>>());
                let path_names = names(path).map(|names| names.collect::<Vec<_>>());
                assert_eq!(path_names.ok(), parent_names.ok(), "{}", path);
            }
        }
        assert_eq!(join("/", "EFI"), "/EFI");
        assert_eq!(join("", "EFI"), "/EFI");
        assert_eq!(join("/EFI/", "Linux"), "/EFI/Linux");
        assert_eq!(join("/EFI", "Linux"), "/EFI/Linux");
        for (path, parent_path) in [
            ("/EFI/Linux", "/EFI"),
            ("/EFI/Linux/", "/EFI"),
            ("EFI/Linux", "EFI"),
            ("/EFI", ""),
            ("/EFI/", ""),
            ("EFI", ""),
            ("", ""),
        ] {
            assert_eq!(parent(path), parent_path, "{}", path);
        }
        assert_eq!(join(parent("/EFI/"), "efi"), "/efi");
        let long = format!("/{}", "x".repeat(MAX_PATH - 1));
        assert_eq!(components(&long).unwrap().len(), 1);
        assert_eq!(components(&format!("{}x", long)).unwrap_err().errno(), ENAMETOOLONG);
    }
}
