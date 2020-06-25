use serde::de::{Deserialize, Deserializer};
use std::borrow::Cow;
use std::fmt;
use std::fs::File;
use std::io::{BufRead, BufReader, Error as IoError, Lines};
use std::iter::FusedIterator;
use std::path::{Path, PathBuf};

/// Wrapper type for a list of string values.
///
/// These lists are often used in configuration, and can contain either literal string values, or
/// string paths prefixed with `@`. This type implements `Deserialize`, and can then be iterated to
/// produce a combined list of all values from all literals and files.
#[derive(Default)]
pub struct StringList {
    inner: Vec<StringListEntry>,
}

enum StringListEntry {
    Literal(String),
    File(PathBuf),
}

impl From<Vec<String>> for StringList {
    fn from(input: Vec<String>) -> Self {
        let inner = input
            .into_iter()
            .map(|value| {
                if value.starts_with("@") {
                    StringListEntry::File((&value[1..]).into())
                } else {
                    StringListEntry::Literal(value)
                }
            })
            .collect();
        Self { inner }
    }
}

impl<'de> Deserialize<'de> for StringList {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let input: Vec<String> = Deserialize::deserialize(deserializer)?;
        Ok(input.into())
    }
}

impl StringList {
    /// Iterate values in the list.
    pub fn iter_values(&self) -> StringListIter {
        StringListIter {
            list: self,
            index: 0,
            reader: None,
        }
    }
}

/// Iterator over values in a `StringList`.
///
/// Produces results that may contain IO errors from opening or reading files. Each result is
/// accompanied by a `StringListSource` that describes where it comes from.
pub struct StringListIter<'a> {
    list: &'a StringList,
    index: usize,
    reader: Option<StringListFileReader<'a>>,
}

impl<'a> Iterator for StringListIter<'a> {
    type Item = (StringListSource<'a>, Result<Cow<'a, str>, IoError>);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            // Exhaust any open reader.
            if let Some(reader) = self.reader.as_mut() {
                if let Some(res) = reader.next() {
                    return Some((
                        StringListSource::File {
                            index: self.index,
                            path: reader.path,
                            line: reader.line,
                        },
                        match res {
                            Ok(data) => Ok(data.into()),
                            Err(err) => Err(err),
                        },
                    ));
                } else {
                    self.reader = None;
                    self.index += 1;
                }
            }

            match self.list.inner.get(self.index)? {
                StringListEntry::Literal(ref data) => {
                    let source = StringListSource::Literal { index: self.index };
                    self.index += 1;
                    return Some((source, Ok(data.into())));
                }
                StringListEntry::File(ref path) => {
                    self.reader = match StringListFileReader::open(path) {
                        Ok(reader) => Some(reader),
                        Err(err) => {
                            return Some((
                                StringListSource::File {
                                    index: self.index,
                                    path,
                                    line: 0,
                                },
                                Err(err),
                            ));
                        }
                    };
                }
            }
        }
    }
}

impl<'a> FusedIterator for StringListFileReader<'a> {}

/// Source of a `StringListIter` result.
pub enum StringListSource<'a> {
    /// Value comes from a literal in the list.
    Literal {
        /// Index in the list.
        index: usize,
    },
    /// Value comes from a file.
    File {
        /// Index in the list.
        index: usize,
        /// Path of the file.
        path: &'a Path,
        /// Line number in the file. (Starts counting at 1.)
        line: usize,
    },
}

impl<'a> fmt::Display for StringListSource<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StringListSource::Literal { index } => write!(f, "#{} (literal)", index + 1),
            StringListSource::File { index, path, line } => {
                write!(f, "#{} {:?}:{}", index + 1, path, line)
            }
        }
    }
}

/// File reader for a generic list of string values.
///
/// This is intended to be compatible with (at least) the IANA TLDs list and the public suffix
/// list. It reads each line until the first whitespace, allows comments using `//` and `#`, and
/// ignores empty lines.
pub struct StringListFileReader<'a> {
    inner: Lines<BufReader<File>>,
    path: &'a Path,
    line: usize,
}

impl<'a> StringListFileReader<'a> {
    /// Open a file for reading.
    pub fn open(path: &'a Path) -> Result<Self, IoError> {
        Ok(Self {
            inner: BufReader::new(File::open(path)?).lines(),
            path,
            line: 0,
        })
    }
}

impl<'a> Iterator for StringListFileReader<'a> {
    type Item = Result<String, IoError>;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(data) = self.inner.next() {
            self.line += 1;

            let data = match data {
                Err(err) => return Some(Err(err)),
                Ok(data) => data,
            };

            if let Some(data) = data.split_whitespace().next() {
                if !data.is_empty() && !data.starts_with("//") && !data.starts_with('#') {
                    return Some(Ok(data.to_owned()));
                }
            }
        }
        None
    }
}
