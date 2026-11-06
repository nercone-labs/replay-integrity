//! Property files of `key=value` lines, as Android's `build.prop` and many tools use them.
//!
//! A line is an entry when it is not blank, does not start with `#`, and contains `=`; the key
//! is the text before the first `=`, trimmed, and the value is the rest without the line's
//! surrounding whitespace. Every other line is kept as it is. Editing an entry keeps the
//! position of its first occurrence, so that a file stays readable after it is changed.

/// One line of a property file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PropLine {
    Entry {
        key: String,
        value: String,
    },
    /// A blank line, a comment, or a line without `=`, kept verbatim.
    Other(String),
}

/// A property file.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PropFile {
    pub lines: Vec<PropLine>,
}

impl PropFile {
    pub fn parse(text: &str) -> PropFile {
        let lines = text
            .lines()
            .map(|line| {
                let trimmed = line.trim();
                match trimmed.split_once('=') {
                    Some((key, value)) if !trimmed.starts_with('#') && !key.trim().is_empty() => {
                        PropLine::Entry { key: key.trim().to_string(), value: value.trim().to_string() }
                    }
                    _ => PropLine::Other(line.trim_end_matches('\r').to_string()),
                }
            })
            .collect();
        PropFile { lines }
    }

    /// The value of the last entry of `key`, the one that readers which keep the last value of
    /// a repeated key see.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries().filter(|(name, _)| *name == key).last().map(|(_, value)| value)
    }

    /// The entries in order, as (key, value) pairs.
    pub fn entries(&self) -> impl Iterator<Item = (&str, &str)> {
        self.lines.iter().filter_map(|line| match line {
            PropLine::Entry { key, value } => Some((key.as_str(), value.as_str())),
            PropLine::Other(_) => None,
        })
    }

    /// The comment lines, without their `#` and surrounding whitespace.
    pub fn comments(&self) -> impl Iterator<Item = &str> {
        self.lines.iter().filter_map(|line| match line {
            PropLine::Other(text) => text.trim().strip_prefix('#').map(str::trim),
            PropLine::Entry { .. } => None,
        })
    }

    /// Sets `key` to `value`: the first entry of `key` is changed and later ones are removed,
    /// or a new entry is appended.
    pub fn set(&mut self, key: &str, value: &str) {
        let mut found = false;
        self.lines.retain_mut(|line| match line {
            PropLine::Entry { key: name, value: current } if name == key => {
                if found {
                    return false;
                }
                found = true;
                *current = value.to_string();
                true
            }
            _ => true,
        });
        if !found {
            self.lines.push(PropLine::Entry { key: key.to_string(), value: value.to_string() });
        }
    }

    /// Removes every entry of `key`.
    pub fn remove(&mut self, key: &str) {
        self.lines.retain(|line| !matches!(line, PropLine::Entry { key: name, .. } if name == key));
    }

    /// The file as text, one line per line, each ending with a line feed.
    pub fn render(&self) -> String {
        let mut text = String::new();
        for line in &self.lines {
            match line {
                PropLine::Entry { key, value } => {
                    text.push_str(key);
                    text.push('=');
                    text.push_str(value);
                }
                PropLine::Other(other) => text.push_str(other),
            }
            text.push('\n');
        }
        text
    }
}
