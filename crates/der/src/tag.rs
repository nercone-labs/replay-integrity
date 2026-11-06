use std::fmt;

/// The class of a tag (X.690 8.1.2.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TagClass {
    Universal,
    Application,
    ContextSpecific,
    Private,
}

/// The identifier of an element: its class, whether it is constructed, and its number.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Tag {
    pub class: TagClass,
    pub constructed: bool,
    pub number: u32,
}

impl Tag {
    pub const BOOLEAN: Tag = Tag::universal(1, false);
    pub const INTEGER: Tag = Tag::universal(2, false);
    pub const BIT_STRING: Tag = Tag::universal(3, false);
    pub const OCTET_STRING: Tag = Tag::universal(4, false);
    pub const NULL: Tag = Tag::universal(5, false);
    pub const OBJECT_IDENTIFIER: Tag = Tag::universal(6, false);
    pub const ENUMERATED: Tag = Tag::universal(10, false);
    pub const UTF8_STRING: Tag = Tag::universal(12, false);
    pub const SEQUENCE: Tag = Tag::universal(16, true);
    pub const SET: Tag = Tag::universal(17, true);
    pub const PRINTABLE_STRING: Tag = Tag::universal(19, false);
    pub const TELETEX_STRING: Tag = Tag::universal(20, false);
    pub const IA5_STRING: Tag = Tag::universal(22, false);
    pub const UTC_TIME: Tag = Tag::universal(23, false);
    pub const GENERALIZED_TIME: Tag = Tag::universal(24, false);
    pub const UNIVERSAL_STRING: Tag = Tag::universal(28, false);
    pub const BMP_STRING: Tag = Tag::universal(30, false);

    /// The largest tag number accepted: larger numbers are not used by any known structure.
    pub const MAX_NUMBER: u32 = (1 << 28) - 1;

    pub const fn universal(number: u32, constructed: bool) -> Tag {
        Tag { class: TagClass::Universal, constructed, number }
    }

    pub const fn context(number: u32, constructed: bool) -> Tag {
        Tag { class: TagClass::ContextSpecific, constructed, number }
    }
}

impl fmt::Display for Tag {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let class = match self.class {
            TagClass::Universal => "UNIVERSAL",
            TagClass::Application => "APPLICATION",
            TagClass::ContextSpecific => "CONTEXT",
            TagClass::Private => "PRIVATE",
        };
        write!(formatter, "[{class} {}]{}", self.number, if self.constructed { " constructed" } else { "" })
    }
}
