use prop::{PropFile, PropLine};

#[test]
fn entries_comments_and_blank_lines_are_told_apart() {
    let file = PropFile::parse("# a comment\n\nKEY=value\n  spaced = around \nnot an entry\n#KEY=inComment\n");
    assert_eq!(file.get("KEY"), Some("value"));
    assert_eq!(file.get("spaced"), Some("around"));
    // A '#'-prefixed line is a comment even when it contains '='.
    assert_eq!(file.get("#KEY"), None);
    assert_eq!(file.comments().collect::<Vec<_>>(), ["a comment", "KEY=inComment"]);
    assert_eq!(file.entries().count(), 2);
}

#[test]
fn setting_keeps_position_and_removes_later_duplicates() {
    let mut file = PropFile::parse("A=1\nB=2\nA=3\n# tail\n");
    // The last value is the one readers see.
    assert_eq!(file.get("A"), Some("3"));
    file.set("A", "9");
    // The first occurrence is changed in place, later ones removed, the comment kept.
    assert_eq!(file.render(), "A=9\nB=2\n# tail\n");
    // A new key is appended.
    file.set("C", "x");
    assert!(file.render().ends_with("C=x\n"));
    file.remove("B");
    assert!(file.get("B").is_none());
}

#[test]
fn a_missing_key_is_none_and_order_is_preserved_on_render() {
    let text = "ONE=1\n# note\nTWO=2\n";
    let file = PropFile::parse(text);
    assert!(file.get("MISSING").is_none());
    // An unchanged file renders to itself (with a trailing newline).
    assert_eq!(file.render(), text);
    assert!(matches!(file.lines[1], PropLine::Other(_)));
}
