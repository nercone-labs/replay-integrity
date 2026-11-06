use quick_xml::XmlVersion;
use quick_xml::escape::resolve_predefined_entity;
use quick_xml::events::{BytesStart, Event};
use quick_xml::reader::Reader;

use crate::KeyboxError;

/// An XML element with its attributes, its child elements and its text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node {
    pub name: String,
    pub attributes: Vec<(String, String)>,
    pub children: Vec<Node>,
    pub text: String,
}

impl Node {
    /// Parses a well-formed document and returns its root element. Document type
    /// declarations are refused, so that no external entity can be referenced.
    pub fn parse(source: &str) -> Result<Node, KeyboxError> {
        let mut reader = Reader::from_str(source);
        let config = reader.config_mut();
        config.check_end_names = true;
        config.check_comments = true;
        let mut stack: Vec<Node> = Vec::new();
        let mut root: Option<Node> = None;
        loop {
            let event = reader.read_event().map_err(|error| KeyboxError::Syntax(format!("{error} at {}", reader.error_position())))?;
            match event {
                Event::Start(tag) | Event::Empty(tag) if root.is_some() && stack.is_empty() => {
                    return Err(KeyboxError::Syntax(format!("a second root element <{}>", tag.name().as_ref())));
                }
                Event::Start(tag) => stack.push(Node::open(&tag)?),
                Event::Empty(tag) => Node::attach(Node::open(&tag)?, &mut stack, &mut root),
                Event::End(_) => {
                    let node = stack.pop().ok_or_else(|| KeyboxError::Syntax("an unexpected end tag".to_string()))?;
                    Node::attach(node, &mut stack, &mut root);
                }
                Event::Text(text) => {
                    let content = text.xml_content(XmlVersion::Implicit1_0);
                    match stack.last_mut() {
                        Some(node) => node.text.push_str(&content),
                        None if content.trim().is_empty() => {}
                        None => return Err(KeyboxError::Syntax("text outside of the root element".to_string())),
                    }
                }
                Event::CData(data) => match stack.last_mut() {
                    Some(node) => node.text.push_str(&data.xml_content(XmlVersion::Implicit1_0)),
                    None => return Err(KeyboxError::Syntax("CDATA outside of the root element".to_string())),
                },
                Event::GeneralRef(reference) => {
                    let resolved = match reference.resolve_char_ref() {
                        Ok(Some(character)) => character.to_string(),
                        Ok(None) => {
                            let name: &str = &reference;
                            resolve_predefined_entity(name).map(str::to_string).ok_or_else(|| KeyboxError::Syntax(format!("an unknown entity &{name};")))?
                        }
                        Err(error) => return Err(KeyboxError::Syntax(error.to_string())),
                    };
                    if let Some(node) = stack.last_mut() {
                        node.text.push_str(&resolved);
                    }
                }
                Event::DocType(_) => return Err(KeyboxError::Syntax("DOCTYPE declarations are not allowed".to_string())),
                Event::Decl(_) | Event::PI(_) | Event::Comment(_) => {}
                Event::Eof => break,
            }
        }
        if !stack.is_empty() {
            return Err(KeyboxError::Syntax("the document ends inside an element".to_string()));
        }
        root.ok_or_else(|| KeyboxError::Syntax("the document has no root element".to_string()))
    }

    fn open(tag: &BytesStart) -> Result<Node, KeyboxError> {
        let name = tag.name().as_ref().to_string();
        let mut attributes: Vec<(String, String)> = Vec::new();
        for attribute in tag.attributes() {
            let attribute = attribute.map_err(|error| KeyboxError::Syntax(format!("an invalid attribute in <{name}>: {error}")))?;
            let key = attribute.key.as_ref().to_string();
            let value =
                attribute.normalized_value(XmlVersion::Implicit1_0).map_err(|error| KeyboxError::Syntax(format!("an invalid value of {key}: {error}")))?;
            if attributes.iter().any(|(existing, _)| *existing == key) {
                return Err(KeyboxError::Syntax(format!("a duplicate attribute {key} in <{name}>")));
            }
            attributes.push((key, value.into_owned()));
        }
        Ok(Node { name, attributes, children: Vec::new(), text: String::new() })
    }

    fn attach(node: Node, stack: &mut [Node], root: &mut Option<Node>) {
        match stack.last_mut() {
            Some(parent) => parent.children.push(node),
            None => *root = Some(node),
        }
    }

    pub fn attribute(&self, name: &str) -> Option<&str> {
        self.attributes.iter().find(|(key, _)| key == name).map(|(_, value)| value.as_str())
    }

    pub fn children_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Node> + 'a {
        self.children.iter().filter(move |child| child.name == name)
    }

    pub fn child(&self, name: &str) -> Option<&Node> {
        self.children.iter().find(|child| child.name == name)
    }
}
