// SPDX-License-Identifier: LGPL-2.1-or-later
//! The Varlink interface definition language: a parser for the subset the
//! specification defines (types, methods, errors) and a validator that
//! checks call parameters against a method's declared inputs.

use std::collections::BTreeMap;
use std::fmt;

use json::{Object, Value};

/// A declared type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Type {
    /// `bool`
    Bool,
    /// `int`
    Int,
    /// `float`
    Float,
    /// `string`
    String,
    /// `object`: any JSON object
    Object,
    /// `any`: any non-null value
    Any,
    /// `(a, b, c)`
    Enum(Vec<String>),
    /// `(name: type, ...)`
    Struct(Vec<Field>),
    /// A type declared with `type Name`.
    Named(String),
    /// `[]T`
    Array(Box<Type>),
    /// `[string]T`
    Map(Box<Type>),
    /// `?T`
    Nullable(Box<Type>),
}

/// A named field of a struct, method or error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Field {
    /// The field name.
    pub name: String,
    /// The field type.
    pub ty: Type,
}

/// A method declaration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Method {
    /// Input parameters.
    pub input: Vec<Field>,
    /// Output parameters.
    pub output: Vec<Field>,
    /// The method may send several replies (`# [Supports 'more' flag]`).
    pub supports_more: bool,
    /// The method must be called with `more` (`# [Requires 'more' flag]`).
    pub requires_more: bool,
    /// The method may take the connection over (`# [Supports 'upgrade' flag]`).
    pub supports_upgrade: bool,
    /// The method must be called with `upgrade` (`# [Requires 'upgrade' flag]`).
    pub requires_upgrade: bool,
}

/// A parsed interface.
#[derive(Clone, Debug)]
pub struct Interface {
    /// The interface name, e.g. `org.varlink.service`.
    pub name: String,
    /// The description text as given, served verbatim.
    pub text: String,
    /// Declared types.
    pub types: BTreeMap<String, Type>,
    /// Declared methods.
    pub methods: BTreeMap<String, Method>,
    /// Declared errors with their parameters.
    pub errors: BTreeMap<String, Vec<Field>>,
}

/// A parse error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    /// Line number, 1-based.
    pub line: usize,
    /// What went wrong.
    pub message: String,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}

impl std::error::Error for Error {}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Token {
    Word(String),
    Punct(&'static str),
    Newline,
}

struct Lexer<'a> {
    text: &'a str,
    pos: usize,
    line: usize,
}

impl Lexer<'_> {
    fn next_token(&mut self) -> Result<Option<Token>, Error> {
        loop {
            let rest = &self.text[self.pos..];
            let Some(c) = rest.chars().next() else { return Ok(None) };
            match c {
                '\n' => {
                    self.pos += 1;
                    self.line += 1;
                    return Ok(Some(Token::Newline));
                }
                ' ' | '\t' | '\r' => self.pos += 1,
                '#' => {
                    let end = rest.find('\n').unwrap_or(rest.len());
                    self.pos += end;
                }
                '-' if rest.starts_with("->") => {
                    self.pos += 2;
                    return Ok(Some(Token::Punct("->")));
                }
                '(' | ')' | ':' | ',' | '?' | '[' | ']' => {
                    self.pos += 1;
                    let p = match c {
                        '(' => "(",
                        ')' => ")",
                        ':' => ":",
                        ',' => ",",
                        '?' => "?",
                        '[' => "[",
                        _ => "]",
                    };
                    return Ok(Some(Token::Punct(p)));
                }
                c if c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-' => {
                    let end = rest
                        .find(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '.' || ch == '-'))
                        .unwrap_or(rest.len());
                    self.pos += end;
                    return Ok(Some(Token::Word(rest[..end].to_string())));
                }
                _ => {
                    return Err(Error {
                        line: self.line,
                        message: format!("unexpected character '{}'", c),
                    })
                }
            }
        }
    }
}

struct Parser {
    tokens: Vec<(Token, usize)>,
    pos: usize,
}

impl Parser {
    fn error(&self, message: impl Into<String>) -> Error {
        let line = self.tokens.get(self.pos).or(self.tokens.last()).map_or(1, |t| t.1);
        Error {
            line,
            message: message.into(),
        }
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos).map(|t| &t.0)
    }

    fn next_token(&mut self) -> Option<Token> {
        let t = self.tokens.get(self.pos).map(|t| t.0.clone());
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    fn skip_newlines(&mut self) {
        while self.peek() == Some(&Token::Newline) {
            self.pos += 1;
        }
    }

    fn expect_punct(&mut self, p: &str) -> Result<(), Error> {
        match self.next_token() {
            Some(Token::Punct(q)) if q == p => Ok(()),
            other => Err(self.error(format!("expected '{}', found {:?}", p, other))),
        }
    }

    fn word(&mut self) -> Result<String, Error> {
        match self.next_token() {
            Some(Token::Word(w)) => Ok(w),
            other => Err(self.error(format!("expected a name, found {:?}", other))),
        }
    }

    fn parse_type(&mut self) -> Result<Type, Error> {
        match self.peek() {
            Some(Token::Punct("?")) => {
                self.pos += 1;
                let inner = self.parse_type()?;
                if matches!(inner, Type::Nullable(_)) {
                    return Err(self.error("nested '?'"));
                }
                Ok(Type::Nullable(Box::new(inner)))
            }
            Some(Token::Punct("[")) => {
                self.pos += 1;
                let map = match self.peek() {
                    Some(Token::Word(w)) if w == "string" => {
                        self.pos += 1;
                        true
                    }
                    _ => false,
                };
                self.expect_punct("]")?;
                let inner = self.parse_type()?;
                if matches!(inner, Type::Nullable(_)) {
                    return Err(self.error("array and map elements cannot be nullable"));
                }
                Ok(if map {
                    Type::Map(Box::new(inner))
                } else {
                    Type::Array(Box::new(inner))
                })
            }
            Some(Token::Punct("(")) => self.parse_struct_or_enum(),
            Some(Token::Word(_)) => {
                let w = self.word()?;
                Ok(match w.as_str() {
                    "bool" => Type::Bool,
                    "int" => Type::Int,
                    "float" => Type::Float,
                    "string" => Type::String,
                    "object" => Type::Object,
                    "any" => Type::Any,
                    _ => {
                        if !valid_type_name(&w) {
                            return Err(self.error(format!("invalid type name '{}'", w)));
                        }
                        Type::Named(w)
                    }
                })
            }
            other => Err(self.error(format!("expected a type, found {:?}", other))),
        }
    }

    /// Parses `( ... )`: a struct if fields have types, an enum otherwise.
    fn parse_struct_or_enum(&mut self) -> Result<Type, Error> {
        self.expect_punct("(")?;
        self.skip_newlines();
        if self.peek() == Some(&Token::Punct(")")) {
            self.pos += 1;
            return Ok(Type::Struct(Vec::new()));
        }
        let mut fields = Vec::new();
        let mut values = Vec::new();
        loop {
            self.skip_newlines();
            let name = self.word()?;
            if !valid_field_name(&name) {
                return Err(self.error(format!("invalid field name '{}'", name)));
            }
            self.skip_newlines();
            if self.peek() == Some(&Token::Punct(":")) {
                self.pos += 1;
                self.skip_newlines();
                let ty = self.parse_type()?;
                fields.push(Field { name, ty });
            } else {
                values.push(name);
            }
            self.skip_newlines();
            match self.next_token() {
                Some(Token::Punct(",")) => continue,
                Some(Token::Punct(")")) => break,
                other => return Err(self.error(format!("expected ',' or ')', found {:?}", other))),
            }
        }
        match (fields.is_empty(), values.is_empty()) {
            (false, true) => Ok(Type::Struct(fields)),
            (true, false) => Ok(Type::Enum(values)),
            _ => Err(self.error("mixed struct fields and enum values")),
        }
    }

    fn fields(&mut self, ty: Type) -> Result<Vec<Field>, Error> {
        match ty {
            Type::Struct(f) => Ok(f),
            _ => Err(self.error("expected a parameter list")),
        }
    }
}

fn valid_type_name(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_uppercase()) && chars.all(|c| c.is_ascii_alphanumeric())
}

fn valid_field_name(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.is_empty() || !bytes[0].is_ascii_alphabetic() || bytes.last() == Some(&b'_') {
        return false;
    }
    let mut prev_underscore = false;
    for &b in &bytes[1..] {
        if b == b'_' {
            if prev_underscore {
                return false;
            }
            prev_underscore = true;
        } else if b.is_ascii_alphanumeric() {
            prev_underscore = false;
        } else {
            return false;
        }
    }
    true
}

/// Whether `s` is a valid interface name: reverse domain notation.
pub fn valid_interface_name(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() < 2 {
        return false;
    }
    parts.iter().enumerate().all(|(i, p)| {
        let bytes = p.as_bytes();
        !bytes.is_empty()
            && (bytes[0].is_ascii_alphabetic() || (i > 0 && bytes[0].is_ascii_digit()))
            && bytes.last() != Some(&b'-')
            && bytes.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'-')
    })
}

/// The flag markers sd-varlink renders as comments right above a method,
/// e.g. `# [Requires 'more' flag]`, joined per method name.
fn method_markers(text: &str) -> BTreeMap<String, String> {
    let mut markers = BTreeMap::new();
    let mut pending = String::new();
    for line in text.lines() {
        let t = line.trim();
        if let Some(comment) = t.strip_prefix('#') {
            if comment.contains("flag]") {
                pending.push_str(comment);
            }
        } else if let Some(rest) = t.strip_prefix("method ") {
            let name: String = rest.chars().take_while(char::is_ascii_alphanumeric).collect();
            markers.insert(name, std::mem::take(&mut pending));
        } else {
            pending.clear();
        }
    }
    markers
}

/// Parses an interface description.
pub fn parse(text: &str) -> Result<Interface, Error> {
    let markers = method_markers(text);
    let mut lexer = Lexer { text, pos: 0, line: 1 };
    let mut tokens = Vec::new();
    while let Some(t) = lexer.next_token()? {
        tokens.push((t, lexer.line));
    }
    let mut p = Parser { tokens, pos: 0 };
    p.skip_newlines();
    if p.word()? != "interface" {
        return Err(p.error("expected 'interface'"));
    }
    let name = p.word()?;
    if !valid_interface_name(&name) {
        return Err(p.error(format!("invalid interface name '{}'", name)));
    }
    let mut iface = Interface {
        name,
        text: text.to_string(),
        types: BTreeMap::new(),
        methods: BTreeMap::new(),
        errors: BTreeMap::new(),
    };
    loop {
        p.skip_newlines();
        let keyword = match p.next_token() {
            None => break,
            Some(Token::Word(w)) => w,
            Some(other) => return Err(p.error(format!("expected a declaration, found {:?}", other))),
        };
        let name = p.word()?;
        if !valid_type_name(&name) {
            return Err(p.error(format!("invalid name '{}'", name)));
        }
        if iface.types.contains_key(&name) || iface.methods.contains_key(&name) || iface.errors.contains_key(&name) {
            return Err(p.error(format!("'{}' is declared twice", name)));
        }
        match keyword.as_str() {
            "type" => {
                let ty = p.parse_struct_or_enum()?;
                iface.types.insert(name, ty);
            }
            "method" => {
                let input = p.parse_struct_or_enum()?;
                let input = p.fields(input)?;
                p.expect_punct("->")?;
                let output = p.parse_struct_or_enum()?;
                let output = p.fields(output)?;
                let markers = markers.get(&name).map_or("", String::as_str);
                iface.methods.insert(
                    name,
                    Method {
                        input,
                        output,
                        supports_more: markers.contains("[Supports 'more' flag]"),
                        requires_more: markers.contains("[Requires 'more' flag]"),
                        supports_upgrade: markers.contains("[Supports 'upgrade' flag]"),
                        requires_upgrade: markers.contains("[Requires 'upgrade' flag]"),
                    },
                );
            }
            "error" => {
                let params = p.parse_struct_or_enum()?;
                let params = p.fields(params)?;
                iface.errors.insert(name, params);
            }
            other => return Err(p.error(format!("unknown keyword '{}'", other))),
        }
    }
    // Every named type must exist.
    let mut referenced = Vec::new();
    for t in iface.types.values() {
        collect_named(t, &mut referenced);
    }
    for m in iface.methods.values() {
        for f in m.input.iter().chain(&m.output) {
            collect_named(&f.ty, &mut referenced);
        }
    }
    for e in iface.errors.values() {
        for f in e {
            collect_named(&f.ty, &mut referenced);
        }
    }
    for n in referenced {
        if !iface.types.contains_key(&n) {
            return Err(Error {
                line: 0,
                message: format!("type '{}' is not declared", n),
            });
        }
    }
    Ok(iface)
}

fn collect_named(ty: &Type, out: &mut Vec<String>) {
    match ty {
        Type::Named(n) => out.push(n.clone()),
        Type::Struct(fields) => fields.iter().for_each(|f| collect_named(&f.ty, out)),
        Type::Array(t) | Type::Map(t) | Type::Nullable(t) => collect_named(t, out),
        _ => {}
    }
}

impl Interface {
    /// Checks `params` against `fields`, the declared parameters of a method
    /// or error. Returns the name of the first offending parameter: one that
    /// is missing, unknown, or of the wrong type.
    pub fn validate<'a>(&self, fields: &'a [Field], params: &'a Object) -> Result<(), &'a str> {
        // Declared fields first, unknown keys second, like sd-varlink.
        for f in fields {
            let value = params.get(&f.name).unwrap_or(&Value::Null);
            if !self.matches(&f.ty, value) {
                return Err(&f.name);
            }
        }
        for key in params.keys() {
            if !fields.iter().any(|f| f.name == key) {
                return Err(key);
            }
        }
        Ok(())
    }

    /// Whether `value` conforms to `ty`.
    pub fn matches(&self, ty: &Type, value: &Value) -> bool {
        match ty {
            Type::Nullable(inner) => value.is_null() || self.matches(inner, value),
            _ if value.is_null() => false,
            Type::Bool => matches!(value, Value::Bool(_)),
            // Integers beyond the JSON number range may arrive as strings.
            Type::Int => match value {
                Value::Int(_) => true,
                Value::String(s) => s.parse::<i128>().is_ok(),
                _ => false,
            },
            Type::Float => matches!(value, Value::Int(_) | Value::Float(_)),
            Type::String => matches!(value, Value::String(_)),
            Type::Object => matches!(value, Value::Object(_)),
            Type::Any => true,
            Type::Enum(values) => value.as_str().is_some_and(|s| values.iter().any(|v| v == s)),
            Type::Struct(fields) => match value {
                Value::Object(o) => self.validate(fields, o).is_ok(),
                _ => false,
            },
            Type::Named(name) => self.types.get(name).is_some_and(|t| self.matches(t, value)),
            Type::Array(inner) => match value {
                Value::Array(items) => items.iter().all(|i| !i.is_null() && self.matches(inner, i)),
                _ => false,
            },
            Type::Map(inner) => match value {
                Value::Object(o) => o.iter().all(|(_, v)| !v.is_null() && self.matches(inner, v)),
                _ => false,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = "\
# A test interface
interface org.example.Test

type Mode (fast, slow)

type Entry (
	# the name
	name: string,
	size: ?int,
	tags: []string,
	attrs: [string]int
)

method Run(mode: Mode, entries: ?[]Entry, options: ?object) -> (count: int, nested: (a: bool, b: ?float))

method Nothing() -> ()

error Failed(reason: string)
";

    #[test]
    fn parses_example() {
        let i = parse(EXAMPLE).unwrap();
        assert_eq!(i.name, "org.example.Test");
        assert_eq!(i.types.len(), 2);
        assert_eq!(i.methods.len(), 2);
        assert_eq!(i.errors.len(), 1);
        let run = &i.methods["Run"];
        assert_eq!(run.input.len(), 3);
        assert_eq!(run.output[1].name, "nested");
        assert!(matches!(i.types["Mode"], Type::Enum(_)));
        assert_eq!(
            parse(include_str!("org.varlink.service.varlink"))
                .unwrap()
                .methods
                .len(),
            2
        );
        assert_eq!(parse(include_str!("io.systemd.varlink")).unwrap().errors.len(), 5);
    }

    #[test]
    fn rejects_bad_idl() {
        for bad in [
            "method X() -> ()",
            "interface test\n",
            "interface org.example\ntype x ()",
            "interface org.example\nmethod A() -> ()\nmethod A() -> ()",
            "interface org.example\nmethod A(x: Unknown) -> ()",
            "interface org.example\ntype T (a: ?[]?int)",
            "interface org.example\ntype T (a: int, b)",
            "interface org.example\nmethod A(bad_: int) -> ()",
        ] {
            assert!(parse(bad).is_err(), "{:?} accepted", bad);
        }
    }

    #[test]
    fn validation() {
        let i = parse(EXAMPLE).unwrap();
        let run = &i.methods["Run"];
        let ok = json::parse(r#"{"mode":"fast","entries":[{"name":"a","tags":[],"attrs":{"x":1}}]}"#).unwrap();
        assert_eq!(i.validate(&run.input, ok.as_object().unwrap()), Ok(()));
        let ok = json::parse(r#"{"mode":"slow","entries":null}"#).unwrap();
        assert_eq!(i.validate(&run.input, ok.as_object().unwrap()), Ok(()));
        for (text, field) in [
            (r#"{}"#, "mode"),
            (r#"{"mode":"medium"}"#, "mode"),
            (r#"{"mode":"fast","bogus":1}"#, "bogus"),
            (r#"{"mode":"fast","entries":[{"tags":[]}]}"#, "entries"),
            (
                r#"{"mode":"fast","entries":[{"name":"a","tags":[null],"attrs":{}}]}"#,
                "entries",
            ),
            (r#"{"mode":"fast","options":5}"#, "options"),
        ] {
            let v = json::parse(text).unwrap();
            assert_eq!(i.validate(&run.input, v.as_object().unwrap()), Err(field), "{}", text);
        }
        assert!(i.matches(&Type::Int, &Value::from("18446744073709551616")));
        assert!(!i.matches(&Type::Int, &Value::from("x")));
        assert!(i.matches(&Type::Float, &Value::from(1u32)));
        assert!(!i.matches(&Type::Any, &Value::Null));
    }

    #[test]
    fn names() {
        assert!(valid_interface_name("org.varlink.service"));
        assert!(valid_interface_name("org.uapi-group.FileSystem"));
        assert!(valid_interface_name("a.0b"));
        assert!(!valid_interface_name("single"));
        assert!(!valid_interface_name("a..b"));
        assert!(!valid_interface_name("a.-b"));
        assert!(!valid_interface_name("1a.b"));
        assert!(valid_field_name("a_b1"));
        assert!(!valid_field_name("a__b"));
        assert!(!valid_field_name("_a"));
        assert!(!valid_field_name("a_"));
    }
}
