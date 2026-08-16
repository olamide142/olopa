//! Typed OIL schema model and Pest-backed parser.

use std::collections::{btree_map::Entry, BTreeMap};

use pest::error::{InputLocation, LineColLocation};
use pest::iterators::Pair;
use pest::Parser as _;
use pest_derive::Parser;

#[derive(Parser)]
#[grammar = "schema/schema.pest"]
struct OilSchemaParser;

/// Parsed stdlib schema registry consumed by resolver/type-checker.
#[derive(Debug, Clone, Default)]
pub struct SchemaRegistry {
    pub roots: BTreeMap<String, RootSchema>,
    pub entities: BTreeMap<String, EntitySchema>,
}

#[derive(Debug, Clone)]
pub struct RootSchema {
    pub name: String,
    pub entity: String,
}

#[derive(Debug, Clone)]
pub struct EntitySchema {
    pub name: String,
    pub fields: BTreeMap<String, FieldSchema>,
}

#[derive(Debug, Clone)]
pub struct FieldSchema {
    pub name: String,
    pub ty: FieldType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldType {
    Primitive(PrimitiveType),
    Entity(String),
    Set(Box<FieldType>),
    Nullable(Box<FieldType>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrimitiveType {
    Str,
    Int,
    Float,
    Bool,
    Duration,
    Path,
    IpAddr,
}

#[derive(Debug, Clone)]
pub struct SchemaError {
    pub line: usize,
    pub col: usize,
    pub message: String,
}

impl SchemaRegistry {
    pub fn is_root(&self, name: &str) -> bool {
        self.roots.contains_key(name)
    }
}

/// Parse `schema.oil` declarations into a typed registry with Pest-provided
/// locations and explicit duplicate validation.
pub fn parse_schema(source: &str) -> Result<SchemaRegistry, Vec<SchemaError>> {
    let mut parsed = OilSchemaParser::parse(Rule::schema, source)
        .map_err(|error| vec![schema_parse_error(error)])?;
    let schema = parsed.next().expect("Pest schema pair");
    let mut registry = SchemaRegistry::default();
    let mut errors = Vec::new();

    for declaration in schema.into_inner() {
        match declaration.as_rule() {
            Rule::root_decl => insert_root(declaration, &mut registry, &mut errors),
            Rule::entity_decl => insert_entity(declaration, &mut registry, &mut errors),
            Rule::EOI => {}
            _ => unreachable!("schema grammar only emits declarations"),
        }
    }

    if errors.is_empty() {
        Ok(registry)
    } else {
        Err(errors)
    }
}

fn insert_root(pair: Pair<'_, Rule>, registry: &mut SchemaRegistry, errors: &mut Vec<SchemaError>) {
    let (line, col) = pair.as_span().start_pos().line_col();
    let mut inner = pair.into_inner();
    let name = inner.next().expect("root name").as_str().to_string();
    let entity = inner.next().expect("root entity").as_str().to_string();
    match registry.roots.entry(name.clone()) {
        Entry::Occupied(_) => errors.push(SchemaError {
            line,
            col,
            message: format!("duplicate root '{name}'"),
        }),
        Entry::Vacant(entry) => {
            entry.insert(RootSchema { name, entity });
        }
    }
}

fn insert_entity(
    pair: Pair<'_, Rule>,
    registry: &mut SchemaRegistry,
    errors: &mut Vec<SchemaError>,
) {
    let (line, col) = pair.as_span().start_pos().line_col();
    let mut inner = pair.into_inner();
    let name = inner.next().expect("entity name").as_str().to_string();
    let mut entity = EntitySchema {
        name: name.clone(),
        fields: BTreeMap::new(),
    };

    for field in inner {
        let (field_line, field_col) = field.as_span().start_pos().line_col();
        let mut field_parts = field.into_inner();
        let field_name = field_parts.next().expect("field name").as_str().to_string();
        let field_type = parse_field_type(field_parts.next().expect("field type"));
        match entity.fields.entry(field_name.clone()) {
            Entry::Occupied(_) => errors.push(SchemaError {
                line: field_line,
                col: field_col,
                message: format!("duplicate field '{field_name}' in entity '{name}'"),
            }),
            Entry::Vacant(entry) => {
                entry.insert(FieldSchema {
                    name: field_name,
                    ty: field_type,
                });
            }
        }
    }

    match registry.entities.entry(name.clone()) {
        Entry::Occupied(_) => errors.push(SchemaError {
            line,
            col,
            message: format!("duplicate entity '{name}'"),
        }),
        Entry::Vacant(entry) => {
            entry.insert(entity);
        }
    }
}

fn parse_field_type(pair: Pair<'_, Rule>) -> FieldType {
    debug_assert_eq!(pair.as_rule(), Rule::field_type);
    let mut parts = pair.into_inner();
    let primary = parts.next().expect("field type primary");
    let mut ty = match primary.as_rule() {
        Rule::set_type => {
            let inner = primary.into_inner().next().expect("Set inner field type");
            FieldType::Set(Box::new(parse_field_type(inner)))
        }
        Rule::identifier => primitive_or_entity(primary.as_str()),
        _ => unreachable!("field type primary"),
    };
    if parts.next().is_some() {
        ty = FieldType::Nullable(Box::new(ty));
    }
    ty
}

fn primitive_or_entity(name: &str) -> FieldType {
    let primitive = match name {
        "Str" => Some(PrimitiveType::Str),
        "Int" => Some(PrimitiveType::Int),
        "Float" => Some(PrimitiveType::Float),
        "Bool" => Some(PrimitiveType::Bool),
        "Duration" => Some(PrimitiveType::Duration),
        "Path" => Some(PrimitiveType::Path),
        "IpAddr" => Some(PrimitiveType::IpAddr),
        _ => None,
    };
    primitive
        .map(FieldType::Primitive)
        .unwrap_or_else(|| FieldType::Entity(name.to_string()))
}

fn schema_parse_error(error: pest::error::Error<Rule>) -> SchemaError {
    let (line, col) = match error.line_col {
        LineColLocation::Pos(location) => location,
        LineColLocation::Span(start, _) => start,
    };
    let message = match error.location {
        InputLocation::Pos(_) | InputLocation::Span(_) => error.to_string(),
    };
    SchemaError { line, col, message }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_schema_entities_and_roots() {
        let src = r#"
root host: Host
entity Host {
  id: Str,
  tags: Set<Str>,
  parent: Host?,
}
"#;
        let registry = parse_schema(src).expect("schema should parse");
        assert!(registry.is_root("host"));
        let host = registry.entities.get("Host").expect("Host entity");
        assert!(host.fields.contains_key("id"));
        assert!(matches!(host.fields["tags"].ty, FieldType::Set(_)));
        assert!(matches!(host.fields["parent"].ty, FieldType::Nullable(_)));
    }

    #[test]
    fn pest_schema_parser_reports_invalid_syntax_with_location() {
        let error = parse_schema("entity Host { id Str }")
            .expect_err("missing colon should fail")
            .remove(0);
        assert_eq!(error.line, 1);
        assert!(error.col > 1);
    }

    #[test]
    fn schema_semantics_reject_duplicates_after_pest_parse() {
        let errors = parse_schema("root host: Host\nroot host: Other\n")
            .expect_err("duplicate root should fail");
        assert!(errors[0].message.contains("duplicate root 'host'"));
        assert_eq!(errors[0].line, 2);
    }
}
