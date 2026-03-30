use std::collections::BTreeMap;

// Typed schema model used by resolver/type-checker.
//
// Design notes:
// - `roots` map symbolic roots (host/process/...) to entity names.
// - `entities` define field-by-field contracts.
// - parser here is intentionally small and purpose-built for schema.oil.

/// Parsed stdlib schema registry consumed by resolver/type-checker.
#[derive(Debug, Clone, Default)]
pub struct SchemaRegistry {
    // Root identifiers available in expressions (e.g. `host.id`).
    pub roots: BTreeMap<String, RootSchema>,
    // Entity definitions keyed by entity name.
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

/// Typed field model used by semantic passes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldType {
    // Primitive scalar types.
    Primitive(PrimitiveType),
    // Named entity type.
    Entity(String),
    // Set<T>
    Set(Box<FieldType>),
    // Nullable T? wrapper
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
    // Fast root existence check used by resolver.
    pub fn is_root(&self, name: &str) -> bool {
        self.roots.contains_key(name)
    }
}

/// Parse `schema.oil`-style declarations into a typed registry.
pub fn parse_schema(source: &str) -> Result<SchemaRegistry, Vec<SchemaError>> {
    let mut parser = SchemaParser::new(source);
    parser.parse();
    if parser.errors.is_empty() {
        Ok(parser.registry)
    } else {
        Err(parser.errors)
    }
}

struct SchemaParser<'a> {
    // Original source text, used line-by-line.
    source: &'a str,
    // Output registry being constructed.
    registry: SchemaRegistry,
    // Non-fatal parse errors.
    errors: Vec<SchemaError>,
}

impl<'a> SchemaParser<'a> {
    fn new(source: &'a str) -> Self {
        Self {
            source,
            registry: SchemaRegistry::default(),
            errors: Vec::new(),
        }
    }

    fn parse(&mut self) {
        // While inside an `entity ... { ... }` block, we keep mutable state here.
        let mut current_entity: Option<EntitySchema> = None;

        for (line_no, raw_line) in self.source.lines().enumerate() {
            let line_no = line_no + 1;
            let (line, col_offset) = strip_comment(raw_line);
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            // Entity field parsing mode.
            if let Some(entity) = current_entity.as_mut() {
                if trimmed == "}" {
                    let completed = current_entity.take().expect("entity exists");
                    if self.registry.entities.contains_key(&completed.name) {
                        self.error(
                            line_no,
                            col_offset + 1,
                            format!("duplicate entity '{}'", completed.name),
                        );
                    } else {
                        self.registry
                            .entities
                            .insert(completed.name.clone(), completed);
                    }
                    continue;
                }

                match parse_field_decl(trimmed) {
                    Ok((field_name, field_ty)) => {
                        if entity.fields.contains_key(&field_name) {
                            self.error(
                                line_no,
                                col_offset + 1,
                                format!(
                                    "duplicate field '{}' in entity '{}'",
                                    field_name, entity.name
                                ),
                            );
                        } else {
                            entity.fields.insert(
                                field_name.clone(),
                                FieldSchema {
                                    name: field_name,
                                    ty: field_ty,
                                },
                            );
                        }
                    }
                    Err(msg) => self.error(line_no, col_offset + 1, msg),
                }
                continue;
            }

            // Top-level `root` declaration.
            if let Some(rest) = trimmed.strip_prefix("root ") {
                match parse_root_decl(rest) {
                    Ok((name, entity)) => {
                        if self.registry.roots.contains_key(&name) {
                            self.error(
                                line_no,
                                col_offset + 1,
                                format!("duplicate root '{}'", name),
                            );
                        } else {
                            self.registry
                                .roots
                                .insert(name.clone(), RootSchema { name, entity });
                        }
                    }
                    Err(msg) => self.error(line_no, col_offset + 1, msg),
                }
                continue;
            }

            // Top-level `entity` declaration header.
            if let Some(rest) = trimmed.strip_prefix("entity ") {
                match parse_entity_header(rest) {
                    Ok(name) => {
                        current_entity = Some(EntitySchema {
                            name,
                            fields: BTreeMap::new(),
                        });
                    }
                    Err(msg) => self.error(line_no, col_offset + 1, msg),
                }
                continue;
            }

            self.error(
                line_no,
                col_offset + 1,
                "unexpected top-level schema token".to_string(),
            );
        }

        // EOF reached while still inside an entity block.
        if let Some(entity) = current_entity {
            self.error(
                self.source.lines().count(),
                1,
                format!("unterminated entity '{}'", entity.name),
            );
        }
    }

    fn error(&mut self, line: usize, col: usize, message: String) {
        self.errors.push(SchemaError { line, col, message });
    }
}

// Removes trailing `//` comment text for this line.
fn strip_comment(line: &str) -> (&str, usize) {
    if let Some(pos) = line.find("//") {
        (&line[..pos], 0)
    } else {
        (line, 0)
    }
}

fn parse_root_decl(rest: &str) -> Result<(String, String), String> {
    let (name, entity) = rest
        .split_once(':')
        .ok_or_else(|| "expected ':' in root declaration".to_string())?;
    let name = name.trim().to_string();
    let entity = entity.trim().trim_end_matches(',').trim().to_string();
    if name.is_empty() {
        return Err("expected root name".to_string());
    }
    if entity.is_empty() {
        return Err("expected root entity type".to_string());
    }
    Ok((name, entity))
}

// Parses `entity <Name> {`
fn parse_entity_header(rest: &str) -> Result<String, String> {
    let mut header = rest.trim();
    if !header.ends_with('{') {
        return Err("expected '{' after entity name".to_string());
    }
    header = header[..header.len() - 1].trim();
    if header.is_empty() {
        return Err("expected entity name".to_string());
    }
    Ok(header.to_string())
}

// Parses `<field_name>: <field_type>,`
fn parse_field_decl(line: &str) -> Result<(String, FieldType), String> {
    let (name, ty) = line
        .split_once(':')
        .ok_or_else(|| "expected ':' in field declaration".to_string())?;
    let name = name.trim().to_string();
    let ty = ty.trim().trim_end_matches(',').trim();
    if name.is_empty() {
        return Err("expected field name".to_string());
    }
    if ty.is_empty() {
        return Err("expected field type".to_string());
    }
    Ok((name, parse_field_type(ty)?))
}

// Recursive field type parser supporting:
// - Primitive
// - Entity
// - Nullable suffix `?`
// - Set<T>
fn parse_field_type(raw: &str) -> Result<FieldType, String> {
    let ty = raw.trim();

    if let Some(inner) = ty.strip_suffix('?') {
        return Ok(FieldType::Nullable(Box::new(parse_field_type(
            inner.trim(),
        )?)));
    }

    if let Some(inner) = ty.strip_prefix("Set<") {
        if !inner.ends_with('>') {
            return Err(format!("invalid set type syntax '{ty}'"));
        }
        let inner = &inner[..inner.len() - 1];
        return Ok(FieldType::Set(Box::new(parse_field_type(inner.trim())?)));
    }

    let primitive = match ty {
        "Str" => Some(PrimitiveType::Str),
        "Int" => Some(PrimitiveType::Int),
        "Float" => Some(PrimitiveType::Float),
        "Bool" => Some(PrimitiveType::Bool),
        "Duration" => Some(PrimitiveType::Duration),
        "Path" => Some(PrimitiveType::Path),
        "IpAddr" => Some(PrimitiveType::IpAddr),
        _ => None,
    };

    if let Some(p) = primitive {
        Ok(FieldType::Primitive(p))
    } else {
        Ok(FieldType::Entity(ty.to_string()))
    }
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
        let reg = parse_schema(src).expect("schema should parse");
        assert!(reg.is_root("host"));
        let host = reg.entities.get("Host").expect("Host entity");
        assert!(host.fields.contains_key("id"));
        assert!(matches!(host.fields["tags"].ty, FieldType::Set(_)));
    }
}
