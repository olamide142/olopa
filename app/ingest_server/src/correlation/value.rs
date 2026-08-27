//! Dynamic scalar value representation and expression operations for the runtime engine.

use std::fmt;
use std::net::IpAddr;
use regex::Regex;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    Ip(IpAddr),
    DurationNs(u64),
    List(Vec<Value>),
}

impl Value {
    pub fn is_truthy(&self) -> bool {
        match self {
            Value::Null => false,
            Value::Bool(b) => *b,
            Value::Int(n) => *n != 0,
            Value::Float(f) => *f != 0.0 && !f.is_nan(),
            Value::Str(s) => !s.is_empty(),
            Value::Ip(_) => true,
            Value::DurationNs(d) => *d > 0,
            Value::List(l) => !l.is_empty(),
        }
    }

    /// Render as a window-bucket key component.
    ///
    /// Two events join only when their key values render identically, so this
    /// has to be exact: floats keep full precision and `Null` is a distinct
    /// marker rather than an empty string, which a real empty field would also
    /// produce.
    pub fn to_key_string(&self) -> String {
        match self {
            Value::Null => "\u{0}null".to_string(),
            Value::Bool(b) => b.to_string(),
            Value::Int(n) => n.to_string(),
            Value::Float(f) => format!("{f:?}"),
            Value::Str(s) => s.clone(),
            Value::Ip(ip) => ip.to_string(),
            Value::DurationNs(d) => d.to_string(),
            Value::List(items) => items
                .iter()
                .map(|v| v.to_key_string())
                .collect::<Vec<_>>()
                .join("\u{1e}"),
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Int(n) => Some(*n),
            Value::Float(f) => Some(*f as i64),
            Value::DurationNs(d) => Some(*d as i64),
            Value::Str(s) => s.trim().parse().ok(),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Float(f) => Some(*f),
            Value::Int(n) => Some(*n as f64),
            Value::DurationNs(d) => Some(*d as f64),
            Value::Str(s) => s.trim().parse().ok(),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn to_string_lossy(&self) -> String {
        match self {
            Value::Null => String::new(),
            Value::Bool(b) => b.to_string(),
            Value::Int(n) => n.to_string(),
            Value::Float(f) => f.to_string(),
            Value::Str(s) => s.clone(),
            Value::Ip(ip) => ip.to_string(),
            Value::DurationNs(d) => format!("{}ns", d),
            Value::List(l) => {
                let items: Vec<String> = l.iter().map(|v| v.to_string_lossy()).collect();
                format!("[{}]", items.join(", "))
            }
        }
    }

    pub fn op_eq(&self, other: &Value) -> bool {
        match (self, other) {
            (Value::Null, Value::Null) => true,
            (Value::Bool(a), Value::Bool(b)) => a == b,
            (Value::Int(a), Value::Int(b)) => a == b,
            (Value::Float(a), Value::Float(b)) => (a - b).abs() < f64::EPSILON,
            (Value::Int(a), Value::Float(b)) | (Value::Float(b), Value::Int(a)) => {
                (*a as f64 - b).abs() < f64::EPSILON
            }
            (Value::Str(a), Value::Str(b)) => a == b,
            (Value::Ip(a), Value::Ip(b)) => a == b,
            (Value::DurationNs(a), Value::DurationNs(b)) => a == b,
            (Value::List(a), Value::List(b)) => a == b,
            // Cross-type string/ip comparisons
            (Value::Ip(a), Value::Str(b)) | (Value::Str(b), Value::Ip(a)) => {
                b.parse::<IpAddr>().map(|ip| &ip == a).unwrap_or(false)
            }
            // Cross-type string/int comparisons
            (Value::Int(a), Value::Str(b)) | (Value::Str(b), Value::Int(a)) => {
                b.parse::<i64>().map(|n| n == *a).unwrap_or(false)
            }
            _ => false,
        }
    }

    pub fn op_ne(&self, other: &Value) -> bool {
        !self.op_eq(other)
    }

    pub fn op_lt(&self, other: &Value) -> bool {
        match (self, other) {
            (Value::Int(a), Value::Int(b)) => a < b,
            (Value::Float(a), Value::Float(b)) => a < b,
            (Value::Int(a), Value::Float(b)) => (*a as f64) < *b,
            (Value::Float(a), Value::Int(b)) => *a < (*b as f64),
            (Value::DurationNs(a), Value::DurationNs(b)) => a < b,
            (Value::Str(a), Value::Str(b)) => a < b,
            _ => false,
        }
    }

    pub fn op_le(&self, other: &Value) -> bool {
        self.op_eq(other) || self.op_lt(other)
    }

    pub fn op_gt(&self, other: &Value) -> bool {
        match (self, other) {
            (Value::Int(a), Value::Int(b)) => a > b,
            (Value::Float(a), Value::Float(b)) => a > b,
            (Value::Int(a), Value::Float(b)) => (*a as f64) > *b,
            (Value::Float(a), Value::Int(b)) => *a > (*b as f64),
            (Value::DurationNs(a), Value::DurationNs(b)) => a > b,
            (Value::Str(a), Value::Str(b)) => a > b,
            _ => false,
        }
    }

    pub fn op_ge(&self, other: &Value) -> bool {
        self.op_eq(other) || self.op_gt(other)
    }

    pub fn op_add(&self, other: &Value) -> Value {
        match (self, other) {
            (Value::Int(a), Value::Int(b)) => Value::Int(a.saturating_add(*b)),
            (Value::Float(a), Value::Float(b)) => Value::Float(a + b),
            (Value::Int(a), Value::Float(b)) => Value::Float(*a as f64 + b),
            (Value::Float(a), Value::Int(b)) => Value::Float(a + *b as f64),
            (Value::DurationNs(a), Value::DurationNs(b)) => {
                Value::DurationNs(a.saturating_add(*b))
            }
            (Value::Str(a), Value::Str(b)) => Value::Str(format!("{}{}", a, b)),
            _ => Value::Null,
        }
    }

    pub fn op_sub(&self, other: &Value) -> Value {
        match (self, other) {
            (Value::Int(a), Value::Int(b)) => Value::Int(a.saturating_sub(*b)),
            (Value::Float(a), Value::Float(b)) => Value::Float(a - b),
            (Value::Int(a), Value::Float(b)) => Value::Float(*a as f64 - b),
            (Value::Float(a), Value::Int(b)) => Value::Float(a - *b as f64),
            (Value::DurationNs(a), Value::DurationNs(b)) => {
                Value::DurationNs(a.saturating_sub(*b))
            }
            _ => Value::Null,
        }
    }

    pub fn op_mul(&self, other: &Value) -> Value {
        match (self, other) {
            (Value::Int(a), Value::Int(b)) => Value::Int(a.saturating_mul(*b)),
            (Value::Float(a), Value::Float(b)) => Value::Float(a * b),
            (Value::Int(a), Value::Float(b)) => Value::Float(*a as f64 * b),
            (Value::Float(a), Value::Int(b)) => Value::Float(a * *b as f64),
            _ => Value::Null,
        }
    }

    pub fn op_div(&self, other: &Value) -> Value {
        match (self, other) {
            (Value::Int(a), Value::Int(b)) if *b != 0 => Value::Int(a / b),
            (Value::Float(a), Value::Float(b)) if *b != 0.0 => Value::Float(a / b),
            (Value::Int(a), Value::Float(b)) if *b != 0.0 => Value::Float(*a as f64 / b),
            (Value::Float(a), Value::Int(b)) if *b != 0 => Value::Float(a / *b as f64),
            _ => Value::Null,
        }
    }

    pub fn op_in(&self, list: &[Value]) -> bool {
        list.iter().any(|item| item.op_eq(self))
    }

    pub fn op_contains(&self, target: &Value) -> bool {
        match (self, target) {
            (Value::Str(haystack), Value::Str(needle)) => haystack.contains(needle.as_str()),
            (Value::List(items), item) => items.iter().any(|elem| elem.op_eq(item)),
            _ => false,
        }
    }

    pub fn op_starts_with(&self, prefix: &Value) -> bool {
        match (self, prefix) {
            (Value::Str(s), Value::Str(p)) => s.starts_with(p.as_str()),
            _ => false,
        }
    }

    pub fn op_ends_with(&self, suffix: &Value) -> bool {
        match (self, suffix) {
            (Value::Str(s), Value::Str(sub)) => s.ends_with(sub.as_str()),
            _ => false,
        }
    }

    pub fn op_matches(&self, pattern: &str) -> bool {
        let Value::Str(text) = self else {
            return false;
        };

        // Quick check if pattern is a glob like "/home/*/.ssh/id_rsa"
        if pattern.contains('*') || pattern.contains('?') {
            if glob_match(pattern, text) {
                return true;
            }
        }

        // Try regex match
        if let Ok(re) = Regex::new(pattern) {
            return re.is_match(text);
        }

        text.contains(pattern)
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string_lossy())
    }
}

/// Simple, high-performance glob matching (* and ?).
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let mut p_idx = 0;
    let mut t_idx = 0;
    let mut star_idx = None;
    let mut match_idx = 0;

    let p_bytes = pattern.as_bytes();
    let t_bytes = text.as_bytes();

    while t_idx < t_bytes.len() {
        if p_idx < p_bytes.len() && (p_bytes[p_idx] == b'?' || p_bytes[p_idx] == t_bytes[t_idx]) {
            p_idx += 1;
            t_idx += 1;
        } else if p_idx < p_bytes.len() && p_bytes[p_idx] == b'*' {
            star_idx = Some(p_idx);
            p_idx += 1;
            match_idx = t_idx;
        } else if let Some(star) = star_idx {
            p_idx = star + 1;
            match_idx += 1;
            t_idx = match_idx;
        } else {
            return false;
        }
    }

    while p_idx < p_bytes.len() && p_bytes[p_idx] == b'*' {
        p_idx += 1;
    }

    p_idx == p_bytes.len()
}
