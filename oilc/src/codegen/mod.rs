pub mod cypher;

use crate::mid::MirProgram;
pub use cypher::{emit_cypher_program, CypherArtifact, CypherProgram};

#[derive(Debug, Clone, Default)]
pub struct CodegenOutput {
    pub cypher: CypherProgram,
}

pub fn generate_backends(mir: &MirProgram) -> CodegenOutput {
    CodegenOutput {
        cypher: emit_cypher_program(mir),
    }
}
