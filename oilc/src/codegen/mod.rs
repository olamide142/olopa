pub mod cypher;
pub mod epl;

use crate::mid::MirProgram;
pub use cypher::{emit_cypher_program, CypherArtifact, CypherProgram};
pub use epl::{emit_epl_program, EplArtifact, EplProgram};

#[derive(Debug, Clone, Default)]
pub struct CodegenOutput {
    pub cypher: CypherProgram,
    pub epl: EplProgram,
}

pub fn generate_backends(mir: &MirProgram) -> CodegenOutput {
    CodegenOutput {
        cypher: emit_cypher_program(mir),
        epl: emit_epl_program(mir),
    }
}
