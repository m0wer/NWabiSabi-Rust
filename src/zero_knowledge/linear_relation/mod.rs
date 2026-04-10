// Linear relation proofs (to be implemented in Phase 3)
// This module will contain:
// - Equation: Linear equations over group elements
// - Statement: Public statements
// - Knowledge: Private witness data

pub mod equation;
pub mod statement;
pub mod knowledge;

pub use equation::Equation;
pub use statement::Statement;
pub use knowledge::Knowledge;
