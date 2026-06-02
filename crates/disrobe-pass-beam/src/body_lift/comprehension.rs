//! Re-sugars BEAM-lowered list and binary comprehensions back to surface syntax.
//!
//! The OTP compiler lowers `[Expr || Quals]` into a local recursive helper named
//! `'-Parent/Arity-lc$^N/M-K-'` (and `-lbc$^...` for binary comprehensions) whose
//! body is the canonical cons/nil/`bad_generator` recursion. This module is a
//! placeholder for the surface reconstruction pass wired in a later step.
