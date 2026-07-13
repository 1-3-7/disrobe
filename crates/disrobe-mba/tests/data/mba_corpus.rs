use disrobe_mba::{Expr, Width};

const PROV_MBA_BLAST: &str =
    "MBA-Blast linear identity (Liu et al., USENIX Security 2021, Table 1)";
const PROV_ZHOU: &str =
    "Zhou et al., Information Hiding in Software with Mixed Boolean-Arithmetic Transforms (2007)";
const PROV_OLLVM: &str = "OLLVM instruction Substitution rewrite (obfuscator-llvm)";
const PROV_LOKI: &str = "Loki linear MBA rewrite rule (Schloegel et al., USENIX Security 2022)";
const PROV_HD: &str = "Hacker's Delight two's-complement identity (Warren)";
const PROV_SYNTIA: &str = "Syntia/QSynth polynomial MBA dataset expansion";

#[derive(Debug, Clone)]
pub(crate) struct CorpusEntry {
    pub(crate) name: &'static str,
    pub(crate) provenance: &'static str,
    pub(crate) e_src: Expr,
    pub(crate) e_obf: Expr,
    pub(crate) width: Width,
}

const fn x() -> Expr {
    Expr::var(0)
}

const fn y() -> Expr {
    Expr::var(1)
}

const fn z() -> Expr {
    Expr::var(2)
}

const fn k(value: u64) -> Expr {
    Expr::konst(value)
}

const fn entry(
    name: &'static str,
    provenance: &'static str,
    e_src: Expr,
    e_obf: Expr,
    width: Width,
) -> CorpusEntry {
    CorpusEntry {
        name,
        provenance,
        e_src,
        e_obf,
        width,
    }
}

pub(crate) fn corpus() -> Vec<CorpusEntry> {
    vec![
        entry(
            "add_xor_carry_w8",
            PROV_OLLVM,
            Expr::add(x(), y()),
            Expr::add(Expr::xor(x(), y()), Expr::mul(k(2), Expr::and(x(), y()))),
            Width::W8,
        ),
        entry(
            "add_xor_carry_w32",
            PROV_OLLVM,
            Expr::add(x(), y()),
            Expr::add(Expr::xor(x(), y()), Expr::mul(k(2), Expr::and(x(), y()))),
            Width::W32,
        ),
        entry(
            "add_xor_carry_w64",
            PROV_HD,
            Expr::add(x(), y()),
            Expr::add(Expr::xor(x(), y()), Expr::mul(k(2), Expr::and(x(), y()))),
            Width::W64,
        ),
        entry(
            "add_or_and_w16",
            PROV_MBA_BLAST,
            Expr::add(x(), y()),
            Expr::add(Expr::or(x(), y()), Expr::and(x(), y())),
            Width::W16,
        ),
        entry(
            "add_or_and_w64",
            PROV_MBA_BLAST,
            Expr::add(x(), y()),
            Expr::add(Expr::or(x(), y()), Expr::and(x(), y())),
            Width::W64,
        ),
        entry(
            "add_2or_minus_xor_w32",
            PROV_MBA_BLAST,
            Expr::add(x(), y()),
            Expr::sub(Expr::mul(k(2), Expr::or(x(), y())), Expr::xor(x(), y())),
            Width::W32,
        ),
        entry(
            "sub_and_andnot_w16",
            PROV_ZHOU,
            Expr::sub(x(), y()),
            Expr::sub(
                Expr::and(x(), Expr::not(y())),
                Expr::and(Expr::not(x()), y()),
            ),
            Width::W16,
        ),
        entry(
            "sub_and_andnot_w64",
            PROV_ZHOU,
            Expr::sub(x(), y()),
            Expr::sub(
                Expr::and(x(), Expr::not(y())),
                Expr::and(Expr::not(x()), y()),
            ),
            Width::W64,
        ),
        entry(
            "sub_2andnot_minus_xor_w8",
            PROV_MBA_BLAST,
            Expr::sub(x(), y()),
            Expr::sub(
                Expr::mul(k(2), Expr::and(x(), Expr::not(y()))),
                Expr::xor(x(), y()),
            ),
            Width::W8,
        ),
        entry(
            "sub_xor_carry_w32",
            PROV_HD,
            Expr::sub(x(), y()),
            Expr::add(
                Expr::xor(x(), Expr::neg(y())),
                Expr::mul(k(2), Expr::and(x(), Expr::neg(y()))),
            ),
            Width::W32,
        ),
        entry(
            "xor_or_minus_and_w8",
            PROV_MBA_BLAST,
            Expr::xor(x(), y()),
            Expr::sub(Expr::or(x(), y()), Expr::and(x(), y())),
            Width::W8,
        ),
        entry(
            "xor_or_minus_and_w32",
            PROV_MBA_BLAST,
            Expr::xor(x(), y()),
            Expr::sub(Expr::or(x(), y()), Expr::and(x(), y())),
            Width::W32,
        ),
        entry(
            "xor_ollvm_sub_w8",
            PROV_OLLVM,
            Expr::xor(x(), y()),
            Expr::or(
                Expr::and(Expr::not(x()), y()),
                Expr::and(x(), Expr::not(y())),
            ),
            Width::W8,
        ),
        entry(
            "xor_or_and_nand_w16",
            PROV_OLLVM,
            Expr::xor(x(), y()),
            Expr::and(Expr::or(x(), y()), Expr::not(Expr::and(x(), y()))),
            Width::W16,
        ),
        entry(
            "and_add_minus_or_w8",
            PROV_MBA_BLAST,
            Expr::and(x(), y()),
            Expr::sub(Expr::add(x(), y()), Expr::or(x(), y())),
            Width::W8,
        ),
        entry(
            "and_add_minus_or_w32",
            PROV_MBA_BLAST,
            Expr::and(x(), y()),
            Expr::sub(Expr::add(x(), y()), Expr::or(x(), y())),
            Width::W32,
        ),
        entry(
            "and_demorgan_w16",
            PROV_OLLVM,
            Expr::and(x(), y()),
            Expr::not(Expr::or(Expr::not(x()), Expr::not(y()))),
            Width::W16,
        ),
        entry(
            "or_add_minus_and_w8",
            PROV_MBA_BLAST,
            Expr::or(x(), y()),
            Expr::sub(Expr::add(x(), y()), Expr::and(x(), y())),
            Width::W8,
        ),
        entry(
            "or_xor_plus_and_w16",
            PROV_ZHOU,
            Expr::or(x(), y()),
            Expr::add(Expr::xor(x(), y()), Expr::and(x(), y())),
            Width::W16,
        ),
        entry(
            "or_demorgan_w32",
            PROV_OLLVM,
            Expr::or(x(), y()),
            Expr::not(Expr::and(Expr::not(x()), Expr::not(y()))),
            Width::W32,
        ),
        entry(
            "ident_and_plus_andnot_w8",
            PROV_LOKI,
            x(),
            Expr::add(Expr::and(x(), y()), Expr::and(x(), Expr::not(y()))),
            Width::W8,
        ),
        entry(
            "not_neg_minus_one_w8",
            PROV_HD,
            Expr::not(x()),
            Expr::sub(Expr::neg(x()), k(1)),
            Width::W8,
        ),
        entry(
            "not_neg_minus_one_w64",
            PROV_HD,
            Expr::not(x()),
            Expr::sub(Expr::neg(x()), k(1)),
            Width::W64,
        ),
        entry(
            "neg_not_plus_one_w16",
            PROV_HD,
            Expr::neg(x()),
            Expr::add(Expr::not(x()), k(1)),
            Width::W16,
        ),
        entry(
            "poly_distrib_x_w8",
            PROV_SYNTIA,
            x(),
            Expr::sub(Expr::mul(x(), Expr::add(y(), k(1))), Expr::mul(x(), y())),
            Width::W8,
        ),
        entry(
            "poly_distrib_x_w64",
            PROV_SYNTIA,
            x(),
            Expr::sub(Expr::mul(x(), Expr::add(y(), k(1))), Expr::mul(x(), y())),
            Width::W64,
        ),
        entry(
            "poly_distrib_2x_w8",
            PROV_SYNTIA,
            Expr::mul(k(2), x()),
            Expr::sub(Expr::mul(x(), Expr::add(y(), k(2))), Expr::mul(x(), y())),
            Width::W8,
        ),
        entry(
            "poly_three_var_zero_w8",
            PROV_SYNTIA,
            k(0),
            Expr::sub(
                Expr::sub(Expr::mul(x(), Expr::add(y(), z())), Expr::mul(x(), y())),
                Expr::mul(x(), z()),
            ),
            Width::W8,
        ),
    ]
}
