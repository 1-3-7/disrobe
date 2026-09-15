#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Assoc {
    Left,
    Right,
    None,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Side {
    Left,
    Right,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Precedence(pub u8);

impl Precedence {
    pub const ATOM: Self = Self(u8::MAX);

    #[must_use]
    pub const fn tighter_than(self, other: Self) -> bool {
        self.0 > other.0
    }
}

#[must_use]
pub const fn parenthesize_operand(
    child: Precedence,
    parent: Precedence,
    parent_assoc: Assoc,
    side: Side,
) -> bool {
    if child.0 > parent.0 {
        false
    } else if child.0 < parent.0 {
        true
    } else {
        match (parent_assoc, side) {
            (Assoc::Left, Side::Left) | (Assoc::Right, Side::Right) => false,
            (Assoc::Left, Side::Right) | (Assoc::Right, Side::Left) | (Assoc::None, _) => true,
        }
    }
}
