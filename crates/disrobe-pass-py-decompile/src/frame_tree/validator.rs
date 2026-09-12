use std::ops::Range;

use disrobe_py_marshal::CodeObject;

use crate::error::{DecompileError, Result};
use crate::frame_tree::{Frame, FrameTree};

pub fn validate(tree: &FrameTree, code: &CodeObject) -> Result<()> {
    let code_len: u32 =
        u32::try_from(code.code.len()).map_err(|_| DecompileError::FrameTreeInvariant {
            reason: "code length exceeds u32".to_owned(),
        })?;
    if tree.root.range.start != 0 || tree.root.range.end != code_len {
        return Err(DecompileError::FrameTreeInvariant {
            reason: format!(
                "root range {:?} does not span code [0, {code_len})",
                tree.root.range
            ),
        });
    }
    validate_node(&tree.root)?;
    Ok(())
}

fn validate_node(node: &Frame) -> Result<()> {
    if node.range.start > node.range.end {
        return Err(DecompileError::FrameTreeInvariant {
            reason: format!("inverted range {:?}", node.range),
        });
    }
    let mut prev_end: u32 = node.range.start;
    let mut sorted_children: Vec<&Frame> = node.children.iter().collect();
    sorted_children.sort_by_key(|f: &&Frame| f.range.start);
    for child in &sorted_children {
        if child.range.start < node.range.start || child.range.end > node.range.end {
            return Err(DecompileError::FrameTreeInvariant {
                reason: format!("child {:?} escapes parent {:?}", child.range, node.range),
            });
        }
        if child.range.start < prev_end {
            return Err(DecompileError::FrameTreeInvariant {
                reason: format!(
                    "sibling overlap: prev_end {prev_end} > child.start {}",
                    child.range.start
                ),
            });
        }
        prev_end = child.range.end;
        validate_node(child)?;
    }
    Ok(())
}

#[must_use]
pub fn covers_offset(node: &Frame, offset: u32) -> bool {
    range_contains(&node.range, offset)
}

const fn range_contains(range: &Range<u32>, offset: u32) -> bool {
    offset >= range.start && offset < range.end
}
