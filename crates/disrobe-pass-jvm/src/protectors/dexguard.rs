use crate::error::{Error, Result};
use crate::protectors::{ProtectorFamily, ProtectorPeelReport};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DexGuardAuthorization(());

impl DexGuardAuthorization {
    #[inline]
    #[must_use]
    pub const fn user_attested() -> Self {
        Self(())
    }
}

pub fn peel(
    dex_bytes: &[u8],
    authorization: Option<DexGuardAuthorization>,
) -> Result<ProtectorPeelReport> {
    if authorization.is_none() {
        return Err(Error::DexGuardRequiresAuthorization);
    }
    if dex_bytes.len() < 8 || &dex_bytes[..4] != b"dex\n" {
        return Err(Error::DexGuardNotDex);
    }
    let mut report: ProtectorPeelReport = ProtectorPeelReport::new(ProtectorFamily::DexGuard);
    report.notes.push(
        "USER-ACTION-REQUIRED: DexGuard evaluation copy needed for full string-decrypt; partial \
         coverage via dex2jar+CFR chain only."
            .to_string(),
    );
    report.strings_residual = scan_residual_encrypted_dex_strings(dex_bytes);
    Ok(report)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CffAnalysis {
    pub suspected_flattened_methods: usize,
    pub dispatcher_switch_methods: usize,
    pub methods_unflattened: usize,
    pub notes: Vec<String>,
}

pub fn undo_cff(
    dex_bytes: &[u8],
    authorization: Option<DexGuardAuthorization>,
) -> Result<CffAnalysis> {
    if authorization.is_none() {
        return Err(Error::DexGuardRequiresAuthorization);
    }
    if dex_bytes.len() < 8 || &dex_bytes[..4] != b"dex\n" {
        return Err(Error::DexGuardNotDex);
    }
    let dex: crate::dex::DexFile = crate::dex::parse(dex_bytes)?;
    let items: Vec<crate::dex::CodeItem> = crate::dex::parse_code_items(&dex, dex_bytes);
    let mut suspected_flattened_methods: usize = 0;
    let mut dispatcher_switch_methods: usize = 0;
    for item in &items {
        let mut packed_switch: usize = 0;
        let mut sparse_switch: usize = 0;
        let mut gotos: usize = 0;
        for &unit in &item.insns {
            match (unit & 0xFF) as u8 {
                0x2B => packed_switch += 1,
                0x2C => sparse_switch += 1,
                0x28..=0x2A => gotos += 1,
                _ => {}
            }
        }
        let switches: usize = packed_switch + sparse_switch;
        if switches >= 1 && gotos >= 6 {
            suspected_flattened_methods += 1;
            dispatcher_switch_methods += switches;
        }
    }
    let notes: Vec<String> = vec![
        "AUTH-GATED detect-only: DexGuard control-flow flattening is characterised structurally; \
         a faithful un-flatten requires a real DexGuard-protected sample (enterprise-gated) to \
         validate against - no synthetic CFG is fabricated."
            .to_string(),
    ];
    Ok(CffAnalysis {
        suspected_flattened_methods,
        dispatcher_switch_methods,
        methods_unflattened: 0,
        notes,
    })
}

#[must_use]
pub fn scan_residual_encrypted_dex_strings(dex_bytes: &[u8]) -> usize {
    if dex_bytes.len() < 0x70 {
        return 0;
    }
    let string_ids_size: u32 = u32::from_le_bytes([
        dex_bytes[0x38],
        dex_bytes[0x39],
        dex_bytes[0x3A],
        dex_bytes[0x3B],
    ]);
    let string_ids_off: u32 = u32::from_le_bytes([
        dex_bytes[0x3C],
        dex_bytes[0x3D],
        dex_bytes[0x3E],
        dex_bytes[0x3F],
    ]);
    let base: usize = string_ids_off as usize;
    let count: usize = string_ids_size as usize;
    if base.saturating_add(count.saturating_mul(4)) > dex_bytes.len() {
        return 0;
    }
    let mut encrypted: usize = 0;
    for i in 0..count {
        let off_pos: usize = base + i * 4;
        let data_off: u32 = u32::from_le_bytes([
            dex_bytes[off_pos],
            dex_bytes[off_pos + 1],
            dex_bytes[off_pos + 2],
            dex_bytes[off_pos + 3],
        ]);
        let data_pos: usize = data_off as usize;
        if data_pos >= dex_bytes.len() {
            continue;
        }
        let mut p: usize = data_pos;
        let mut size: u32 = 0;
        let mut shift: u32 = 0;
        while p < dex_bytes.len() {
            let b: u8 = dex_bytes[p];
            size |= u32::from(b & 0x7F) << shift;
            p += 1;
            if b & 0x80 == 0 {
                break;
            }
            shift += 7;
            if shift > 28 {
                break;
            }
        }
        let str_end: usize = p.saturating_add(size as usize).min(dex_bytes.len());
        if p >= str_end {
            continue;
        }
        let slice: &[u8] = &dex_bytes[p..str_end];
        let non_print: usize = slice
            .iter()
            .filter(|b: &&u8| **b < 0x20 || **b > 0x7E)
            .count();
        if slice.len() >= 4 && (non_print as f64 / slice.len() as f64) > 0.5 {
            encrypted += 1;
        }
    }
    encrypted
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn no_auth_yields_error() {
        let bytes: &[u8] = b"dex\n035\x00";
        let err: Error = peel(bytes, None).expect_err("auth required");
        assert!(matches!(err, Error::DexGuardRequiresAuthorization));
    }

    #[test]
    fn non_dex_input_rejected() {
        let bytes: &[u8] = b"not a dex file at all";
        let err: Error =
            peel(bytes, Some(DexGuardAuthorization::user_attested())).expect_err("not dex");
        assert!(matches!(err, Error::DexGuardNotDex));
    }

    #[test]
    fn minimal_dex_header_returns_report_with_user_action_note() {
        let mut bytes: Vec<u8> = b"dex\n035\x00".to_vec();
        bytes.extend(std::iter::repeat_n(0u8, 0x80));
        let report: ProtectorPeelReport =
            peel(&bytes, Some(DexGuardAuthorization::user_attested())).expect("ok");
        assert_eq!(report.family, ProtectorFamily::DexGuard);
        assert!(
            report
                .notes
                .iter()
                .any(|n: &String| n.contains("USER-ACTION-REQUIRED"))
        );
    }
}
