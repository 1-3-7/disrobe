use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerIdentifier, SignerInfo};
use const_oid::ObjectIdentifier;
use der::asn1::{Any, OctetString};
use der::{Decode, Encode, Sequence};
use rsa::RsaPublicKey;
use rsa::pkcs1::DecodeRsaPublicKey;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use signature::Verifier;
use signature::hazmat::PrehashVerifier;
use spki::AlgorithmIdentifierOwned;
use x509_cert::certificate::Certificate;

use crate::packers::pe_sections::{read_u16, read_u32};

const OID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
const OID_SPC_INDIRECT_DATA: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.1.4");
const OID_MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
const OID_SIGNING_TIME: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.5");
const OID_COUNTER_SIGNATURE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.6");
const OID_RFC3161_TIMESTAMP: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.3.3.1");
const OID_BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");

const OID_SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
const OID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const OID_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
const OID_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");

const OID_RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const OID_RSA_SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.5");
const OID_RSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const OID_RSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
const OID_RSA_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");
const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const OID_ECDSA_SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.1");
const OID_ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const OID_ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
const OID_ECDSA_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4");
const OID_EC_P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const OID_EC_P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");

const WIN_CERT_TYPE_PKCS_SIGNED_DATA: u16 = 0x0002;
const SECURITY_DIR_INDEX: usize = 4;
const OPT_CHECKSUM_OFFSET: usize = 0x40;
const SECURITY_DIR_OFFSET_PE32: usize = 128;
const SECURITY_DIR_OFFSET_PE32_PLUS: usize = 144;
const OPT_MAGIC_PE32: u16 = 0x010B;
const OPT_MAGIC_PE32_PLUS: u16 = 0x020B;
const MAX_CHAIN_DEPTH: usize = 12;

const TRUSTED_ROOTS: &[&[u8]] = &[
    include_bytes!("authenticode_roots/microsoft_root_2010.der"),
    include_bytes!("authenticode_roots/microsoft_root_2011.der"),
    include_bytes!("authenticode_roots/digicert_assured_id_root.der"),
    include_bytes!("authenticode_roots/digicert_global_root.der"),
    include_bytes!("authenticode_roots/digicert_trusted_root_g4.der"),
    include_bytes!("authenticode_roots/digicert_high_assurance_ev_root.der"),
    include_bytes!("authenticode_roots/usertrust_rsa.der"),
    include_bytes!("authenticode_roots/sectigo_public_code_signing_root_r46.der"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthenticodeVerdict {
    MalformedSignature,
    NoSignature,
    HashMismatch,
    Expired,
    SelfSigned,
    UntrustedChain,
    UnsupportedAlgorithm,
    Valid,
}

impl AuthenticodeVerdict {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::MalformedSignature => "malformed signature",
            Self::NoSignature => "no signature",
            Self::HashMismatch => "hash mismatch",
            Self::Expired => "expired signing certificate",
            Self::SelfSigned => "self-signed signing certificate",
            Self::UntrustedChain => "certificate chain not anchored to a bundled root",
            Self::UnsupportedAlgorithm => "unsupported signature algorithm",
            Self::Valid => "valid",
        }
    }

    #[must_use]
    pub const fn is_trusted(self) -> bool {
        matches!(self, Self::Valid)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertInfo {
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub not_before: String,
    pub not_after: String,
    pub is_ca: bool,
    pub self_signed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimestampInfo {
    pub tsa_subject: String,
    pub signing_time: String,
    pub hash_algorithm: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticodeReport {
    pub verdict: AuthenticodeVerdict,
    pub digest_algorithm: String,
    pub computed_hash: String,
    pub claimed_hash: String,
    pub chain: Vec<CertInfo>,
    pub signer_index: usize,
    pub timestamp: Option<TimestampInfo>,
}

impl AuthenticodeReport {
    fn shell(verdict: AuthenticodeVerdict) -> Self {
        Self {
            verdict,
            digest_algorithm: String::new(),
            computed_hash: String::new(),
            claimed_hash: String::new(),
            chain: Vec::new(),
            signer_index: 0,
            timestamp: None,
        }
    }
}

#[derive(Sequence)]
struct SpcIndirectDataContent {
    data: Any,
    message_digest: SpcDigestInfo,
}

#[derive(Sequence)]
struct SpcDigestInfo {
    digest_algorithm: AlgorithmIdentifierOwned,
    digest: OctetString,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DigestKind {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl DigestKind {
    fn from_oid(oid: &ObjectIdentifier) -> Option<Self> {
        match *oid {
            OID_SHA1 => Some(Self::Sha1),
            OID_SHA256 => Some(Self::Sha256),
            OID_SHA384 => Some(Self::Sha384),
            OID_SHA512 => Some(Self::Sha512),
            _ => None,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA-1",
            Self::Sha256 => "SHA-256",
            Self::Sha384 => "SHA-384",
            Self::Sha512 => "SHA-512",
        }
    }

    fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha1 => sha1::Sha1::digest(data).to_vec(),
            Self::Sha256 => sha2::Sha256::digest(data).to_vec(),
            Self::Sha384 => sha2::Sha384::digest(data).to_vec(),
            Self::Sha512 => sha2::Sha512::digest(data).to_vec(),
        }
    }
}

struct HashGeometry {
    checksum_off: usize,
    secdir_entry_off: usize,
    security_offset: usize,
    security_size: usize,
}

#[must_use]
pub fn verify(pe_bytes: &[u8]) -> AuthenticodeReport {
    let Some(geom): Option<HashGeometry> = hash_geometry(pe_bytes) else {
        return AuthenticodeReport::shell(AuthenticodeVerdict::NoSignature);
    };
    if geom.security_offset == 0 || geom.security_size == 0 {
        return AuthenticodeReport::shell(AuthenticodeVerdict::NoSignature);
    }
    let Some(end): Option<usize> = geom.security_offset.checked_add(geom.security_size) else {
        return AuthenticodeReport::shell(AuthenticodeVerdict::MalformedSignature);
    };
    if end > pe_bytes.len() {
        return AuthenticodeReport::shell(AuthenticodeVerdict::MalformedSignature);
    }
    let Some(pkcs7): Option<&[u8]> = first_pkcs7_blob(pe_bytes, geom.security_offset, end) else {
        return AuthenticodeReport::shell(AuthenticodeVerdict::MalformedSignature);
    };
    match verify_signed(pe_bytes, &geom, pkcs7) {
        Ok(report) => report,
        Err(verdict) => AuthenticodeReport::shell(verdict),
    }
}

fn verify_signed(
    pe_bytes: &[u8],
    geom: &HashGeometry,
    pkcs7: &[u8],
) -> Result<AuthenticodeReport, AuthenticodeVerdict> {
    let real_len: usize =
        der_tlv_total_len(pkcs7).ok_or(AuthenticodeVerdict::MalformedSignature)?;
    let pkcs7: &[u8] = pkcs7
        .get(..real_len)
        .ok_or(AuthenticodeVerdict::MalformedSignature)?;
    let content_info: ContentInfo =
        ContentInfo::from_der(pkcs7).map_err(|_| AuthenticodeVerdict::MalformedSignature)?;
    if content_info.content_type != OID_SIGNED_DATA {
        return Err(AuthenticodeVerdict::MalformedSignature);
    }
    let signed_der: Vec<u8> = content_info
        .content
        .to_der()
        .map_err(|_| AuthenticodeVerdict::MalformedSignature)?;
    let signed_data: SignedData =
        SignedData::from_der(&signed_der).map_err(|_| AuthenticodeVerdict::MalformedSignature)?;

    let signer: &SignerInfo = signed_data
        .signer_infos
        .0
        .iter()
        .next()
        .ok_or(AuthenticodeVerdict::MalformedSignature)?;

    let econtent: &Any = signed_data
        .encap_content_info
        .econtent
        .as_ref()
        .ok_or(AuthenticodeVerdict::MalformedSignature)?;
    if signed_data.encap_content_info.econtent_type != OID_SPC_INDIRECT_DATA {
        return Err(AuthenticodeVerdict::MalformedSignature);
    }
    let econtent_der: Vec<u8> = econtent
        .to_der()
        .map_err(|_| AuthenticodeVerdict::MalformedSignature)?;
    let spc: SpcIndirectDataContent = SpcIndirectDataContent::from_der(&econtent_der)
        .map_err(|_| AuthenticodeVerdict::MalformedSignature)?;

    let claimed_hash: &[u8] = spc.message_digest.digest.as_bytes();
    let digest_kind: Option<DigestKind> =
        DigestKind::from_oid(&spc.message_digest.digest_algorithm.oid);
    let Some(digest_kind): Option<DigestKind> = digest_kind else {
        let mut report: AuthenticodeReport =
            AuthenticodeReport::shell(AuthenticodeVerdict::UnsupportedAlgorithm);
        report.claimed_hash = hex_upper(claimed_hash);
        return Ok(report);
    };

    let computed: Vec<u8> = authenticode_digest(pe_bytes, geom, digest_kind);
    let hash_match: bool = computed == claimed_hash;

    let certs: Vec<Certificate> = collect_certificates(&signed_data);
    let chain: Vec<Certificate> = build_chain(&certs, signer);
    let chain_info: Vec<CertInfo> = chain.iter().map(cert_info).collect();
    let timestamp: Option<TimestampInfo> = extract_timestamp(signer);

    let mut report: AuthenticodeReport = AuthenticodeReport {
        verdict: AuthenticodeVerdict::Valid,
        digest_algorithm: digest_kind.label().to_owned(),
        computed_hash: hex_upper(&computed),
        claimed_hash: hex_upper(claimed_hash),
        chain: chain_info,
        signer_index: 0,
        timestamp,
    };

    if !hash_match {
        report.verdict = AuthenticodeVerdict::HashMismatch;
        return Ok(report);
    }

    let signer_state: SignerVerification =
        verify_signer(signer, chain.first(), econtent, &econtent_der);
    match signer_state {
        SignerVerification::Failed => {
            report.verdict = AuthenticodeVerdict::MalformedSignature;
            return Ok(report);
        }
        SignerVerification::Ok | SignerVerification::Unsupported => {}
    }

    let reference_time: i64 = report
        .timestamp
        .as_ref()
        .and_then(|t: &TimestampInfo| parse_iso_to_unix(&t.signing_time))
        .unwrap_or_else(now_unix);

    let Some(leaf): Option<&Certificate> = chain.first() else {
        report.verdict = AuthenticodeVerdict::MalformedSignature;
        return Ok(report);
    };

    if cert_is_expired(leaf, reference_time) {
        report.verdict = AuthenticodeVerdict::Expired;
        return Ok(report);
    }

    if name_eq(&leaf.tbs_certificate.subject, &leaf.tbs_certificate.issuer) {
        report.verdict = AuthenticodeVerdict::SelfSigned;
        return Ok(report);
    }

    if !links_verify(&chain) || !chain_is_anchored(&chain) {
        report.verdict = AuthenticodeVerdict::UntrustedChain;
        return Ok(report);
    }

    if matches!(signer_state, SignerVerification::Unsupported) {
        report.verdict = AuthenticodeVerdict::UnsupportedAlgorithm;
        return Ok(report);
    }

    report.verdict = AuthenticodeVerdict::Valid;
    Ok(report)
}

fn hash_geometry(bytes: &[u8]) -> Option<HashGeometry> {
    if bytes.len() < 0x40 || !bytes.starts_with(b"MZ") {
        return None;
    }
    let e_lfanew: usize = read_u32(bytes, 0x3C).ok()? as usize;
    let coff_off: usize = e_lfanew.checked_add(4)?;
    if bytes.get(e_lfanew..coff_off)? != b"PE\x00\x00" {
        return None;
    }
    let opt_off: usize = coff_off.checked_add(20)?;
    let magic: u16 = read_u16(bytes, opt_off).ok()?;
    let is_pe32_plus: bool = match magic {
        OPT_MAGIC_PE32 => false,
        OPT_MAGIC_PE32_PLUS => true,
        _ => return None,
    };
    let checksum_off: usize = opt_off.checked_add(OPT_CHECKSUM_OFFSET)?;
    let secdir_entry_off: usize = opt_off.checked_add(if is_pe32_plus {
        SECURITY_DIR_OFFSET_PE32_PLUS
    } else {
        SECURITY_DIR_OFFSET_PE32
    })?;
    let number_of_dirs: usize = {
        let count_off: usize = opt_off.checked_add(if is_pe32_plus { 108 } else { 92 })?;
        read_u32(bytes, count_off).ok()? as usize
    };
    if number_of_dirs <= SECURITY_DIR_INDEX {
        return None;
    }
    let security_offset: usize = read_u32(bytes, secdir_entry_off).ok()? as usize;
    let security_size: usize = read_u32(bytes, secdir_entry_off.checked_add(4)?).ok()? as usize;
    Some(HashGeometry {
        checksum_off,
        secdir_entry_off,
        security_offset,
        security_size,
    })
}

fn first_pkcs7_blob(bytes: &[u8], start: usize, end: usize) -> Option<&[u8]> {
    let mut cursor: usize = start;
    while cursor + 8 <= end {
        let dw_length: usize = read_u32(bytes, cursor).ok()? as usize;
        let cert_type: u16 = read_u16(bytes, cursor + 6).ok()?;
        if dw_length < 8 {
            return None;
        }
        let entry_end: usize = cursor.checked_add(dw_length)?;
        if entry_end > end {
            return None;
        }
        if cert_type == WIN_CERT_TYPE_PKCS_SIGNED_DATA {
            return bytes.get(cursor + 8..entry_end);
        }
        let padded: usize = dw_length.checked_add(7)? & !7usize;
        cursor = cursor.checked_add(padded)?;
    }
    None
}

fn authenticode_digest(bytes: &[u8], geom: &HashGeometry, kind: DigestKind) -> Vec<u8> {
    match kind {
        DigestKind::Sha1 => hash_regions::<sha1::Sha1>(bytes, geom),
        DigestKind::Sha256 => hash_regions::<sha2::Sha256>(bytes, geom),
        DigestKind::Sha384 => hash_regions::<sha2::Sha384>(bytes, geom),
        DigestKind::Sha512 => hash_regions::<sha2::Sha512>(bytes, geom),
    }
}

fn hash_regions<D: Digest>(bytes: &[u8], geom: &HashGeometry) -> Vec<u8> {
    let len: usize = bytes.len();
    let clamp = |a: usize, b: usize| -> Option<(usize, usize)> {
        let start: usize = a.min(len);
        let stop: usize = b.min(len);
        if start < stop {
            Some((start, stop))
        } else {
            None
        }
    };
    let mut skips: Vec<(usize, usize)> = Vec::with_capacity(3);
    if let Some(r) = clamp(geom.checksum_off, geom.checksum_off.saturating_add(4)) {
        skips.push(r);
    }
    if let Some(r) = clamp(
        geom.secdir_entry_off,
        geom.secdir_entry_off.saturating_add(8),
    ) {
        skips.push(r);
    }
    if let Some(r) = clamp(
        geom.security_offset,
        geom.security_offset.saturating_add(geom.security_size),
    ) {
        skips.push(r);
    }
    skips.sort_unstable_by_key(|r: &(usize, usize)| r.0);

    let mut hasher: D = D::new();
    let mut pos: usize = 0;
    for (a, b) in skips {
        if a > pos
            && let Some(slice) = bytes.get(pos..a)
        {
            hasher.update(slice);
        }
        pos = pos.max(b);
    }
    if pos < len
        && let Some(slice) = bytes.get(pos..)
    {
        hasher.update(slice);
    }
    hasher.finalize().to_vec()
}

fn collect_certificates(signed_data: &SignedData) -> Vec<Certificate> {
    let Some(set) = signed_data.certificates.as_ref() else {
        return Vec::new();
    };
    let mut out: Vec<Certificate> = Vec::new();
    for choice in set.0.iter() {
        if let cms::cert::CertificateChoices::Certificate(cert) = choice {
            out.push(cert.clone());
        }
    }
    out
}

fn build_chain(certs: &[Certificate], signer: &SignerInfo) -> Vec<Certificate> {
    let Some(leaf): Option<&Certificate> = find_signer_cert(certs, signer) else {
        return Vec::new();
    };
    let mut chain: Vec<Certificate> = vec![leaf.clone()];
    while chain.len() < MAX_CHAIN_DEPTH {
        let Some(current): Option<&Certificate> = chain.last() else {
            break;
        };
        if name_eq(
            &current.tbs_certificate.subject,
            &current.tbs_certificate.issuer,
        ) {
            break;
        }
        let issuer: &x509_cert::name::Name = &current.tbs_certificate.issuer;
        let next: Option<&Certificate> = certs.iter().find(|candidate: &&Certificate| {
            name_eq(&candidate.tbs_certificate.subject, issuer)
                && !name_eq(
                    &candidate.tbs_certificate.subject,
                    &candidate.tbs_certificate.issuer,
                )
        });
        let next: &Certificate = match next {
            Some(cert) if !chain_contains(&chain, cert) => cert,
            _ => {
                let root: Option<&Certificate> = certs.iter().find(|candidate: &&Certificate| {
                    name_eq(&candidate.tbs_certificate.subject, issuer)
                        && !chain_contains(&chain, candidate)
                });
                match root {
                    Some(cert) => cert,
                    None => break,
                }
            }
        };
        chain.push(next.clone());
    }
    chain
}

fn chain_contains(chain: &[Certificate], cert: &Certificate) -> bool {
    chain.iter().any(|c: &Certificate| {
        name_eq(&c.tbs_certificate.subject, &cert.tbs_certificate.subject)
            && c.tbs_certificate.serial_number.as_bytes()
                == cert.tbs_certificate.serial_number.as_bytes()
    })
}

fn find_signer_cert<'a>(certs: &'a [Certificate], signer: &SignerInfo) -> Option<&'a Certificate> {
    match &signer.sid {
        SignerIdentifier::IssuerAndSerialNumber(ias) => certs.iter().find(|cert: &&Certificate| {
            name_eq(&cert.tbs_certificate.issuer, &ias.issuer)
                && cert.tbs_certificate.serial_number.as_bytes() == ias.serial_number.as_bytes()
        }),
        SignerIdentifier::SubjectKeyIdentifier(_) => certs.first(),
    }
}

fn links_verify(chain: &[Certificate]) -> bool {
    for pair in chain.windows(2) {
        let [child, parent] = pair else {
            return false;
        };
        if !cert_signature_ok(child, parent) {
            return false;
        }
    }
    true
}

fn chain_is_anchored(chain: &[Certificate]) -> bool {
    let Some(top): Option<&Certificate> = chain.last() else {
        return false;
    };
    for raw in TRUSTED_ROOTS {
        let Ok(root): Result<Certificate, _> = Certificate::from_der(raw) else {
            continue;
        };
        if name_eq(&root.tbs_certificate.subject, &top.tbs_certificate.issuer)
            && cert_signature_ok(top, &root)
        {
            return true;
        }
    }
    false
}

enum SignerVerification {
    Ok,
    Failed,
    Unsupported,
}

fn verify_signer(
    signer: &SignerInfo,
    leaf: Option<&Certificate>,
    econtent: &Any,
    econtent_der: &[u8],
) -> SignerVerification {
    let Some(leaf): Option<&Certificate> = leaf else {
        return SignerVerification::Failed;
    };
    let Some(signed_attrs) = signer.signed_attrs.as_ref() else {
        return SignerVerification::Failed;
    };
    let digest_kind: Option<DigestKind> = DigestKind::from_oid(&signer.digest_alg.oid);
    let Some(digest_kind): Option<DigestKind> = digest_kind else {
        return SignerVerification::Unsupported;
    };
    if !message_digest_matches(signed_attrs, digest_kind, econtent, econtent_der) {
        return SignerVerification::Failed;
    }
    let Ok(mut tbs): Result<Vec<u8>, _> = signed_attrs.to_der() else {
        return SignerVerification::Failed;
    };
    if tbs.first() == Some(&0xA0) {
        tbs[0] = 0x31;
    }
    let signature: &[u8] = signer.signature.as_bytes();
    let spki: &spki::SubjectPublicKeyInfoOwned = &leaf.tbs_certificate.subject_public_key_info;
    match verify_signature(
        spki,
        &signer.signature_algorithm.oid,
        digest_kind,
        &tbs,
        signature,
    ) {
        SignatureOutcome::Ok => SignerVerification::Ok,
        SignatureOutcome::Failed => SignerVerification::Failed,
        SignatureOutcome::Unsupported => SignerVerification::Unsupported,
    }
}

fn message_digest_matches(
    signed_attrs: &cms::signed_data::SignedAttributes,
    digest_kind: DigestKind,
    econtent: &Any,
    econtent_der: &[u8],
) -> bool {
    let Some(stored): Option<Vec<u8>> = signed_attr_octets(signed_attrs, &OID_MESSAGE_DIGEST)
    else {
        return false;
    };
    let full: Vec<u8> = digest_kind.digest(econtent_der);
    if stored == full {
        return true;
    }
    let inner: Vec<u8> = digest_kind.digest(econtent.value());
    stored == inner
}

fn signed_attr_octets(
    attrs: &cms::signed_data::SignedAttributes,
    oid: &ObjectIdentifier,
) -> Option<Vec<u8>> {
    let attr = attrs
        .iter()
        .find(|a: &&x509_cert::attr::Attribute| a.oid == *oid)?;
    let value: &Any = attr.values.iter().next()?;
    let der: Vec<u8> = value.to_der().ok()?;
    let octet: OctetString = OctetString::from_der(&der).ok()?;
    Some(octet.as_bytes().to_vec())
}

enum SignatureOutcome {
    Ok,
    Failed,
    Unsupported,
}

fn verify_signature(
    spki: &spki::SubjectPublicKeyInfoOwned,
    sig_alg: &ObjectIdentifier,
    digest_kind: DigestKind,
    message: &[u8],
    signature: &[u8],
) -> SignatureOutcome {
    let key_oid: ObjectIdentifier = spki.algorithm.oid;
    if key_oid == OID_RSA_ENCRYPTION {
        let effective: DigestKind = match *sig_alg {
            OID_RSA_SHA1 => DigestKind::Sha1,
            OID_RSA_SHA256 => DigestKind::Sha256,
            OID_RSA_SHA384 => DigestKind::Sha384,
            OID_RSA_SHA512 => DigestKind::Sha512,
            OID_RSA_ENCRYPTION => digest_kind,
            _ => return SignatureOutcome::Unsupported,
        };
        return rsa_verify(spki, effective, message, signature);
    }
    if key_oid == OID_EC_PUBLIC_KEY {
        let effective: DigestKind = match *sig_alg {
            OID_ECDSA_SHA1 => DigestKind::Sha1,
            OID_ECDSA_SHA256 => DigestKind::Sha256,
            OID_ECDSA_SHA384 => DigestKind::Sha384,
            OID_ECDSA_SHA512 => DigestKind::Sha512,
            _ => digest_kind,
        };
        return ecdsa_verify(spki, effective, message, signature);
    }
    SignatureOutcome::Unsupported
}

fn rsa_verify(
    spki: &spki::SubjectPublicKeyInfoOwned,
    digest_kind: DigestKind,
    message: &[u8],
    signature: &[u8],
) -> SignatureOutcome {
    let key_der: &[u8] = spki.subject_public_key.raw_bytes();
    let Ok(public_key): Result<RsaPublicKey, _> = RsaPublicKey::from_pkcs1_der(key_der) else {
        return SignatureOutcome::Failed;
    };
    let Ok(sig): Result<rsa::pkcs1v15::Signature, _> =
        rsa::pkcs1v15::Signature::try_from(signature)
    else {
        return SignatureOutcome::Failed;
    };
    let ok: bool = match digest_kind {
        DigestKind::Sha1 => rsa::pkcs1v15::VerifyingKey::<sha1::Sha1>::new(public_key)
            .verify(message, &sig)
            .is_ok(),
        DigestKind::Sha256 => rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(public_key)
            .verify(message, &sig)
            .is_ok(),
        DigestKind::Sha384 => rsa::pkcs1v15::VerifyingKey::<sha2::Sha384>::new(public_key)
            .verify(message, &sig)
            .is_ok(),
        DigestKind::Sha512 => rsa::pkcs1v15::VerifyingKey::<sha2::Sha512>::new(public_key)
            .verify(message, &sig)
            .is_ok(),
    };
    if ok {
        SignatureOutcome::Ok
    } else {
        SignatureOutcome::Failed
    }
}

fn ecdsa_verify(
    spki: &spki::SubjectPublicKeyInfoOwned,
    digest_kind: DigestKind,
    message: &[u8],
    signature: &[u8],
) -> SignatureOutcome {
    let curve: Option<ObjectIdentifier> = spki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|p: &Any| p.decode_as::<ObjectIdentifier>().ok());
    let point: &[u8] = spki.subject_public_key.raw_bytes();
    let prehash: Vec<u8> = digest_kind.digest(message);
    match curve {
        Some(OID_EC_P256) => {
            let Ok(vk): Result<p256::ecdsa::VerifyingKey, _> =
                p256::ecdsa::VerifyingKey::from_sec1_bytes(point)
            else {
                return SignatureOutcome::Failed;
            };
            let Ok(sig): Result<p256::ecdsa::Signature, _> =
                p256::ecdsa::Signature::from_der(signature)
            else {
                return SignatureOutcome::Failed;
            };
            if vk.verify_prehash(&prehash, &sig).is_ok() {
                SignatureOutcome::Ok
            } else {
                SignatureOutcome::Failed
            }
        }
        Some(OID_EC_P384) => {
            let Ok(vk): Result<p384::ecdsa::VerifyingKey, _> =
                p384::ecdsa::VerifyingKey::from_sec1_bytes(point)
            else {
                return SignatureOutcome::Failed;
            };
            let Ok(sig): Result<p384::ecdsa::Signature, _> =
                p384::ecdsa::Signature::from_der(signature)
            else {
                return SignatureOutcome::Failed;
            };
            if vk.verify_prehash(&prehash, &sig).is_ok() {
                SignatureOutcome::Ok
            } else {
                SignatureOutcome::Failed
            }
        }
        _ => SignatureOutcome::Unsupported,
    }
}

fn cert_signature_ok(child: &Certificate, parent: &Certificate) -> bool {
    let Ok(tbs): Result<Vec<u8>, _> = child.tbs_certificate.to_der() else {
        return false;
    };
    let digest_kind: DigestKind = match child.signature_algorithm.oid {
        OID_RSA_SHA1 | OID_ECDSA_SHA1 => DigestKind::Sha1,
        OID_RSA_SHA256 | OID_ECDSA_SHA256 => DigestKind::Sha256,
        OID_RSA_SHA384 | OID_ECDSA_SHA384 => DigestKind::Sha384,
        OID_RSA_SHA512 | OID_ECDSA_SHA512 => DigestKind::Sha512,
        _ => return false,
    };
    let signature: &[u8] = child.signature.raw_bytes();
    matches!(
        verify_signature(
            &parent.tbs_certificate.subject_public_key_info,
            &child.signature_algorithm.oid,
            digest_kind,
            &tbs,
            signature,
        ),
        SignatureOutcome::Ok
    )
}

fn cert_info(cert: &Certificate) -> CertInfo {
    let subject: String = cert.tbs_certificate.subject.to_string();
    let issuer: String = cert.tbs_certificate.issuer.to_string();
    let serial: String = hex_upper(cert.tbs_certificate.serial_number.as_bytes());
    let not_before: String = unix_to_iso(time_to_unix(&cert.tbs_certificate.validity.not_before));
    let not_after: String = unix_to_iso(time_to_unix(&cert.tbs_certificate.validity.not_after));
    CertInfo {
        subject,
        issuer,
        serial,
        not_before,
        not_after,
        is_ca: cert_is_ca(cert),
        self_signed: name_eq(&cert.tbs_certificate.subject, &cert.tbs_certificate.issuer),
    }
}

fn cert_is_ca(cert: &Certificate) -> bool {
    let Some(extensions) = cert.tbs_certificate.extensions.as_ref() else {
        return false;
    };
    for ext in extensions {
        if ext.extn_id == OID_BASIC_CONSTRAINTS
            && let Ok(bc) =
                x509_cert::ext::pkix::BasicConstraints::from_der(ext.extn_value.as_bytes())
        {
            return bc.ca;
        }
    }
    false
}

fn cert_is_expired(cert: &Certificate, reference: i64) -> bool {
    let not_before: i64 = time_to_unix(&cert.tbs_certificate.validity.not_before);
    let not_after: i64 = time_to_unix(&cert.tbs_certificate.validity.not_after);
    reference < not_before || reference > not_after
}

fn time_to_unix(time: &x509_cert::time::Time) -> i64 {
    let secs: u64 = time.to_unix_duration().as_secs();
    i64::try_from(secs).unwrap_or(i64::MAX)
}

fn extract_timestamp(signer: &SignerInfo) -> Option<TimestampInfo> {
    let unsigned = signer.unsigned_attrs.as_ref()?;
    for attr in unsigned.iter() {
        if attr.oid == OID_RFC3161_TIMESTAMP
            && let Some(value) = attr.values.iter().next()
            && let Some(info) = parse_rfc3161(value)
        {
            return Some(info);
        }
        if attr.oid == OID_COUNTER_SIGNATURE
            && let Some(value) = attr.values.iter().next()
            && let Some(info) = parse_counter_signature(value)
        {
            return Some(info);
        }
    }
    None
}

fn parse_rfc3161(value: &Any) -> Option<TimestampInfo> {
    let der: Vec<u8> = value.to_der().ok()?;
    let content_info_body: &[u8] = child_with_tag(&der_children(&der)?, 0x30)?;
    let ci_fields: Vec<(u8, &[u8])> = der_children(content_info_body)?;
    let signed_data_wrapped: &[u8] = child_with_tag(&ci_fields, 0xA0)?;
    let signed_data_body: &[u8] = child_with_tag(&der_children(signed_data_wrapped)?, 0x30)?;
    let sd_fields: Vec<(u8, &[u8])> = der_children(signed_data_body)?;
    let eci_body: &[u8] = child_with_tag(&sd_fields, 0x30)?;
    let eci_fields: Vec<(u8, &[u8])> = der_children(eci_body)?;
    let econtent_explicit: &[u8] = child_with_tag(&eci_fields, 0xA0)?;
    let tst_der: &[u8] = child_with_tag(&der_children(econtent_explicit)?, 0x04)?;
    let (gen_time, hash_algorithm): (String, String) = parse_tst_info(tst_der)?;
    let tsa_subject: String = tsa_subject_from_certs(&sd_fields).unwrap_or_default();
    Some(TimestampInfo {
        tsa_subject,
        signing_time: gen_time,
        hash_algorithm,
    })
}

fn tsa_subject_from_certs(sd_fields: &[(u8, &[u8])]) -> Option<String> {
    let certs_content: &[u8] = child_with_tag(sd_fields, 0xA0)?;
    let first_len: usize = der_tlv_total_len(certs_content)?;
    let cert_tlv: &[u8] = certs_content.get(..first_len)?;
    let cert: Certificate = Certificate::from_der(cert_tlv).ok()?;
    Some(cert.tbs_certificate.subject.to_string())
}

fn child_with_tag<'a>(children: &[(u8, &'a [u8])], tag: u8) -> Option<&'a [u8]> {
    children
        .iter()
        .find(|(t, _): &&(u8, &[u8])| *t == tag)
        .map(|(_, body): &(u8, &'a [u8])| *body)
}

fn parse_counter_signature(value: &Any) -> Option<TimestampInfo> {
    let der: Vec<u8> = value.to_der().ok()?;
    let signer: SignerInfo = SignerInfo::from_der(&der).ok()?;
    let signed_attrs = signer.signed_attrs.as_ref()?;
    let signing_time: String = signed_attr_time(signed_attrs, &OID_SIGNING_TIME)?;
    let hash_algorithm: String = DigestKind::from_oid(&signer.digest_alg.oid)
        .map(|d: DigestKind| d.label().to_owned())
        .unwrap_or_default();
    Some(TimestampInfo {
        tsa_subject: String::new(),
        signing_time,
        hash_algorithm,
    })
}

fn signed_attr_time(
    attrs: &cms::signed_data::SignedAttributes,
    oid: &ObjectIdentifier,
) -> Option<String> {
    let attr = attrs
        .iter()
        .find(|a: &&x509_cert::attr::Attribute| a.oid == *oid)?;
    let value: &Any = attr.values.iter().next()?;
    let der: Vec<u8> = value.to_der().ok()?;
    if let Ok(utc) = der::asn1::UtcTime::from_der(&der) {
        return Some(unix_to_iso(
            i64::try_from(utc.to_unix_duration().as_secs()).ok()?,
        ));
    }
    if let Ok(gen_time) = der::asn1::GeneralizedTime::from_der(&der) {
        return Some(unix_to_iso(
            i64::try_from(gen_time.to_unix_duration().as_secs()).ok()?,
        ));
    }
    None
}

fn parse_tst_info(der: &[u8]) -> Option<(String, String)> {
    let children: Vec<(u8, &[u8])> = der_children(der)?;
    let (seq_tag, seq_body) = children.first().copied()?;
    if seq_tag != 0x30 {
        return None;
    }
    let fields: Vec<(u8, &[u8])> = der_children(seq_body)?;
    let hash_algorithm: String = fields
        .iter()
        .find(|(tag, _): &&(u8, &[u8])| *tag == 0x30)
        .and_then(|(_, body): &(u8, &[u8])| der_children(body))
        .and_then(|inner: Vec<(u8, &[u8])>| {
            inner
                .iter()
                .find(|(tag, _): &&(u8, &[u8])| *tag == 0x30)
                .and_then(|(_, algo): &(u8, &[u8])| der_children(algo))
                .and_then(|algo_fields: Vec<(u8, &[u8])>| {
                    algo_fields
                        .iter()
                        .find(|(tag, _): &&(u8, &[u8])| *tag == 0x06)
                        .and_then(|(_, oid_bytes): &(u8, &[u8])| oid_to_digest_label(oid_bytes))
                })
        })
        .unwrap_or_default();
    let gen_time: String = fields
        .iter()
        .find(|(tag, _): &&(u8, &[u8])| *tag == 0x18)
        .and_then(|(_, body): &(u8, &[u8])| generalized_time_to_iso(body))?;
    Some((gen_time, hash_algorithm))
}

fn oid_to_digest_label(oid_bytes: &[u8]) -> Option<String> {
    let mut der: Vec<u8> = Vec::with_capacity(oid_bytes.len() + 2);
    der.push(0x06);
    der.push(u8::try_from(oid_bytes.len()).ok()?);
    der.extend_from_slice(oid_bytes);
    let oid: ObjectIdentifier = ObjectIdentifier::from_der(&der).ok()?;
    DigestKind::from_oid(&oid).map(|d: DigestKind| d.label().to_owned())
}

fn generalized_time_to_iso(body: &[u8]) -> Option<String> {
    if body.len() < 14 {
        return None;
    }
    let text: &str = std::str::from_utf8(&body[..14]).ok()?;
    if !text.bytes().all(|b: u8| b.is_ascii_digit()) {
        return None;
    }
    Some(format!(
        "{}-{}-{}T{}:{}:{}Z",
        &text[0..4],
        &text[4..6],
        &text[6..8],
        &text[8..10],
        &text[10..12],
        &text[12..14],
    ))
}

fn der_tlv_total_len(bytes: &[u8]) -> Option<usize> {
    let _tag: u8 = *bytes.first()?;
    let first_len: u8 = *bytes.get(1)?;
    if first_len & 0x80 == 0 {
        return 2usize.checked_add(first_len as usize);
    }
    let count: usize = (first_len & 0x7F) as usize;
    if count == 0 || count > 4 {
        return None;
    }
    let mut length: usize = 0;
    for i in 0..count {
        let byte: u8 = *bytes.get(2 + i)?;
        length = length.checked_shl(8)?.checked_add(byte as usize)?;
    }
    2usize.checked_add(count)?.checked_add(length)
}

fn der_children(bytes: &[u8]) -> Option<Vec<(u8, &[u8])>> {
    let mut out: Vec<(u8, &[u8])> = Vec::new();
    let mut pos: usize = 0;
    while pos < bytes.len() {
        let tag: u8 = *bytes.get(pos)?;
        pos = pos.checked_add(1)?;
        let first_len: u8 = *bytes.get(pos)?;
        pos = pos.checked_add(1)?;
        let length: usize = if first_len & 0x80 == 0 {
            first_len as usize
        } else {
            let count: usize = (first_len & 0x7F) as usize;
            if count == 0 || count > 4 {
                return None;
            }
            let mut value: usize = 0;
            for _ in 0..count {
                let byte: u8 = *bytes.get(pos)?;
                pos = pos.checked_add(1)?;
                value = value.checked_shl(8)?.checked_add(byte as usize)?;
            }
            value
        };
        let end: usize = pos.checked_add(length)?;
        let content: &[u8] = bytes.get(pos..end)?;
        out.push((tag, content));
        pos = end;
    }
    Some(out)
}

fn name_eq(a: &x509_cert::name::Name, b: &x509_cert::name::Name) -> bool {
    match (a.to_der(), b.to_der()) {
        (Ok(da), Ok(db)) => da == db,
        _ => false,
    }
}

fn hex_upper(bytes: &[u8]) -> String {
    let mut out: String = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(
            char::from_digit((byte >> 4) as u32, 16)
                .unwrap_or('0')
                .to_ascii_uppercase(),
        );
        out.push(
            char::from_digit((byte & 0x0F) as u32, 16)
                .unwrap_or('0')
                .to_ascii_uppercase(),
        );
    }
    out
}

fn now_unix() -> i64 {
    i64::try_from(disrobe_core::time::now_secs()).unwrap_or(i64::MAX)
}

fn parse_iso_to_unix(iso: &str) -> Option<i64> {
    let bytes: &[u8] = iso.as_bytes();
    if bytes.len() < 19 {
        return None;
    }
    let year: i64 = iso.get(0..4)?.parse().ok()?;
    let month: i64 = iso.get(5..7)?.parse().ok()?;
    let day: i64 = iso.get(8..10)?.parse().ok()?;
    let hour: i64 = iso.get(11..13)?.parse().ok()?;
    let minute: i64 = iso.get(14..16)?.parse().ok()?;
    let second: i64 = iso.get(17..19)?.parse().ok()?;
    Some(civil_to_unix(year, month, day, hour, minute, second))
}

fn civil_to_unix(year: i64, month: i64, day: i64, hour: i64, minute: i64, second: i64) -> i64 {
    let y: i64 = if month <= 2 { year - 1 } else { year };
    let era: i64 = if y >= 0 { y } else { y - 399 } / 400;
    let yoe: i64 = y - era * 400;
    let doy: i64 = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let doe: i64 = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days: i64 = era * 146_097 + doe - 719_468;
    days * 86_400 + hour * 3_600 + minute * 60 + second
}

fn unix_to_iso(unix: i64) -> String {
    let days: i64 = unix.div_euclid(86_400);
    let secs: i64 = unix.rem_euclid(86_400);
    let z: i64 = days + 719_468;
    let era: i64 = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe: i64 = z - era * 146_097;
    let yoe: i64 = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year: i64 = yoe + era * 400;
    let doy: i64 = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp: i64 = (5 * doy + 2) / 153;
    let day: i64 = doy - (153 * mp + 2) / 5 + 1;
    let month: i64 = if mp < 10 { mp + 3 } else { mp - 9 };
    let full_year: i64 = if month <= 2 { year + 1 } else { year };
    let hour: i64 = secs / 3_600;
    let minute: i64 = (secs % 3_600) / 60;
    let second: i64 = secs % 60;
    format!("{full_year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn unsigned_or_malformed_never_panics() {
        let inputs: Vec<Vec<u8>> = vec![
            Vec::new(),
            vec![0u8],
            b"MZ".to_vec(),
            b"MZ\x00\x00".to_vec(),
            vec![0x4D, 0x5A, 0xFF, 0xFF, 0xFF, 0xFF],
            (0..512u16).map(|i: u16| (i & 0xFF) as u8).collect(),
        ];
        for input in &inputs {
            let report: AuthenticodeReport = verify(input);
            let _ = report.verdict;
        }
    }

    #[test]
    fn empty_security_directory_is_no_signature() {
        let bytes: Vec<u8> = crate::fixtures::minimal_pe32();
        let report: AuthenticodeReport = verify(&bytes);
        assert_eq!(report.verdict, AuthenticodeVerdict::NoSignature);
    }

    #[test]
    fn roots_bundle_parses() {
        let mut parsed: usize = 0;
        for raw in TRUSTED_ROOTS {
            assert!(
                Certificate::from_der(raw).is_ok(),
                "trusted root DER failed to parse"
            );
            parsed += 1;
        }
        assert!(parsed >= 6, "expected a curated root bundle, saw {parsed}");
    }

    #[test]
    fn iso_round_trip_matches_known_epochs() {
        assert_eq!(unix_to_iso(0), "1970-01-01T00:00:00Z");
        assert_eq!(unix_to_iso(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(
            parse_iso_to_unix("2023-11-14T22:13:20Z"),
            Some(1_700_000_000)
        );
        assert_eq!(
            parse_iso_to_unix(&unix_to_iso(1_600_000_000)),
            Some(1_600_000_000)
        );
    }

    #[test]
    fn digest_kind_maps_known_oids() {
        assert_eq!(DigestKind::from_oid(&OID_SHA256), Some(DigestKind::Sha256));
        assert_eq!(DigestKind::from_oid(&OID_SHA1), Some(DigestKind::Sha1));
        assert!(DigestKind::from_oid(&OID_RSA_ENCRYPTION).is_none());
    }
}
