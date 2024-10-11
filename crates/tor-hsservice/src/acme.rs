//! Functions relating to generating documents for draft-ietf-acme-onion

use asn1_rs::ToDer;
use tor_bytes::EncodeError;
use crate::config::CAARecordList;
use tor_netdoc::doc::hsdesc::{CAARecord, CAARecordBuilder, CAARecordBuilderError, CAARecordSet};
use crate::internal_prelude::*;

/// Possible errors when creating a CSR for an Onion Service
#[derive(Debug, Copy, Clone, Error)]
#[non_exhaustive]
pub enum OnionCsrError {
    /// Arti can't find the key for this service
    #[error("Arti can't find the key for this service")]
    KeyNotFound,
    /// The CA nonce is too long to fit
    #[error("The CA nonce is too long to fit")]
    CANonceTooLong,
    /// The CA nonce too short - not enough entropy
    #[error("The CA nonce is too short")]
    CANonceTooShort,
}

/// Create and sign a Certificate Signing Request
pub(crate) fn onion_csr(
    keymgr: &KeyMgr,
    nickname: &HsNickname,
    ca_nonce: &[u8],
) -> Result<Vec<u8>, OnionCsrError> {
    if ca_nonce.len() < 8 {
        return Err(OnionCsrError::CANonceTooShort);
    }
    if ca_nonce.len() > 128 {
        return Err(OnionCsrError::CANonceTooLong);
    }

    let hsid_spec = HsIdPublicKeySpecifier::new(nickname.clone());
    let hs_key = Into::<ed25519::ExpandedKeypair>::into(
        keymgr
            .get::<HsIdKeypair>(&hsid_spec)
            .map_err(|_| OnionCsrError::KeyNotFound)?
            .ok_or(OnionCsrError::KeyNotFound)?,
    );

    let mut rng = rand::thread_rng();
    let mut applicant_nonce = [0_u8; 10];
    rng.fill(&mut applicant_nonce);
    drop(rng);

    // See RFC 2986 for format details

    // CertificationRequestInfo SEQUENCE
    let mut tbs_csr_contents = Vec::new();
    // version INTEGER
    0.write_der(&mut tbs_csr_contents)
        .expect("serialize version INTEGER");
    // subject Name
    asn1_rs::Sequence::new((&[]).into()).write_der(&mut tbs_csr_contents)
        .expect("serialize subject Name");

    let mut subject_pk_contents = Vec::new();
    // algorithm AlgorithmIdentifier
    asn1_rs::Sequence::from_iter_to_der([
        // algorithm OBJECT IDENTIFIER - id-Ed25519
        asn1_rs::oid!(1.3.101.112)
    ].iter())
        .expect("create algorithm AlgorithmIdentifier")
        .write_der(&mut subject_pk_contents)
        .expect("serialize algorithm AlgorithmIdentifier");
    // subjectPublicKey BIT STRING
    asn1_rs::BitString::new(0, &hs_key.public().to_bytes())
        .write_der(&mut subject_pk_contents)
        .expect("serialize subjectPublicKey BIT STRING");
    // subjectPKInfo SubjectPublicKeyInfo
    asn1_rs::Sequence::new(subject_pk_contents.into()).write_der(&mut tbs_csr_contents)
        .expect("serialize subjectPKInfo SubjectPublicKeyInfo");

    let mut ca_nonce_contents = Vec::new();
    // type OBJECT IDENTIFIER - cabf-caSigningNonce
    asn1_rs::oid!(2.23.140.41).write_der(&mut ca_nonce_contents)
        .expect("serialize type OBJECT IDENTIFIER - cabf-caSigningNonce");
    // values SET
    asn1_rs::Set::from_iter_to_der([
        asn1_rs::OctetString::new(ca_nonce)
    ].iter())
        .expect("create values SET")
        .write_der(&mut ca_nonce_contents)
        .expect("serialize values SET");

    let mut applicant_nonce_contents = Vec::new();
    // type OBJECT IDENTIFIER - cabf-applicantSigningNonce
    asn1_rs::oid!(2.23.140.42).write_der(&mut applicant_nonce_contents)
        .expect("serialize type OBJECT IDENTIFIER - cabf-applicantSigningNonce");
    // values SET
    asn1_rs::Set::from_iter_to_der([
        asn1_rs::OctetString::new(&applicant_nonce)
    ].iter())
        .expect("create values SET")
        .write_der(&mut applicant_nonce_contents)
        .expect("serialize values SET");

    // attributes [0] Attributes
    asn1_rs::TaggedImplicit::<asn1_rs::Set, asn1_rs::Error, 0>::implicit(
        asn1_rs::Set::from_iter_to_der([
            // Attribute SEQUENCE
            asn1_rs::Sequence::new(ca_nonce_contents.into()),
            // Attribute SEQUENCE
            asn1_rs::Sequence::new(applicant_nonce_contents.into()),
        ].iter()).expect("create attributes [0] Attributes")
    ).write_der(&mut tbs_csr_contents).expect("serialize attributes [0] Attributes");

    let tbs_csr = asn1_rs::Sequence::new(tbs_csr_contents.into());
    let mut tbs = Vec::new();
    tbs_csr.write_der(&mut tbs).expect("serialize CertificationRequestInfo SEQUENCE");
    let signature = hs_key.sign(&tbs);

    let mut csr_contents = Vec::new();
    tbs_csr.write_der(&mut csr_contents)
        .expect("serialize CertificationRequestInfo SEQUENCE");
    // signatureAlgorithm AlgorithmIdentifier
    asn1_rs::Sequence::from_iter_to_der([
        // algorithm OBJECT IDENTIFIER - id-Ed25519
        asn1_rs::oid!(1.3.101.112)
    ].iter())
        .expect("create signatureAlgorithm AlgorithmIdentifier")
        .write_der(&mut csr_contents)
        .expect("serialize signatureAlgorithm AlgorithmIdentifier");
    // signature BIT STRING
    asn1_rs::BitString::new(0, signature.to_bytes().as_slice())
        .write_der(&mut csr_contents).expect("serialize signature BIT STRING");

    let mut csr = Vec::new();
    // CertificationRequest SEQUENCE
    asn1_rs::Sequence::new(csr_contents.into()).write_der(&mut csr)
        .expect("serialize CertificationRequest SEQUENCE");

    Ok(csr)
}

/// Possible errors when creating a CAA document for an Onion Service
#[derive(Debug, Clone, Error)]
#[non_exhaustive]
pub enum OnionCaaError {
    /// Arti can't find the key for this service
    #[error("Arti can't find the key for this service")]
    KeyNotFound,
    /// The system clock is bogus
    #[error("The system clock is bogus")]
    InvalidSystemTime,
    /// The CAA records couldn't be serialized
    #[error("The CAA records couldn't be serialized")]
    EncodeError(#[from] EncodeError),
}

/// A CAA document per draft-ietf-acme-onion
#[derive(Debug)]
#[non_exhaustive]
pub struct OnionCaa {
    /// CAA RRSet
    caa: String,
    /// Expiry UNIX timestamp
    expiry: u64,
    /// Document signature
    signature: Vec<u8>,
}

impl OnionCaa {
    /// The encoded CAA RRSet
    pub fn caa(&self) -> &str {
        &self.caa
    }

    /// Document expiry as a UNIX timestamp
    pub fn expiry(&self) -> u64 {
        self.expiry
    }

    /// Signature over the document
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }
}

/// Create and sign a CAA RRSet document
pub(crate) fn onion_caa(
    keymgr: &KeyMgr,
    nickname: &HsNickname,
    caa: &CAARecordList,
    expiry: u64,
) -> Result<OnionCaa, OnionCaaError> {
    let hsid_spec = HsIdPublicKeySpecifier::new(nickname.clone());
    let hs_key = Into::<ed25519::ExpandedKeypair>::into(
        keymgr
            .get::<HsIdKeypair>(&hsid_spec)
            .map_err(|_| OnionCaaError::KeyNotFound)?
            .ok_or(OnionCaaError::KeyNotFound)?,
    );

    let mut rng = rand::thread_rng();
    // Vary expiry timestamp by up to 15 minutes to obscure local clock skew
    let expiry_jitter = Duration::from_secs(rng.gen_range(0..=900));

    let now = SystemTime::now();
    let expiry = now + Duration::from_secs(expiry) + expiry_jitter;
    let expiry_unix = expiry
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| OnionCaaError::InvalidSystemTime)?
        .as_secs();

    let caa_records = caa
        .iter()
        .map(|r| {
            CAARecordBuilder::default()
                .flags(r.flags)
                .tag(r.tag.clone())
                .value(r.value.clone())
                .build()
        })
        .collect::<Result<Vec<CAARecord>, CAARecordBuilderError>>()
        .expect("unable to build CAA record");
    let caa_rrset = CAARecordSet::new(&caa_records);
    let tbs_caa_rrset = caa_rrset.build_sign(&mut rng)?;

    let tbs = format!("onion-caa|{}|{}", expiry_unix, tbs_caa_rrset);
    let signature = hs_key.sign(tbs.as_bytes());

    Ok(OnionCaa {
        caa: tbs_caa_rrset,
        expiry: expiry_unix,
        signature: signature.to_vec(),
    })
}