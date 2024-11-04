//! Functions relating to generating documents for draft-ietf-acme-onion

use crate::internal_prelude::*;
use asn1_rs::ToDer;
#[cfg(test)]
use mock_instant::global::{SystemTime, UNIX_EPOCH};
#[cfg(not(test))]
use std::time::{SystemTime, UNIX_EPOCH};
use tor_bytes::EncodeError;
use tor_netdoc::doc::hsdesc::CAARecordSet;

const MIN_CA_NONCE_LEN: usize = 8; // Per CA/BF Baseline Requirements
const MAX_CA_NONCE_LEN: usize = 128; // Somewhat arbitrarily chosen, to avoid wasting time signing a huge amount of data

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

/// Create and sign a Certificate Signing Request as per CA/BF Baseline Requirements Appendix B
#[rustfmt::skip]
pub(crate) fn onion_csr(
    keymgr: &KeyMgr,
    nickname: &HsNickname,
    ca_nonce: &[u8],
) -> Result<Vec<u8>, OnionCsrError> {
    if ca_nonce.len() < MIN_CA_NONCE_LEN {
        return Err(OnionCsrError::CANonceTooShort);
    }
    if ca_nonce.len() > MAX_CA_NONCE_LEN {
        return Err(OnionCsrError::CANonceTooLong);
    }

    let hsid_spec = HsIdPublicKeySpecifier::new(nickname.clone());
    let hs_key = ed25519::ExpandedKeypair::from(
        keymgr
            .get::<HsIdKeypair>(&hsid_spec)
            .map_err(|_| OnionCsrError::KeyNotFound)?
            .ok_or(OnionCsrError::KeyNotFound)?,
    );

    let mut rng = rand::thread_rng();
    // 10 bytes is a mostly arbitrary amount of entropy. It can be changed but MUST be 8 or more.
    let mut applicant_nonce = [0_u8; 10];
    rng.fill(&mut applicant_nonce);
    drop(rng);

    // See RFC 2986 and RFC 8410 for format details
    // EXPECT SAFETY: ASN.1 serialization shouldn't fail in this function because IO errors can`t
    // happen when writing to Vec and no DER objects are manually constructed.

    // CertificationRequestInfo SEQUENCE
    let mut tbs_csr_contents = Vec::new();
    // version INTEGER
    0.write_der(&mut tbs_csr_contents)
        .expect("serialize version INTEGER");
    // subject Name
    asn1_rs::Sequence::new((&[]).into())
        .write_der(&mut tbs_csr_contents)
        .expect("serialize subject Name");

    let mut subject_pk_contents = Vec::new();
    // algorithm AlgorithmIdentifier
    asn1_rs::Sequence::from_iter_to_der([
        // algorithm OBJECT IDENTIFIER: {iso(1) identified-organization(3) thawte(101) id-Ed25519(112)}
        asn1_rs::oid!(1.3.101.112),
    ].iter())
        .expect("create algorithm AlgorithmIdentifier")
        .write_der(&mut subject_pk_contents)
        .expect("serialize algorithm AlgorithmIdentifier");
    // subjectPublicKey BIT STRING
    asn1_rs::BitString::new(0, &hs_key.public().to_bytes())
        .write_der(&mut subject_pk_contents)
        .expect("serialize subjectPublicKey BIT STRING");
    // subjectPKInfo SubjectPublicKeyInfo
    asn1_rs::Sequence::new(subject_pk_contents.into())
        .write_der(&mut tbs_csr_contents)
        .expect("serialize subjectPKInfo SubjectPublicKeyInfo");

    let mut ca_nonce_contents = Vec::new();
    // type OBJECT IDENTIFIER: {joint-iso-itu-t(2) international-organizations(23) ca-browser-forum(140) cabf-caSigningNonce(41)}
    asn1_rs::oid!(2.23.140.41)
        .write_der(&mut ca_nonce_contents)
        .expect("serialize type OBJECT IDENTIFIER - cabf-caSigningNonce");
    // values SET
    asn1_rs::Set::from_iter_to_der([asn1_rs::OctetString::new(ca_nonce)].iter())
        .expect("create values SET")
        .write_der(&mut ca_nonce_contents)
        .expect("serialize values SET");

    let mut applicant_nonce_contents = Vec::new();
    // type OBJECT IDENTIFIER: {joint-iso-itu-t(2) international-organizations(23) ca-browser-forum(140) cabf-applicantSigningNonce(42)}
    asn1_rs::oid!(2.23.140.42)
        .write_der(&mut applicant_nonce_contents)
        .expect("serialize type OBJECT IDENTIFIER - cabf-applicantSigningNonce");
    // values SET
    asn1_rs::Set::from_iter_to_der([asn1_rs::OctetString::new(&applicant_nonce)].iter())
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
        ].iter())
            .expect("create attributes [0] Attributes"),
    )
        .write_der(&mut tbs_csr_contents)
        .expect("serialize attributes [0] Attributes");

    let tbs_csr = asn1_rs::Sequence::new(tbs_csr_contents.into());
    let mut tbs = Vec::new();
    tbs_csr
        .write_der(&mut tbs)
        .expect("serialize CertificationRequestInfo SEQUENCE");
    let signature = hs_key.sign(&tbs);

    let mut csr_contents = Vec::new();
    tbs_csr
        .write_der(&mut csr_contents)
        .expect("serialize CertificationRequestInfo SEQUENCE");
    // signatureAlgorithm AlgorithmIdentifier
    asn1_rs::Sequence::from_iter_to_der([
        // algorithm OBJECT IDENTIFIER: {iso(1) identified-organization(3) thawte(101) id-Ed25519(112)}
        asn1_rs::oid!(1.3.101.112),
    ].iter())
        .expect("create signatureAlgorithm AlgorithmIdentifier")
        .write_der(&mut csr_contents)
        .expect("serialize signatureAlgorithm AlgorithmIdentifier");
    // signature BIT STRING
    asn1_rs::BitString::new(0, signature.to_bytes().as_slice())
        .write_der(&mut csr_contents)
        .expect("serialize signature BIT STRING");

    let mut csr = Vec::new();
    // CertificationRequest SEQUENCE
    asn1_rs::Sequence::new(csr_contents.into())
        .write_der(&mut csr)
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

/// Create and sign a CAA RRSet document as per draft-ietf-acme-onion
pub(crate) fn onion_caa(
    keymgr: &KeyMgr,
    nickname: &HsNickname,
    caa: &[hickory_proto::rr::rdata::CAA],
    expiry: u64,
) -> Result<OnionCaa, OnionCaaError> {
    let hsid_spec = HsIdPublicKeySpecifier::new(nickname.clone());
    let hs_key = ed25519::ExpandedKeypair::from(
        keymgr
            .get::<HsIdKeypair>(&hsid_spec)
            .map_err(|_| OnionCaaError::KeyNotFound)?
            .ok_or(OnionCaaError::KeyNotFound)?,
    );

    let mut rng = rand::thread_rng();
    // Vary expiry timestamp by up to 15 minutes to obscure local clock skew
    let expiry_jitter = Duration::from_secs(
        rng.gen_range_checked(0..=900)
            .expect("generate random expiry jitter"),
    );

    let now = SystemTime::now();
    let expiry = now + Duration::from_secs(expiry) + expiry_jitter;
    let expiry_unix = expiry
        .duration_since(UNIX_EPOCH)
        .map_err(|_| OnionCaaError::InvalidSystemTime)?
        .as_secs();

    let caa_rrset = CAARecordSet::new(caa);
    let tbs_caa_rrset = caa_rrset.build_sign(&mut rng)?;

    let tbs = format!("onion-caa|{}|{}", expiry_unix, tbs_caa_rrset);
    let signature = hs_key.sign(tbs.as_bytes());

    Ok(OnionCaa {
        caa: tbs_caa_rrset,
        expiry: expiry_unix,
        signature: signature.to_vec(),
    })
}

#[cfg(test)]
pub(crate) mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;

    use crate::HsIdKeypairSpecifier;
    use test_temp_dir::test_temp_dir;
    use tor_llcrypto::pk::ed25519::{Signature, Verifier};

    const TEST_SVC_NICKNAME: &str = "test-acme-svc";

    #[test]
    fn onion_caa() {
        let time_start = 86401;
        let time_expiry = 86400;
        let temp_dir = test_temp_dir!();
        let nickname = HsNickname::try_from(TEST_SVC_NICKNAME.to_string()).unwrap();
        let hsid_spec = HsIdKeypairSpecifier::new(nickname.clone());
        let keymgr = crate::test::create_keymgr(&temp_dir);
        let (hsid_keypair, hsid_public) = crate::test::create_hsid();
        mock_instant::global::MockClock::set_system_time(Duration::from_secs(time_start));

        keymgr
            .insert(hsid_keypair, &hsid_spec, KeystoreSelector::Primary, true)
            .unwrap();

        let generated_caa = super::onion_caa(
            &keymgr,
            &nickname,
            &[hickory_proto::rr::rdata::CAA::new_issue(
                true,
                Some(hickory_proto::rr::Name::from_str("test.acmeforonions.org").unwrap()),
                vec![hickory_proto::rr::rdata::caa::KeyValue::new(
                    "validationmethods",
                    "onion-csr-01",
                )],
            )],
            time_expiry,
        )
        .unwrap();

        assert_eq!(
            generated_caa.caa,
            "caa 128 issue \"test.acmeforonions.org; validationmethods=onion-csr-01\""
        );

        let time_min = time_start + time_expiry;
        let time_max = time_start + time_expiry + 900; // jitter
        assert!(generated_caa.expiry >= time_min && generated_caa.expiry <= time_max);

        assert_eq!(generated_caa.signature.len(), 64);

        let message = format!("onion-caa|{}|{}", generated_caa.expiry, generated_caa.caa);
        let signature = Signature::from_slice(&generated_caa.signature).unwrap();
        hsid_public.verify(message.as_bytes(), &signature).unwrap();
    }

    #[test]
    fn onion_csr_too_short() {
        let temp_dir = test_temp_dir!();
        let nickname = HsNickname::try_from(TEST_SVC_NICKNAME.to_string()).unwrap();
        let hsid_spec = HsIdKeypairSpecifier::new(nickname.clone());
        let keymgr = crate::test::create_keymgr(&temp_dir);
        let (hsid_keypair, _hsid_public) = crate::test::create_hsid();

        keymgr
            .insert(hsid_keypair, &hsid_spec, KeystoreSelector::Primary, true)
            .unwrap();

        assert!(matches!(
            onion_csr(&keymgr, &nickname, &[]),
            Err(OnionCsrError::CANonceTooShort)
        ));
    }

    #[test]
    fn onion_csr_too_long() {
        let temp_dir = test_temp_dir!();
        let nickname = HsNickname::try_from(TEST_SVC_NICKNAME.to_string()).unwrap();
        let hsid_spec = HsIdKeypairSpecifier::new(nickname.clone());
        let keymgr = crate::test::create_keymgr(&temp_dir);
        let (hsid_keypair, _hsid_public) = crate::test::create_hsid();

        keymgr
            .insert(hsid_keypair, &hsid_spec, KeystoreSelector::Primary, true)
            .unwrap();

        let dummy_nonce = [0u8; 256];
        assert!(matches!(
            onion_csr(&keymgr, &nickname, &dummy_nonce),
            Err(OnionCsrError::CANonceTooLong)
        ));
    }

    #[test]
    fn onion_csr_valid() {
        let temp_dir = test_temp_dir!();
        let nickname = HsNickname::try_from(TEST_SVC_NICKNAME.to_string()).unwrap();
        let hsid_spec = HsIdKeypairSpecifier::new(nickname.clone());
        let keymgr = crate::test::create_keymgr(&temp_dir);
        let (hsid_keypair, _hsid_public) = crate::test::create_hsid();

        keymgr
            .insert(hsid_keypair, &hsid_spec, KeystoreSelector::Primary, true)
            .unwrap();

        let dummy_nonce = [0u8; 16];
        let generated_csr = onion_csr(&keymgr, &nickname, &dummy_nonce).unwrap();
        assert_eq!(generated_csr.len(), 180);

        let dummy_nonce = [0u8; 32];
        let generated_csr = onion_csr(&keymgr, &nickname, &dummy_nonce).unwrap();
        assert_eq!(generated_csr.len(), 196);
    }
}
