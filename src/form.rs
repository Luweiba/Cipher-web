use rocket::http::RawStr;
use rocket::request::{FromForm, FromFormValue};

#[derive(Debug, Clone, Copy)]
pub enum EncryptMode {
    ECB,
    CBC,
    CFB,
    OFB,
}

impl<'v> FromFormValue<'v> for EncryptMode {
    type Error = &'static str;

    fn from_form_value(v: &'v RawStr) -> Result<Self, Self::Error> {
        if v.contains("ECB") {
            Ok(EncryptMode::ECB)
        } else if v.contains("CBC") {
            Ok(EncryptMode::CBC)
        } else if v.contains("CFB") {
            Ok(EncryptMode::CFB)
        } else if v.contains("OFB") {
            Ok(EncryptMode::OFB)
        } else {
            Err("Not a Mode")
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum EncryptPaddingMode {
    Pkcs7,
    AnsiX923,
    Iso7816,
    NoPadding,
    ZeroPadding,
}
impl<'v> FromFormValue<'v> for EncryptPaddingMode {
    type Error = &'static str;

    fn from_form_value(v: &'v RawStr) -> Result<Self, Self::Error> {
        if v.contains("Pkcs7") {
            Ok(EncryptPaddingMode::Pkcs7)
        } else if v.contains("AnsiX923") {
            Ok(EncryptPaddingMode::AnsiX923)
        } else if v.contains("Iso7816") {
            Ok(EncryptPaddingMode::Iso7816)
        } else if v.contains("NoPadding") {
            Ok(EncryptPaddingMode::NoPadding)
        } else if v.contains("ZeroPadding") {
            Ok(EncryptPaddingMode::ZeroPadding)
        } else {
            Err("Not a Padding Mode")
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum EncryptAlgorithm {
    AES,
    DES,
}

impl<'v> FromFormValue<'v> for EncryptAlgorithm {
    type Error = &'static str;

    fn from_form_value(v: &'v RawStr) -> Result<Self, Self::Error> {
        if v.contains("des") {
            Ok(EncryptAlgorithm::DES)
        } else if v.contains("aes") {
            Ok(EncryptAlgorithm::AES)
        } else {
            Err("Wrong Algorithm")
        }
    }
}

#[derive(FromForm, Debug)]
pub struct EncryptItem<'r> {
    pub algorithm: Result<EncryptAlgorithm, &'static str>,
    pub mode: Result<EncryptMode, &'static str>,
    pub padding: Result<EncryptPaddingMode, &'static str>,
    pub iv: &'r RawStr,
    pub key: &'r RawStr,
    pub message: &'r RawStr,
}

#[derive(FromForm, Debug)]
pub struct RsaKeysItem<'r> {
    pub length: &'r RawStr,
    pub mode: &'r RawStr,
}

#[derive(FromForm, Debug)]
pub struct RsaCryptItem<'r> {
    pub mode: &'r RawStr,
    pub padding: &'r RawStr,
    pub keys: &'r RawStr,
    pub message: &'r RawStr,
}

#[derive(FromForm, Debug)]
pub struct DHItem<'r> {
    pub final_packet: &'r RawStr,
    pub public_key: &'r RawStr,
    pub mode: &'r RawStr,
}

#[derive(FromForm, Debug)]
pub struct AffineCryptItem<'r> {
    pub lower_a: &'r RawStr,
    pub lower_b: &'r RawStr,
    pub upper_a: &'r RawStr,
    pub upper_b: &'r RawStr,
    pub number_a: &'r RawStr,
    pub number_b: &'r RawStr,
    pub message: &'r RawStr,
}
#[derive(FromForm, Debug)]
pub struct Rc4CryptItem<'r> {
    pub key: &'r RawStr,
    pub message: &'r RawStr,
    pub flag: &'r RawStr,
}
#[derive(FromForm, Debug)]
pub struct LfsrJkItem<'r> {
    pub j_state: &'r RawStr,
    pub k_state: &'r RawStr,
    pub j_state_c: &'r RawStr,
    pub k_state_c: &'r RawStr,
    pub message: &'r RawStr,
}
#[derive(FromForm, Debug)]
pub struct Sha3HashItem<'r> {
    pub msg: &'r RawStr,
}

#[derive(FromForm, Debug)]
pub struct SignatureItem<'r> {
    pub p: &'r RawStr,
    pub g: &'r RawStr,
    pub Ya: &'r RawStr,
    pub private_key: &'r RawStr,
    pub mac: &'r RawStr,
    pub mode: &'r RawStr,
}
