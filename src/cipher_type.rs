use block_modes::block_padding::{AnsiX923, Iso7816, NoPadding, Pkcs7, ZeroPadding};
use block_modes::{Cbc, Cfb, Ecb, Ofb};
use des::Des;
use aes::Aes128;

pub type CbcDesPkcs7 = Cbc<Des, Pkcs7>;
pub type EcbDesPkcs7 = Ecb<Des, Pkcs7>;
pub type CfbDesPkcs7 = Cfb<Des, Pkcs7>;
pub type OfbDesPkcs7 = Ofb<Des, Pkcs7>;

pub type CbcDesAnsiX923 = Cbc<Des, AnsiX923>;
pub type EcbDesAnsiX923 = Ecb<Des, AnsiX923>;
pub type CfbDesAnsiX923 = Cfb<Des, AnsiX923>;
pub type OfbDesAnsiX923 = Ofb<Des, AnsiX923>;

pub type CbcDesIso7816 = Cbc<Des, Iso7816>;
pub type EcbDesIso7816 = Ecb<Des, Iso7816>;
pub type CfbDesIso7816 = Cfb<Des, Iso7816>;
pub type OfbDesIso7816 = Ofb<Des, Iso7816>;

pub type CbcDesNoPadding = Cbc<Des, NoPadding>;
pub type EcbDesNoPadding = Ecb<Des, NoPadding>;
pub type CfbDesNoPadding = Cfb<Des, NoPadding>;
pub type OfbDesNoPadding = Ofb<Des, NoPadding>;

pub type CbcDesZeroPadding = Cbc<Des, ZeroPadding>;
pub type EcbDesZeroPadding = Ecb<Des, ZeroPadding>;
pub type CfbDesZeroPadding = Cfb<Des, ZeroPadding>;
pub type OfbDesZeroPadding = Ofb<Des, ZeroPadding>;



pub type CbcAes128Pkcs7 = Cbc<Aes128, Pkcs7>;
pub type EcbAes128Pkcs7 = Ecb<Aes128, Pkcs7>;
pub type CfbAes128Pkcs7 = Cfb<Aes128, Pkcs7>;
pub type OfbAes128Pkcs7 = Ofb<Aes128, Pkcs7>;

pub type CbcAes128AnsiX923 = Cbc<Aes128, AnsiX923>;
pub type EcbAes128AnsiX923 = Ecb<Aes128, AnsiX923>;
pub type CfbAes128AnsiX923 = Cfb<Aes128, AnsiX923>;
pub type OfbAes128AnsiX923 = Ofb<Aes128, AnsiX923>;

pub type CbcAes128Iso7816 = Cbc<Aes128, Iso7816>;
pub type EcbAes128Iso7816 = Ecb<Aes128, Iso7816>;
pub type CfbAes128Iso7816 = Cfb<Aes128, Iso7816>;
pub type OfbAes128Iso7816 = Ofb<Aes128, Iso7816>;

pub type CbcAes128NoPadding = Cbc<Aes128, NoPadding>;
pub type EcbAes128NoPadding = Ecb<Aes128, NoPadding>;
pub type CfbAes128NoPadding = Cfb<Aes128, NoPadding>;
pub type OfbAes128NoPadding = Ofb<Aes128, NoPadding>;

pub type CbcAes128ZeroPadding = Cbc<Aes128, ZeroPadding>;
pub type EcbAes128ZeroPadding = Ecb<Aes128, ZeroPadding>;
pub type CfbAes128ZeroPadding = Cfb<Aes128, ZeroPadding>;
pub type OfbAes128ZeroPadding = Ofb<Aes128, ZeroPadding>;
