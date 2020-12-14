//！ 服务层函数

use crate::cipher_type::*;
use crate::form::*;
use crate::lfsr_jk::LfsrJk;
use crate::rc4::*;
use base64::{decode, encode};
use block_modes::BlockMode;
use rand::random;
use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use rand::thread_rng;
use rocket::request::Form;
use rocket::State;
use rsa::PrivateKeyPemEncoding;
use rsa::PublicKey;
use rsa::{PaddingScheme, PublicKeyParts, PublicKeyPemEncoding, RSAPrivateKey, RSAPublicKey};
use sha3::digest::DynDigest;
use sha3::{Digest, Sha3_256};
use std::convert::TryFrom;
use std::sync::{Arc, Mutex};
/// 用于将URL中的标点符号与中文解码
fn url_decode(data_in: String) -> String {
    let mut output = String::new();
    let data_vec = data_in.chars().collect::<Vec<char>>();
    let mut character_vec = vec![];
    let mut flag = false;
    let mut index = 0;
    while index < data_vec.len() {
        let ch = data_vec[index];
        if ch == '+' {
            output.push(' ');
            index += 1;
        } else if ch == '%' {
            let high_byte;
            let low_byte;
            if let Some(&byte) = data_vec.get(index + 1) {
                high_byte = byte;
            } else {
                if flag {
                    if character_vec.len() == 1 {
                        output.push(character_vec[0] as char);
                    } else {
                        output.push_str(&String::from_utf8(character_vec.clone()).unwrap());
                    }
                    character_vec.clear();
                }
                output.push(ch);
                index += 1;
                continue;
            }
            if let Some(&byte) = data_vec.get(index + 2) {
                low_byte = byte;
            } else {
                if flag {
                    if character_vec.len() == 1 {
                        output.push(character_vec[0] as char);
                    } else {
                        output.push_str(&String::from_utf8(character_vec.clone()).unwrap());
                    }
                    character_vec.clear();
                }
                output.push(ch);
                index += 1;
                continue;
            }
            if high_byte.is_ascii_hexdigit() && low_byte.is_ascii_hexdigit() {
                let byte =
                    (high_byte.to_digit(16).unwrap() * 16 + low_byte.to_digit(16).unwrap()) as u8;
                if flag {
                    character_vec.push(byte);
                } else {
                    flag = true;
                    character_vec.push(byte);
                }
                index += 3;
            } else {
                if flag {
                    if character_vec.len() == 1 {
                        output.push(character_vec[0] as char);
                    } else {
                        output.push_str(&String::from_utf8(character_vec.clone()).unwrap());
                    }
                    character_vec.clear();
                }
                output.push(ch);
                index += 1;
                continue;
            }
        } else {
            if flag {
                if character_vec.len() == 1 {
                    output.push(character_vec[0] as char);
                } else {
                    output.push_str(&String::from_utf8(character_vec.clone()).unwrap());
                }
                character_vec.clear();
            }
            output.push(ch);
            index += 1;
        }
    }
    if flag {
        if character_vec.len() == 1 {
            output.push(character_vec[0] as char);
        } else {
            output.push_str(&String::from_utf8(character_vec.clone()).unwrap());
        }
        character_vec.clear();
    }
    output
}
/// 处理AES与DES算法
pub fn handle(encrypt_item: Form<EncryptItem>, flag: bool) -> Result<String, String> {
    if let Err(e) = encrypt_item.algorithm {
        return Err(format!("Error: {}", e));
    }
    if let Err(e) = encrypt_item.mode {
        return Err(format!("Error: {}", e));
    }
    if let Err(e) = encrypt_item.padding {
        return Err(format!("Error: {}", e));
    }

    // 根据算法选择初始向量长度和密匙长度
    let (iv_len, key_len) = match encrypt_item.algorithm.as_ref().unwrap() {
        EncryptAlgorithm::DES => (8, 8),
        EncryptAlgorithm::AES => (16, 16),
    };
    if iv_len != encrypt_item.iv.as_bytes().len() {
        return Err(format!("Error: Wrong IV Length!Expect {}", iv_len));
    }
    if key_len != encrypt_item.key.as_bytes().len() {
        return Err(format!("Error: Wrong Key Length!Expect {}", key_len));
    }
    let mut buffer = [0u8; 512];
    let s = url_decode(encrypt_item.message.as_str().to_string());
    let pos = s.as_bytes().len();
    buffer[..pos].copy_from_slice(s.as_bytes());
    let mut decrypt_buffer = vec![];
    if !flag {
        decrypt_buffer = decode(s.as_str()).unwrap();
    }
    let ciphertext = match encrypt_item.algorithm.unwrap() {
        EncryptAlgorithm::DES => match encrypt_item.mode.unwrap() {
            EncryptMode::CBC => match encrypt_item.padding.unwrap() {
                EncryptPaddingMode::Pkcs7 => {
                    let cipher = CbcDesPkcs7::new_var(
                        encrypt_item.key.as_bytes(),
                        encrypt_item.iv.as_bytes(),
                    )
                    .unwrap();
                    if flag {
                        cipher.encrypt(&mut buffer, pos).unwrap()
                    } else {
                        cipher.decrypt(&mut decrypt_buffer).unwrap()
                    }
                }
                EncryptPaddingMode::ZeroPadding => {
                    let cipher = CbcDesZeroPadding::new_var(
                        encrypt_item.key.as_bytes(),
                        encrypt_item.iv.as_bytes(),
                    )
                    .unwrap();
                    if flag {
                        cipher.encrypt(&mut buffer, pos).unwrap()
                    } else {
                        cipher.decrypt(&mut decrypt_buffer).unwrap()
                    }
                }
                EncryptPaddingMode::NoPadding => {
                    let cipher = CbcDesNoPadding::new_var(
                        encrypt_item.key.as_bytes(),
                        encrypt_item.iv.as_bytes(),
                    )
                    .unwrap();
                    if flag {
                        cipher.encrypt(&mut buffer, pos).unwrap()
                    } else {
                        cipher.decrypt(&mut decrypt_buffer).unwrap()
                    }
                }
                EncryptPaddingMode::Iso7816 => {
                    let cipher = CbcDesIso7816::new_var(
                        encrypt_item.key.as_bytes(),
                        encrypt_item.iv.as_bytes(),
                    )
                    .unwrap();
                    if flag {
                        cipher.encrypt(&mut buffer, pos).unwrap()
                    } else {
                        cipher.decrypt(&mut decrypt_buffer).unwrap()
                    }
                }
                EncryptPaddingMode::AnsiX923 => {
                    let cipher = CbcDesAnsiX923::new_var(
                        encrypt_item.key.as_bytes(),
                        encrypt_item.iv.as_bytes(),
                    )
                    .unwrap();
                    if flag {
                        cipher.encrypt(&mut buffer, pos).unwrap()
                    } else {
                        cipher.decrypt(&mut decrypt_buffer).unwrap()
                    }
                }
            },
            EncryptMode::ECB => match encrypt_item.padding.unwrap() {
                EncryptPaddingMode::Pkcs7 => {
                    let cipher = EcbDesPkcs7::new_var(
                        encrypt_item.key.as_bytes(),
                        encrypt_item.iv.as_bytes(),
                    )
                    .unwrap();
                    if flag {
                        cipher.encrypt(&mut buffer, pos).unwrap()
                    } else {
                        cipher.decrypt(&mut decrypt_buffer).unwrap()
                    }
                }
                EncryptPaddingMode::ZeroPadding => {
                    let cipher = EcbDesZeroPadding::new_var(
                        encrypt_item.key.as_bytes(),
                        encrypt_item.iv.as_bytes(),
                    )
                    .unwrap();
                    if flag {
                        cipher.encrypt(&mut buffer, pos).unwrap()
                    } else {
                        cipher.decrypt(&mut decrypt_buffer).unwrap()
                    }
                }
                EncryptPaddingMode::NoPadding => {
                    let cipher = EcbDesNoPadding::new_var(
                        encrypt_item.key.as_bytes(),
                        encrypt_item.iv.as_bytes(),
                    )
                    .unwrap();
                    if flag {
                        cipher.encrypt(&mut buffer, pos).unwrap()
                    } else {
                        cipher.decrypt(&mut decrypt_buffer).unwrap()
                    }
                }
                EncryptPaddingMode::Iso7816 => {
                    let cipher = EcbDesIso7816::new_var(
                        encrypt_item.key.as_bytes(),
                        encrypt_item.iv.as_bytes(),
                    )
                    .unwrap();
                    if flag {
                        cipher.encrypt(&mut buffer, pos).unwrap()
                    } else {
                        cipher.decrypt(&mut decrypt_buffer).unwrap()
                    }
                }
                EncryptPaddingMode::AnsiX923 => {
                    let cipher = EcbDesAnsiX923::new_var(
                        encrypt_item.key.as_bytes(),
                        encrypt_item.iv.as_bytes(),
                    )
                    .unwrap();
                    if flag {
                        cipher.encrypt(&mut buffer, pos).unwrap()
                    } else {
                        cipher.decrypt(&mut decrypt_buffer).unwrap()
                    }
                }
            },
            EncryptMode::OFB => match encrypt_item.padding.unwrap() {
                EncryptPaddingMode::Pkcs7 => {
                    let cipher = OfbDesPkcs7::new_var(
                        encrypt_item.key.as_bytes(),
                        encrypt_item.iv.as_bytes(),
                    )
                    .unwrap();
                    if flag {
                        cipher.encrypt(&mut buffer, pos).unwrap()
                    } else {
                        cipher.decrypt(&mut decrypt_buffer).unwrap()
                    }
                }
                EncryptPaddingMode::ZeroPadding => {
                    let cipher = OfbDesZeroPadding::new_var(
                        encrypt_item.key.as_bytes(),
                        encrypt_item.iv.as_bytes(),
                    )
                    .unwrap();
                    if flag {
                        cipher.encrypt(&mut buffer, pos).unwrap()
                    } else {
                        cipher.decrypt(&mut decrypt_buffer).unwrap()
                    }
                }
                EncryptPaddingMode::NoPadding => {
                    let cipher = OfbDesNoPadding::new_var(
                        encrypt_item.key.as_bytes(),
                        encrypt_item.iv.as_bytes(),
                    )
                    .unwrap();
                    if flag {
                        cipher.encrypt(&mut buffer, pos).unwrap()
                    } else {
                        cipher.decrypt(&mut decrypt_buffer).unwrap()
                    }
                }
                EncryptPaddingMode::Iso7816 => {
                    let cipher = OfbDesIso7816::new_var(
                        encrypt_item.key.as_bytes(),
                        encrypt_item.iv.as_bytes(),
                    )
                    .unwrap();
                    if flag {
                        cipher.encrypt(&mut buffer, pos).unwrap()
                    } else {
                        cipher.decrypt(&mut decrypt_buffer).unwrap()
                    }
                }
                EncryptPaddingMode::AnsiX923 => {
                    let cipher = OfbDesAnsiX923::new_var(
                        encrypt_item.key.as_bytes(),
                        encrypt_item.iv.as_bytes(),
                    )
                    .unwrap();
                    if flag {
                        cipher.encrypt(&mut buffer, pos).unwrap()
                    } else {
                        cipher.decrypt(&mut decrypt_buffer).unwrap()
                    }
                }
            },
            EncryptMode::CFB => match encrypt_item.padding.unwrap() {
                EncryptPaddingMode::Pkcs7 => {
                    let cipher = CfbDesPkcs7::new_var(
                        encrypt_item.key.as_bytes(),
                        encrypt_item.iv.as_bytes(),
                    )
                    .unwrap();
                    if flag {
                        cipher.encrypt(&mut buffer, pos).unwrap()
                    } else {
                        cipher.decrypt(&mut decrypt_buffer).unwrap()
                    }
                }
                EncryptPaddingMode::ZeroPadding => {
                    let cipher = CfbDesZeroPadding::new_var(
                        encrypt_item.key.as_bytes(),
                        encrypt_item.iv.as_bytes(),
                    )
                    .unwrap();
                    if flag {
                        cipher.encrypt(&mut buffer, pos).unwrap()
                    } else {
                        cipher.decrypt(&mut decrypt_buffer).unwrap()
                    }
                }
                EncryptPaddingMode::NoPadding => {
                    let cipher = CfbDesNoPadding::new_var(
                        encrypt_item.key.as_bytes(),
                        encrypt_item.iv.as_bytes(),
                    )
                    .unwrap();
                    if flag {
                        cipher.encrypt(&mut buffer, pos).unwrap()
                    } else {
                        cipher.decrypt(&mut decrypt_buffer).unwrap()
                    }
                }
                EncryptPaddingMode::Iso7816 => {
                    let cipher = CfbDesIso7816::new_var(
                        encrypt_item.key.as_bytes(),
                        encrypt_item.iv.as_bytes(),
                    )
                    .unwrap();
                    if flag {
                        cipher.encrypt(&mut buffer, pos).unwrap()
                    } else {
                        cipher.decrypt(&mut decrypt_buffer).unwrap()
                    }
                }
                EncryptPaddingMode::AnsiX923 => {
                    let cipher = CfbDesAnsiX923::new_var(
                        encrypt_item.key.as_bytes(),
                        encrypt_item.iv.as_bytes(),
                    )
                    .unwrap();
                    if flag {
                        cipher.encrypt(&mut buffer, pos).unwrap()
                    } else {
                        cipher.decrypt(&mut decrypt_buffer).unwrap()
                    }
                }
            },
        },
        EncryptAlgorithm::AES => match encrypt_item.mode.unwrap() {
            EncryptMode::CBC => match encrypt_item.padding.unwrap() {
                EncryptPaddingMode::Pkcs7 => {
                    let cipher = CbcAes128Pkcs7::new_var(
                        encrypt_item.key.as_bytes(),
                        encrypt_item.iv.as_bytes(),
                    )
                    .unwrap();
                    if flag {
                        cipher.encrypt(&mut buffer, pos).unwrap()
                    } else {
                        cipher.decrypt(&mut decrypt_buffer).unwrap()
                    }
                }
                EncryptPaddingMode::ZeroPadding => {
                    let cipher = CbcAes128ZeroPadding::new_var(
                        encrypt_item.key.as_bytes(),
                        encrypt_item.iv.as_bytes(),
                    )
                    .unwrap();
                    if flag {
                        cipher.encrypt(&mut buffer, pos).unwrap()
                    } else {
                        cipher.decrypt(&mut decrypt_buffer).unwrap()
                    }
                }
                EncryptPaddingMode::NoPadding => {
                    let cipher = CbcAes128NoPadding::new_var(
                        encrypt_item.key.as_bytes(),
                        encrypt_item.iv.as_bytes(),
                    )
                    .unwrap();
                    if flag {
                        cipher.encrypt(&mut buffer, pos).unwrap()
                    } else {
                        cipher.decrypt(&mut decrypt_buffer).unwrap()
                    }
                }
                EncryptPaddingMode::Iso7816 => {
                    let cipher = CbcAes128Iso7816::new_var(
                        encrypt_item.key.as_bytes(),
                        encrypt_item.iv.as_bytes(),
                    )
                    .unwrap();
                    if flag {
                        cipher.encrypt(&mut buffer, pos).unwrap()
                    } else {
                        cipher.decrypt(&mut decrypt_buffer).unwrap()
                    }
                }
                EncryptPaddingMode::AnsiX923 => {
                    let cipher = CbcAes128AnsiX923::new_var(
                        encrypt_item.key.as_bytes(),
                        encrypt_item.iv.as_bytes(),
                    )
                    .unwrap();
                    if flag {
                        cipher.encrypt(&mut buffer, pos).unwrap()
                    } else {
                        cipher.decrypt(&mut decrypt_buffer).unwrap()
                    }
                }
            },
            EncryptMode::ECB => match encrypt_item.padding.unwrap() {
                EncryptPaddingMode::Pkcs7 => {
                    let cipher = EcbAes128Pkcs7::new_var(
                        encrypt_item.key.as_bytes(),
                        encrypt_item.iv.as_bytes(),
                    )
                    .unwrap();
                    if flag {
                        cipher.encrypt(&mut buffer, pos).unwrap()
                    } else {
                        cipher.decrypt(&mut decrypt_buffer).unwrap()
                    }
                }
                EncryptPaddingMode::ZeroPadding => {
                    let cipher = EcbAes128ZeroPadding::new_var(
                        encrypt_item.key.as_bytes(),
                        encrypt_item.iv.as_bytes(),
                    )
                    .unwrap();
                    if flag {
                        cipher.encrypt(&mut buffer, pos).unwrap()
                    } else {
                        cipher.decrypt(&mut decrypt_buffer).unwrap()
                    }
                }
                EncryptPaddingMode::NoPadding => {
                    let cipher = EcbAes128NoPadding::new_var(
                        encrypt_item.key.as_bytes(),
                        encrypt_item.iv.as_bytes(),
                    )
                    .unwrap();
                    if flag {
                        cipher.encrypt(&mut buffer, pos).unwrap()
                    } else {
                        cipher.decrypt(&mut decrypt_buffer).unwrap()
                    }
                }
                EncryptPaddingMode::Iso7816 => {
                    let cipher = EcbAes128Iso7816::new_var(
                        encrypt_item.key.as_bytes(),
                        encrypt_item.iv.as_bytes(),
                    )
                    .unwrap();
                    if flag {
                        cipher.encrypt(&mut buffer, pos).unwrap()
                    } else {
                        cipher.decrypt(&mut decrypt_buffer).unwrap()
                    }
                }
                EncryptPaddingMode::AnsiX923 => {
                    let cipher = EcbAes128AnsiX923::new_var(
                        encrypt_item.key.as_bytes(),
                        encrypt_item.iv.as_bytes(),
                    )
                    .unwrap();
                    if flag {
                        cipher.encrypt(&mut buffer, pos).unwrap()
                    } else {
                        cipher.decrypt(&mut decrypt_buffer).unwrap()
                    }
                }
            },
            EncryptMode::OFB => match encrypt_item.padding.unwrap() {
                EncryptPaddingMode::Pkcs7 => {
                    let cipher = OfbAes128Pkcs7::new_var(
                        encrypt_item.key.as_bytes(),
                        encrypt_item.iv.as_bytes(),
                    )
                    .unwrap();
                    if flag {
                        cipher.encrypt(&mut buffer, pos).unwrap()
                    } else {
                        cipher.decrypt(&mut decrypt_buffer).unwrap()
                    }
                }
                EncryptPaddingMode::ZeroPadding => {
                    let cipher = OfbAes128ZeroPadding::new_var(
                        encrypt_item.key.as_bytes(),
                        encrypt_item.iv.as_bytes(),
                    )
                    .unwrap();
                    if flag {
                        cipher.encrypt(&mut buffer, pos).unwrap()
                    } else {
                        cipher.decrypt(&mut decrypt_buffer).unwrap()
                    }
                }
                EncryptPaddingMode::NoPadding => {
                    let cipher = OfbAes128NoPadding::new_var(
                        encrypt_item.key.as_bytes(),
                        encrypt_item.iv.as_bytes(),
                    )
                    .unwrap();
                    if flag {
                        cipher.encrypt(&mut buffer, pos).unwrap()
                    } else {
                        cipher.decrypt(&mut decrypt_buffer).unwrap()
                    }
                }
                EncryptPaddingMode::Iso7816 => {
                    let cipher = OfbAes128Iso7816::new_var(
                        encrypt_item.key.as_bytes(),
                        encrypt_item.iv.as_bytes(),
                    )
                    .unwrap();
                    if flag {
                        cipher.encrypt(&mut buffer, pos).unwrap()
                    } else {
                        cipher.decrypt(&mut decrypt_buffer).unwrap()
                    }
                }
                EncryptPaddingMode::AnsiX923 => {
                    let cipher = OfbAes128AnsiX923::new_var(
                        encrypt_item.key.as_bytes(),
                        encrypt_item.iv.as_bytes(),
                    )
                    .unwrap();
                    if flag {
                        cipher.encrypt(&mut buffer, pos).unwrap()
                    } else {
                        cipher.decrypt(&mut decrypt_buffer).unwrap()
                    }
                }
            },
            EncryptMode::CFB => match encrypt_item.padding.unwrap() {
                EncryptPaddingMode::Pkcs7 => {
                    let cipher = CfbAes128Pkcs7::new_var(
                        encrypt_item.key.as_bytes(),
                        encrypt_item.iv.as_bytes(),
                    )
                    .unwrap();
                    if flag {
                        cipher.encrypt(&mut buffer, pos).unwrap()
                    } else {
                        cipher.decrypt(&mut decrypt_buffer).unwrap()
                    }
                }
                EncryptPaddingMode::ZeroPadding => {
                    let cipher = CfbAes128ZeroPadding::new_var(
                        encrypt_item.key.as_bytes(),
                        encrypt_item.iv.as_bytes(),
                    )
                    .unwrap();
                    if flag {
                        cipher.encrypt(&mut buffer, pos).unwrap()
                    } else {
                        cipher.decrypt(&mut decrypt_buffer).unwrap()
                    }
                }
                EncryptPaddingMode::NoPadding => {
                    let cipher = CfbAes128NoPadding::new_var(
                        encrypt_item.key.as_bytes(),
                        encrypt_item.iv.as_bytes(),
                    )
                    .unwrap();
                    if flag {
                        cipher.encrypt(&mut buffer, pos).unwrap()
                    } else {
                        cipher.decrypt(&mut decrypt_buffer).unwrap()
                    }
                }
                EncryptPaddingMode::Iso7816 => {
                    let cipher = CfbAes128Iso7816::new_var(
                        encrypt_item.key.as_bytes(),
                        encrypt_item.iv.as_bytes(),
                    )
                    .unwrap();
                    if flag {
                        cipher.encrypt(&mut buffer, pos).unwrap()
                    } else {
                        cipher.decrypt(&mut decrypt_buffer).unwrap()
                    }
                }
                EncryptPaddingMode::AnsiX923 => {
                    let cipher = CfbAes128AnsiX923::new_var(
                        encrypt_item.key.as_bytes(),
                        encrypt_item.iv.as_bytes(),
                    )
                    .unwrap();
                    if flag {
                        cipher.encrypt(&mut buffer, pos).unwrap()
                    } else {
                        cipher.decrypt(&mut decrypt_buffer).unwrap()
                    }
                }
            },
        },
    };
    if flag {
        Ok(encode(ciphertext))
    } else {
        Ok(String::from_utf8(ciphertext.to_vec()).unwrap())
    }
}
/// 处理RSA的加解密
pub fn rsa_handle(rsa_crypt_item: Form<RsaCryptItem>, encrypt: bool) -> Result<String, String> {
    let keys = url_decode(rsa_crypt_item.keys.to_string());
    let message = url_decode(rsa_crypt_item.message.to_string());
    let der_encoded =
        keys.lines()
            .filter(|line| !line.starts_with("-"))
            .fold(String::new(), |mut data, line| {
                data.push_str(&line);
                data
            });
    let der_bytes = base64::decode(&der_encoded).unwrap();
    let mut rng = OsRng;
    if encrypt {
        let public_key = if rsa_crypt_item.mode.contains("pkcs8") {
            RSAPublicKey::from_pkcs8(&der_bytes).unwrap()
        } else {
            RSAPublicKey::from_pkcs1(&der_bytes).unwrap()
        };
        let enc_data = if rsa_crypt_item.padding.contains("PKCS1v15") {
            public_key
                .encrypt(
                    &mut rng,
                    PaddingScheme::new_pkcs1v15_encrypt(),
                    message.as_bytes(),
                )
                .unwrap()
        } else {
            public_key
                .encrypt(
                    &mut rng,
                    PaddingScheme::new_pkcs1v15_encrypt(),
                    message.as_bytes(),
                )
                .unwrap()
        };
        Ok(encode(&enc_data))
    } else {
        let private_key = if rsa_crypt_item.mode.contains("pkcs8") {
            RSAPrivateKey::from_pkcs8(&der_bytes).unwrap()
        } else {
            RSAPrivateKey::from_pkcs1(&der_bytes).unwrap()
        };
        let decoded_data = decode(message.as_bytes()).unwrap();
        let dec_data = if rsa_crypt_item.padding.contains("PKCS1v15") {
            private_key
                .decrypt(PaddingScheme::new_pkcs1v15_encrypt(), &decoded_data)
                .unwrap()
        } else {
            private_key
                .decrypt(PaddingScheme::new_pkcs1v15_encrypt(), &decoded_data)
                .unwrap()
        };
        Ok(String::from_utf8(dec_data).unwrap())
    }
}
// 处理
pub fn dh_handle(dh_item: Form<DHItem>) -> Result<String, String> {
    let public_key = url_decode(dh_item.public_key.to_string());
    let final_packet = url_decode(dh_item.final_packet.to_string());
    let der_encoded = public_key
        .lines()
        .filter(|line| !line.starts_with("-"))
        .fold(String::new(), |mut data, line| {
            data.push_str(&line);
            data
        });
    let der_bytes = base64::decode(&der_encoded).unwrap();
    let mut rng = OsRng;
    let public_key = if dh_item.mode.contains("pkcs8") {
        RSAPublicKey::from_pkcs8(&der_bytes).unwrap()
    } else {
        RSAPublicKey::from_pkcs1(&der_bytes).unwrap()
    };
    let mut raw_final_packet = String::new();
    let mut signature = Vec::new();
    for (i, data) in final_packet.split("|").enumerate() {
        if i == 0 {
            raw_final_packet = data.to_string();
        } else {
            signature = decode(data.to_string()).unwrap();
        }
    }
    let mut hasher = Sha3_256::new();
    Digest::update(&mut hasher, raw_final_packet.as_bytes());
    let raw_final_packet_result = hasher.finalize();
    let raw_final_packet_result_slice = raw_final_packet_result.as_slice();
    if public_key
        .verify(
            PaddingScheme::new_pkcs1v15_sign(None),
            raw_final_packet_result_slice,
            &signature,
        )
        .is_err()
    {
        return Err(format!("Error: Signature Verification Failed"));
    }
    let mut Ya: u32 = 0;
    let mut p: u32 = 0;
    let mut g: u32 = 0;
    let mut mac = String::new();
    for (i, item) in raw_final_packet.split("`").enumerate() {
        match i {
            0 => {
                if let Ok(tmp) = item.parse::<u32>() {
                    p = tmp;
                } else {
                    return Err(format!("Error: Can't parse {} to Unsigned Integer", item));
                }
            }
            1 => {
                if let Ok(tmp) = item.parse::<u32>() {
                    g = tmp;
                } else {
                    return Err(format!("Error: Can't parse {} to Unsigned Integer", item));
                }
            }
            2 => {
                if let Ok(tmp) = item.parse::<u32>() {
                    Ya = tmp;
                } else {
                    return Err(format!("Error: Can't parse {} to Unsigned Integer", item));
                }
            }
            3 => {
                mac = item.to_string();
            }
            _ => {
                break;
            }
        }
    }
    let mac = decode(mac).unwrap();
    let mut hasher = Sha3_256::new();
    Digest::update(&mut hasher, Ya.to_string().as_bytes());
    let raw_mac_result = hasher.finalize();
    let raw_mac_result_slice = raw_mac_result.as_slice();
    let new_mac = Vec::from(raw_mac_result_slice);
    if new_mac != mac {
        return Err(format!("Error: Mac failed"));
    }
    let B = random::<u32>() % (p - 1) + 1;
    let Yb = fast_mod(g, B, p);
    let shared_k = fast_mod(Ya, B, p);
    Ok(format!("{}```{}&&&{}", Yb, shared_k, B))
}
/// 仿射加密处理函数
pub fn affine_handle(
    affine_crypt_item: Form<AffineCryptItem>,
    flag: bool,
) -> Result<String, String> {
    let mut lower_a;
    let mut lower_b;
    let mut upper_a;
    let mut upper_b;
    let mut number_a;
    let mut number_b;
    if let Ok(tmp) = affine_crypt_item.lower_a.parse::<u32>() {
        lower_a = tmp;
    } else {
        return Err(format!(
            "Error: Can't parse {} to Integer",
            affine_crypt_item.lower_a
        ));
    }
    if let Ok(tmp) = affine_crypt_item.lower_b.parse::<u32>() {
        lower_b = tmp;
    } else {
        return Err(format!(
            "Error: Can't parse {} to Integer",
            affine_crypt_item.lower_b
        ));
    }
    if let Ok(tmp) = affine_crypt_item.upper_a.parse::<u32>() {
        upper_a = tmp;
    } else {
        return Err(format!(
            "Error: Can't parse {} to Integer",
            affine_crypt_item.upper_a
        ));
    }
    if let Ok(tmp) = affine_crypt_item.upper_b.parse::<u32>() {
        upper_b = tmp;
    } else {
        return Err(format!(
            "Error: Can't parse {} to Integer",
            affine_crypt_item.upper_b
        ));
    }
    if let Ok(tmp) = affine_crypt_item.number_a.parse::<u32>() {
        number_a = tmp;
    } else {
        return Err(format!(
            "Error: Can't parse {} to Integer",
            affine_crypt_item.number_a
        ));
    }
    if let Ok(tmp) = affine_crypt_item.number_b.parse::<u32>() {
        number_b = tmp;
    } else {
        return Err(format!(
            "Error: Can't parse {} to Integer",
            affine_crypt_item.number_b
        ));
    }
    if gcd(lower_a, 26) != 1 {
        return Err(format!("Error: Gcd({}, {}) Not equal 1", lower_a, 26));
    }
    if gcd(upper_a, 26) != 1 {
        return Err(format!("Error: Gcd({}, {}) Not equal 1", upper_a, 26));
    }
    if gcd(number_a, 10) != 1 {
        return Err(format!("Error: Gcd({}, {}) Not equal 1", number_a, 10));
    }
    let msg = url_decode(affine_crypt_item.message.to_string());
    if flag {
        // Encrypt
        let mut ans = String::new();
        for ch in msg.chars() {
            if ch.is_ascii_alphabetic() {
                if ch.is_uppercase() {
                    // 大写字母
                    let x = ch as u32 - 'A' as u32;
                    let y = (upper_a * x + upper_b) % 26;
                    let target = 'A' as u32 + y;
                    let new_ch = char::try_from(target).unwrap();
                    ans.push(new_ch);
                } else {
                    // 小写字母
                    let x = ch as u32 - 'a' as u32;
                    let y = (lower_a * x + lower_b) % 26;
                    let target = 'a' as u32 + y;
                    let new_ch = char::try_from(target).unwrap();
                    ans.push(new_ch);
                }
            } else if ch.is_ascii_digit() {
                // 数字
                let x = ch as u32 - '0' as u32;
                let y = (number_a * x + number_b) % 26;
                let target = '0' as u32 + y;
                let new_ch = char::try_from(target).unwrap();
                ans.push(new_ch);
            } else {
                ans.push(ch);
            }
        }
        return Ok(ans);
    } else {
        // Decrypt
        let lower_a_ = exgcd(lower_a as i32, 26) as u32;
        let upper_a_ = exgcd(upper_a as i32, 26) as u32;
        let number_a_ = exgcd(number_a as i32, 10) as u32;
        let mut ans = String::new();
        for ch in msg.chars() {
            if ch.is_ascii_alphabetic() {
                if ch.is_uppercase() {
                    // 大写字母
                    let x = ch as u32 - 'A' as u32;
                    let y = (upper_a_ * (x + 26 - upper_b)) % 26;
                    let target = 'A' as u32 + y;
                    let new_ch = char::try_from(target).unwrap();
                    ans.push(new_ch);
                } else {
                    // 小写字母
                    let x = ch as u32 - 'a' as u32;
                    let y = (lower_a_ * (x + 26 - lower_b)) % 26;
                    let target = 'a' as u32 + y;
                    let new_ch = char::try_from(target).unwrap();
                    ans.push(new_ch);
                }
            } else if ch.is_ascii_digit() {
                // 数字
                let x = ch as u32 - '0' as u32;
                let y = (number_a_ * (x + 10 - number_b)) % 10;
                let target = '0' as u32 + y;
                let new_ch = char::try_from(target).unwrap();
                ans.push(new_ch);
            } else {
                ans.push(ch);
            }
        }
        return Ok(ans);
    }
}
/// 扩展欧几里得算法
fn exgcd(a: i32, m: i32) -> i32 {
    let mut a = a;
    let mut b = m;
    let mut s0 = 1;
    let mut t0 = 0;
    let mut s1 = 0;
    let mut t1 = 1;
    while b != 1 {
        let c = a % b;
        let k = a / b;
        let s = s0 - k * s1; // 更新s
        let t = t0 - k * t1; // 更新t
                             // 下一轮循环的参数更新
        a = b;
        b = c;
        t0 = t1;
        s0 = s1;
        t1 = t;
        s1 = s;
    }
    while s1 < 0 {
        s1 += m;
    }
    return s1;
}
/// 求最大公因数
fn gcd(a: u32, b: u32) -> u32 {
    if b == 0 {
        a
    } else {
        gcd(b, a % b)
    }
}
/// 处理RC4加密算法
pub fn rc4_handle(rc4_crypt_item: Form<Rc4CryptItem>) -> Result<String, String> {
    let mut key = rc4_crypt_item.key.to_string();
    let mut k = Vec::from(key.as_bytes());
    let mut rc4_cipher = Rc4::new(k);
    let mut msg = url_decode(rc4_crypt_item.message.to_string());
    let mut buffer = [0u8; 512];
    let mut pos;
    if rc4_crypt_item.flag == "False" {
        let decrypt_msg = decode(msg.as_bytes()).unwrap();
        pos = decrypt_msg.len();
        buffer[..pos].copy_from_slice(&decrypt_msg);
    } else {
        pos = msg.as_bytes().len();
        buffer[..pos].copy_from_slice(msg.as_bytes());
    }
    rc4_cipher.crypt(&mut buffer);
    if rc4_crypt_item.flag == "True" {
        return Ok(encode(buffer[..pos].to_vec()));
    } else {
        return Ok(String::from_utf8(buffer[..pos].to_vec()).unwrap());
    }
}
/// 处理LFSR-JK触发器流密码加密
pub fn lfsr_jk_handle(lfsr_jk_item: Form<LfsrJkItem>, flag: bool) -> Result<String, String> {
    let mut j_state;
    let mut k_state;
    let mut j_state_c;
    let mut k_state_c;
    if let Ok(tmp) = lfsr_jk_item.j_state.parse::<u32>() {
        j_state = tmp;
    } else {
        return Err(format!(
            "Error: Can't parse {} to Integer",
            lfsr_jk_item.j_state
        ));
    }
    if let Ok(tmp) = lfsr_jk_item.k_state.parse::<u32>() {
        k_state = tmp;
    } else {
        return Err(format!(
            "Error: Can't parse {} to Integer",
            lfsr_jk_item.k_state
        ));
    }
    if let Ok(tmp) = lfsr_jk_item.j_state_c.parse::<u32>() {
        j_state_c = tmp;
    } else {
        return Err(format!(
            "Error: Can't parse {} to Integer",
            lfsr_jk_item.j_state_c
        ));
    }
    if let Ok(tmp) = lfsr_jk_item.k_state_c.parse::<u32>() {
        k_state_c = tmp;
    } else {
        return Err(format!(
            "Error: Can't parse {} to Integer",
            lfsr_jk_item.k_state_c
        ));
    }
    let mut lfsr_jk_cipher = LfsrJk::new(j_state, k_state, j_state_c, k_state_c, 0);
    let mut msg = url_decode(lfsr_jk_item.message.to_string());
    let mut buffer = [0u8; 512];
    let mut pos;
    if flag {
        pos = msg.as_bytes().len();
        buffer[..pos].copy_from_slice(msg.as_bytes());
    } else {
        let decrypt_msg = decode(msg.as_bytes()).unwrap();
        pos = decrypt_msg.len();
        buffer[..pos].copy_from_slice(&decrypt_msg);
    }
    lfsr_jk_cipher.crypt(&mut buffer[..pos]);
    if flag {
        return Ok(encode(buffer[..pos].to_vec()));
    } else {
        return Ok(String::from_utf8(buffer[..pos].to_vec()).unwrap());
    }
}
/// 用于处理素数产生
#[derive(Debug)]
pub struct Primes {
    primes: Vec<u32>,
    biggest: u32,
    len: usize,
}
impl Primes {
    pub fn new() -> Self {
        Self {
            primes: vec![2],
            biggest: 2,
            len: 1,
        }
    }
    pub fn update_primes(&mut self, target: u32) {
        if self.biggest > target {
            return;
        } else {
            for x in self.biggest..=target {
                if Self::is_prime(x) {
                    self.primes.push(x);
                    //println!("push prime: {}", x);
                }
            }
            self.biggest = target;
            self.len = self.primes.len();
        }
    }
    /// 判断x是否为素数
    pub fn is_prime(x: u32) -> bool {
        if x == 2 {
            return true;
        }
        // 获取x的开方
        let k = f64::from(x).sqrt().ceil() as u32;
        for i in 2..=k {
            if x % i == 0 {
                return false;
            }
        }
        return true;
    }
    /// 素因子分解，返回值为(p, cnt)的数组
    pub fn decompose(&mut self, n: u32) -> Vec<(u32, u32)> {
        let mut ans = vec![];
        if self.biggest < n {
            self.update_primes(n);
        }
        let mut prime_index = 0;
        let mut prime = self.primes[0];
        let mut cnt = 0;
        let mut n_tmp = n;
        while n_tmp > 1 && prime_index < self.len {
            //println!("n: {}, prime: {}", n_tmp, prime);
            if n_tmp % prime == 0 {
                n_tmp /= prime;
                cnt += 1;
            } else {
                if cnt > 0 {
                    ans.push((prime, cnt));
                    cnt = 0;
                }
                prime_index += 1;
                prime = self.primes[prime_index];
            }
        }
        if cnt > 0 {
            ans.push((prime, cnt));
        }
        if n_tmp != 1 {
            panic!("Error");
        }
        ans
    }
    pub fn get_a_prime(&self) -> u32 {
        let rand_idx = (random::<usize>() % (self.len - 1)) + 1;
        self.primes[rand_idx]
    }
}
/// 快速模运算
pub fn fast_mod(n: u32, p: u32, m: u32) -> u32 {
    let mut scale = n % m;
    let mut ans = 1;
    let mut mask = 1;
    for _ in 0..32 {
        if p & mask > 0 {
            ans = (ans * scale) % m;
        }
        scale = (scale * scale) % m;
        mask <<= 1;
    }
    ans
}
/// 根据因式分解的结果得出所有的因子
pub fn get_factors(factors: Vec<(u32, u32)>) -> Vec<u32> {
    let (factors, factor_exp): (Vec<u32>, Vec<u32>) = factors.into_iter().unzip();
    let n = factor_exp.iter().fold(1, |mut ans, item| {
        ans *= *item + 1;
        ans
    });
    let mut count = vec![0; factors.len()];
    let mut factor;
    let mut ans = vec![];
    for _ in 0..n {
        factor = count.iter().zip(factors.iter()).fold(1, |mut acc, item| {
            acc *= (*item.1).pow(*item.0);
            acc
        });
        ans.push(factor);
        count[0] += 1;
        for i in 0..count.len() - 1 {
            if count[i] > factor_exp[i] {
                count[i] = 0;
                count[i + 1] += 1;
            } else {
                // println!("{:?}", count);
                break;
            }
        }
    }
    ans.sort();
    ans
}
/// 随机获取一个素数p的本原根
pub fn get_one_origin_primitive_root(primes: &mut Primes, p: u32) -> u32 {
    let mut ans = 0;
    let factors = primes.decompose(p - 1);
    let (factors, _): (Vec<u32>, Vec<u32>) = factors.into_iter().unzip();
    let test_exp = factors
        .into_iter()
        .map(|x| (p - 1) / x)
        .collect::<Vec<u32>>();
    let mut order = (2..p).collect::<Vec<u32>>();
    order.shuffle(&mut thread_rng());
    for x in order {
        let mut flag = true;
        for exp in test_exp.iter() {
            if fast_mod(x, *exp, p) == 1 {
                flag = false;
                break;
            }
        }
        if flag {
            ans = x;
            break;
        }
    }
    ans
}
// 处理Diffie-Hellman协议的快速生成素数与本原根
pub fn handle_diffie_hellman_generate(primes: State<Mutex<Primes>>) -> Result<String, String> {
    let mut primes = primes.lock().unwrap();
    let p = primes.get_a_prime();
    let g = get_one_origin_primitive_root(&mut primes, p);
    let a = (random::<u32>() % (p - 1)) + 1;
    Ok(format!("{}```{}&&&{}", p, g, a))
}
/// 用SHA-3哈希算法生成报文完整码
pub fn handle_sha3(sha3_hash_item: Form<Sha3HashItem>) -> Result<String, String> {
    let msg = sha3_hash_item.msg.to_string();
    let mut hasher = Sha3_256::new();
    Digest::update(&mut hasher, msg.as_bytes());
    let result = hasher.finalize();
    let result_slice = result.as_slice();
    //println!("{:?}", result_slice);
    Ok(format!("{}", encode(result_slice)))
}
/// 用RSA私钥进行签名
pub fn handle_signature(signature_item: Form<SignatureItem>) -> Result<String, String> {
    let p;
    let g;
    let Ya;
    let private_key = url_decode(signature_item.private_key.to_string());
    let mac = url_decode(signature_item.mac.to_string());
    if let Ok(tmp) = signature_item.p.parse::<u64>() {
        p = tmp;
    } else {
        return Err(format!(
            "Error: can't convert p to integer, your p is {}",
            signature_item.p
        ));
    }
    if let Ok(tmp) = signature_item.g.parse::<u64>() {
        g = tmp;
    } else {
        return Err(format!(
            "Error: can't convert g to integer, your g is {}",
            signature_item.g
        ));
    }
    if let Ok(tmp) = signature_item.Ya.parse::<u64>() {
        Ya = tmp;
    } else {
        return Err(format!(
            "Error: can't convert Ya to integer, your Ya is {}",
            signature_item.Ya
        ));
    }
    let mut final_packet = format!("{}`{}`{}`{}", p, g, Ya, mac);
    let mut hasher = Sha3_256::new();
    Digest::update(&mut hasher, final_packet.as_bytes());
    let result = hasher.finalize();
    let result_slice = result.as_slice();
    let mut rng = OsRng;
    let der_encoded = private_key
        .lines()
        .filter(|line| !line.starts_with("-"))
        .fold(String::new(), |mut data, line| {
            data.push_str(&line);
            data
        });
    let der_bytes = base64::decode(&der_encoded).unwrap();
    let private_key = if signature_item.mode.contains("pkcs8") {
        RSAPrivateKey::from_pkcs8(&der_bytes).unwrap()
    } else {
        RSAPrivateKey::from_pkcs1(&der_bytes).unwrap()
    };
    let signed_data = private_key
        .sign(PaddingScheme::new_pkcs1v15_sign(None), result_slice)
        .unwrap();
    Ok(encode(&signed_data))
}
