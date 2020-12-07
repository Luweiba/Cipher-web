#![feature(proc_macro_hygiene, decl_macro)]
#![allow(unused)]
#[macro_use] extern crate rocket;
#[macro_use] extern crate serde_derive;
use std::collections::HashMap;
use std::sync::Mutex;
use rocket::{Request, State};
use rocket::response::Redirect;
use rocket_contrib::templates::Template;
use rocket::request::Form;
use std::thread;
mod cipher_type;
mod form;
mod handle;
mod rc4;
mod lfsr_jk;
use form::*;
use handle::*;
use rc4::*;
use lfsr_jk::*;

use rsa::{RSAPrivateKey, RSAPublicKey, PaddingScheme, PublicKeyPemEncoding};
use rsa::PublicKey;
use rand::rngs::OsRng;
use rsa::PrivateKeyPemEncoding;
#[derive(Serialize)]
struct Context {
    name: String,
    description: String,
}
#[get("/")]
fn index() -> Redirect {
    Redirect::to(uri!(get: crypto_name = "des"))
}
#[post("/encrypt", data="<encrypt_item>")]
fn encrypt(encrypt_item: Form<EncryptItem>) -> Result<String, String> {
    handle(encrypt_item, true)
}
#[post("/decrypt", data="<decrypt_item>")]
fn decrypt(decrypt_item: Form<EncryptItem>) -> Result<String, String> { handle(decrypt_item, false) }
#[post("/rsa_generate_keys", data="<rsa_keys_item>")]
fn rsa_generate_keys(rsa_keys_item: Form<RsaKeysItem>) -> Result<String, String> {
    let mut length: usize = 512;
    if rsa_keys_item.length.contains("1024bit") {
        length = 1024;
    } else if rsa_keys_item.length.contains("2048bit") {
        length = 2048;
    } else if rsa_keys_item.length.contains("4096bit") {
        length = 4096;
    } else {
        length = 512;
    }
    let mut rng = OsRng;
    let private_keys = RSAPrivateKey::new(&mut rng, length).unwrap();
    let public_keys = RSAPublicKey::from(&private_keys);
    if rsa_keys_item.mode.contains("1") {
        let mut priv_s = private_keys.to_pem_pkcs1().unwrap();
        let pub_s = public_keys.to_pem_pkcs1().unwrap();
        priv_s.push_str("```");
        priv_s.push_str(&pub_s);
        return Ok(priv_s);
    } else if rsa_keys_item.mode.contains("8") {
        let mut priv_s = private_keys.to_pem_pkcs8().unwrap();
        let pub_s = public_keys.to_pem_pkcs8().unwrap();
        priv_s.push_str("```");
        priv_s.push_str(&pub_s);
        return Ok(priv_s);
    } else {
        return Err("Error: Wrong Mode".to_string());
    }
}
#[post("/affine_encrypt", data="<affine_crypt_item>")]
fn affine_encrypt(affine_crypt_item: Form<AffineCryptItem>) -> Result<String, String> {
    affine_handle(affine_crypt_item, true)
}
#[post("/affine_decrypt", data="<affine_crypt_item>")]
fn affine_decrypt(affine_crypt_item: Form<AffineCryptItem>) -> Result<String, String> {
    affine_handle(affine_crypt_item, false)
}
#[post("/sha3", data="<sha3_hash_item>")]
fn sha3(sha3_hash_item: Form<Sha3HashItem>) -> Result<String, String> {
    handle_sha3(sha3_hash_item)
}
#[post("/rsa/crypt/encrypt", data="<rsa_crypt_item>")]
fn my_rsa_encrypt(rsa_crypt_item: Form<RsaCryptItem>) -> Result<String, String> {
    rsa_handle(rsa_crypt_item, true)
}
#[post("/rsa/crypt/decrypt", data="<rsa_crypt_item>")]
fn my_rsa_decrypt(rsa_crypt_item: Form<RsaCryptItem>) -> Result<String, String> {
    rsa_handle(rsa_crypt_item, false)
}
#[post("/handle_diffie_hellman", data = "<dh_item>")]
fn diffie_hellman(dh_item: Form<DHItem>) -> Result<String, String> {
    dh_handle(dh_item)
}
#[post("/rc4/crypt", data="<rc4_crypt_item>")]
fn rc4_crypt(rc4_crypt_item: Form<Rc4CryptItem>) -> Result<String, String> {
    rc4_handle(rc4_crypt_item)
}
#[post("/lfsr_jk/encrypt", data = "<lfsr_jk_item>")]
fn lfsr_jk_encrypt(lfsr_jk_item: Form<LfsrJkItem>) -> Result<String, String> {
    lfsr_jk_handle(lfsr_jk_item, true)
}
#[post("/signature", data = "<signature_item>")]
fn signature(signature_item: Form<SignatureItem>) -> Result<String, String> {
    handle_signature(signature_item)
}
#[post("/lfsr_jk/decrypt", data = "<lfsr_jk_item>")]
fn lfsr_jk_decrypt(lfsr_jk_item: Form<LfsrJkItem>) -> Result<String, String> {
    lfsr_jk_handle(lfsr_jk_item, false)
}
#[get("/handle_diffie_hellman_generate")]
fn diffie_hellman_generate(primes: State<Mutex<Primes>>) -> Result<String, String> {
    handle_diffie_hellman_generate(primes)
}
#[get("/diffie_hellman")]
fn get_diffie_hellman() -> Template {
    let context = Context {
        name: "dh".to_string(),
        description: "HHH".to_string(),
    };
    Template::render("d_h", &context)
}
#[get("/<crypto_name>", rank=2)]
fn get(crypto_name: String) -> Template {
    let context = Context {
        name: crypto_name.to_lowercase(),
        description: "HHH".to_string(),
    };
    Template::render("index", &context)
}
#[get("/rc4")]
fn get_rc4() -> Template {
    let context = Context {
        name: "rc4".to_string(),
        description: "HHH".to_string(),
    };
    Template::render("rc4", &context)
}
#[get("/lfsr_jk")]
fn get_lfsr_jk() -> Template {
    let context = Context {
        name: "lfsr_jk".to_string(),
        description: "HHH".to_string(),
    };
    Template::render("lfsr_jk", &context)
}
#[get("/affine")]
fn get_affine() -> Template {
    let context = Context {
        name: "affine".to_string(),
        description: "HHH".to_string(),
    };
    Template::render("affine", &context)
}
#[get("/rsa")]
fn rsa_crypt() -> Template {
    let context = Context {
        name: "rsa".to_string(),
        description: "HHH".to_string(),
    };
    Template::render("rsa_crypt", &context)
}

#[catch(404)]
fn not_found(req: &Request<'_>) -> Template {
    let mut map = HashMap::new();
    map.insert("path", req.uri().path());
    Template::render("error/404", &map)
}
fn main() {
    let mut primes = Primes::new();
    primes.update_primes(10000);
    rocket::ignite()
        .manage(Mutex::new(primes))
        .mount("/", routes![index, get, encrypt, decrypt, rsa_crypt, rsa_generate_keys, my_rsa_decrypt,
                                         my_rsa_encrypt, get_diffie_hellman, diffie_hellman, diffie_hellman_generate, get_affine, affine_decrypt,
                                         affine_encrypt, get_rc4, rc4_crypt, get_lfsr_jk, lfsr_jk_decrypt, lfsr_jk_encrypt, sha3, signature])
        .attach(Template::fairing())
        .register(catchers![not_found]).launch();
}