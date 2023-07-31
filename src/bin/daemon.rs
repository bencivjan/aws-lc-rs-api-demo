use aws_lc_rs::{
    error::Unspecified,
    kem::{KemPrivateKey, KemPublicKey, KYBER768_R3},
};
use clap::Parser;

fn main() {
    println!("I am the Daemon!");
}

fn kyber_encaps(public_key_bytes: &[u8]) {
    let public_key = KemPublicKey::new(&KYBER768_R3, public_key_bytes).unwrap();
    let result = public_key.encapsulate(Unspecified, |ct, ss| {
        Ok((ct.to_vec(), ss.to_vec()))
    });
}