use aws_lc_rs::{
    error::Unspecified,
    kem::{KemPrivateKey, KemPublicKey, KYBER768_R3},
};
use clap::Parser;
use std::net::TcpListener;
use std::thread;
use std::io::Write;

fn main() {
    println!("I am the Daemon!");

    let listener = TcpListener::bind("127.0.0.1:8000").unwrap();
    println!("listening started, ready to accept");
    for stream in listener.incoming() {
        thread::spawn(|| {
            let mut stream = stream.unwrap();
            stream.write(b"Hello World\r\n").unwrap();
            println!("Connection established");
        });
    }
}

fn kyber_encaps(public_key_bytes: &[u8]) {
    let public_key = KemPublicKey::new(&KYBER768_R3, public_key_bytes).unwrap();
    let result = public_key.encapsulate(Unspecified, |ct, ss| {
        Ok((ct.to_vec(), ss.to_vec()))
    });
}