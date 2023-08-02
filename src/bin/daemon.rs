use aws_lc_rs::{
    error::Unspecified,
    kem::{KemPrivateKey, KemPublicKey, KYBER768_R3},
};
use clap::Parser;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

const KYBER768_R3_PUBLIC_KEY_LENGTH: usize = 1184;

fn main() -> Result<(), std::io::Error> {
    println!("I am the Daemon!");

    let listener = TcpListener::bind("127.0.0.1:8000")?;
    println!("listening started, ready to accept");

    for stream in listener.incoming() {
        thread::spawn(|| -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            let mut stream = stream?;

            println!("Connection established");
            let mut buffer = [0u8; KYBER768_R3_PUBLIC_KEY_LENGTH];

            println!(
                "Number of public key bytes read: {}",
                stream.read(&mut buffer[..])?
            );
            println!("Received public key: {:x?}", buffer);

            let (ciphertext, shared_secret) = kyber_encaps(&buffer)?;
            let _ct_num_bytes = stream.write(&ciphertext)?;

            println!();
            println!("Shared secret: {:x?}", shared_secret);
            Ok(())
        });
    }

    Ok(())
}

fn kyber_encaps(public_key_bytes: &[u8]) -> Result<(Box<[u8]>, Box<[u8]>), Unspecified> {
    let public_key = KemPublicKey::new(&KYBER768_R3, public_key_bytes)?;
    public_key.encapsulate(Unspecified, |ct, ss| Ok((ct.into(), ss.into())))
}
