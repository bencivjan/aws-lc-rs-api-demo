use aws_lc_rs::{
    error::Unspecified,
    kem::{KemPublicKey, KYBER768_R3},
};
use clap::Parser;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::io;

const KYBER768_R3_PUBLIC_KEY_LENGTH: usize = 1184;

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Server port
    #[arg(short, long, default_value_t = 8000)]
    port: u64,
}

fn main() -> Result<(), std::io::Error> {
    let args = Args::parse();
    let listener = TcpListener::bind("127.0.0.1:".to_string() + &args.port.to_string())?;
    println!("Listening on port {}, ready to accept", args.port);

    for stream in listener.incoming() {
        thread::spawn(|| -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            let mut stream = stream?;

            println!("Connection established\n");
            let mut buffer = [0u8; KYBER768_R3_PUBLIC_KEY_LENGTH];

            println!(
                "Received public key!\nNumber of public key bytes read: {}",
                stream.read(&mut buffer[..])?
            );
            println!("Public key: {:x?}\n", buffer);

            let mut input = String::new();
            io::stdin().read_line(&mut input).expect("Failed to read line");
            
            let (ciphertext, shared_secret) = kyber_encaps(&buffer)?;
            println!("Ciphertext: {:x?}", ciphertext);

            io::stdin().read_line(&mut input).expect("Failed to read line");
            let ct_num_bytes = stream.write(&ciphertext)?;

            println!("Number of ciphertext bytes sent: {}", ct_num_bytes);

            println!();
            println!("Shared secret: {:x?}\n", shared_secret);
            Ok(())
        });
    }

    Ok(())
}

fn kyber_encaps(public_key_bytes: &[u8]) -> Result<(Box<[u8]>, Box<[u8]>), Unspecified> {
    let public_key = KemPublicKey::new(&KYBER768_R3, public_key_bytes)?;
    public_key.encapsulate(Unspecified, |ct, ss| Ok((ct.into(), ss.into())))
}
