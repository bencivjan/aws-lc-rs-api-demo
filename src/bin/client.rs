use aws_lc_rs::{
    error::Unspecified,
    kem::{KemPrivateKey, KemPublicKey, KYBER768_R3},
};
use clap::Parser;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::str;
use std::io;

const KYBER768_R3_CIPHERTEXT_LENGTH: usize = 1088;
const KYBER768_R3_PUBLIC_KEY_LENGTH: usize = 1184;

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// IP address of the server
    #[arg(short, long, default_value_t = String::from("127.0.0.1"))]
    address: String,
    /// Server port
    #[arg(short, long, default_value_t = 8000)]
    port: u64,
}

// TODO: Create server and client exchange using kyber + hybrid?
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    println!("Address: {}", args.address);

    let mut stream = TcpStream::connect(format!("{}:{}", args.address, args.port))?;

    println!("Successfully connected to the server!");

    let (priv_key, public_key) = kyber_keygen()?;

    let mut buffer = [0u8; KYBER768_R3_PUBLIC_KEY_LENGTH];
    let mut ct_buf = [0u8; KYBER768_R3_CIPHERTEXT_LENGTH];

    buffer.copy_from_slice(public_key.as_ref());
    println!("Public key: {:x?}\n", buffer);

    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("Failed to read line");

    let pk_num_bytes = stream.write(&buffer)?;
    println!("Number of public key bytes sent: {}", pk_num_bytes);

    let ct_num_bytes = stream.read(&mut ct_buf)?;
    println!(
        "Received ciphertext!\nNumber of ciphertext bytes read: {}",
        ct_num_bytes
    );
    println!("Ciphertext: {:x?}\n", ct_buf);

    io::stdin().read_line(&mut input).expect("Failed to read line");

    let shared_secret = kyber_decaps(priv_key, &mut ct_buf)?;

    println!("Shared secret: {:x?}", shared_secret);
    Ok(())
}

fn kyber_keygen() -> Result<(KemPrivateKey, KemPublicKey), Unspecified> {
    let priv_key = KemPrivateKey::generate(&KYBER768_R3)?;
    let pub_key = priv_key.compute_public_key()?;
    Ok((priv_key, pub_key))
}

fn kyber_decaps(priv_key: KemPrivateKey, ciphertext: &mut [u8]) -> Result<Box<[u8]>, Unspecified> {
    priv_key.decapsulate(ciphertext, Unspecified, |ss| Ok(ss.into()))
}
