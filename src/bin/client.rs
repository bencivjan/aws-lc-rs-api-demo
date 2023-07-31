use aws_lc_rs::{
    error::Unspecified,
    kem::{KemPrivateKey, KemPublicKey, KYBER768_R3},
};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// IP address of the server
    #[arg(short, long)]
    address: String,
    /// Server port
    #[arg(short, long, default_value_t = 443)]
    port: u64,
}

// TODO: Create server and client exchange using kyber + hybrid?
fn main() {
    let args = Args::parse();
    println!("Address: {}", args.address);
}

fn kyber_keygen() -> Result<KemPublicKey, Unspecified> {
    let priv_key = KemPrivateKey::generate(&KYBER768_R3)?;
    priv_key.compute_public_key()
}

fn kyber_decaps(priv_key: KemPrivateKey, ciphertext: &mut [u8]) {
    let result = priv_key.decapsulate(ciphertext, Unspecified, |ss| {
        Ok(ss.to_vec())
    });
}
