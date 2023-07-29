use aws_lc_rs::{
    error::Unspecified,
    kem::{KemPrivateKey, KemPublicKey, KYBER1024_R3, KYBER512_R3, KYBER768_R3},
};

// TODO: Create server and client exchange using kyber + hybrid?
fn main() {
    println!("Hello, world!");
    
    for algorithm in [&KYBER512_R3, &KYBER768_R3, &KYBER1024_R3] {
        let priv_key = KemPrivateKey::generate(algorithm).unwrap();
        assert_eq!(priv_key.algorithm(), algorithm);

        let pub_key = priv_key.compute_public_key().unwrap();

        let mut ciphertext: Vec<u8> = vec![];
        let mut alice_shared_secret: Vec<u8> = vec![];

        let alice_result = pub_key.encapsulate(Unspecified, |ct, ss| {
            ciphertext.extend_from_slice(ct);
            alice_shared_secret.extend_from_slice(ss);
            Ok(())
        });
        assert_eq!(alice_result, Ok(()));

        let mut bob_shared_secret: Vec<u8> = vec![];

        let bob_result = priv_key.decapsulate(&mut ciphertext, Unspecified, |ss| {
            bob_shared_secret.extend_from_slice(ss);
            Ok(())
        });
        assert_eq!(bob_result, Ok(()));
        assert_eq!(alice_shared_secret, bob_shared_secret);
    }
}
