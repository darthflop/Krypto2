use rsa::{traits::{PrivateKeyParts, PublicKeyParts}, RsaPrivateKey, RsaPublicKey};
use rand::rngs::OsRng;

fn main() {
    
    rsa_key_gen();
}

fn rsa_key_gen() {

    // Zufälligen Generator initialisieren
    let mut rng = OsRng;

    // 3000-Bit privaten Schlüssel generieren
    let bits = 3000;
    let private_key = RsaPrivateKey::new(&mut rng, bits)
        .expect("Fehler beim Erzeugen des privaten Schlüssels");

    let _public_key = RsaPublicKey::from(&private_key);

    // Parameter ausgeben
    println!("n (Modulus): {}\n", private_key.n());
    println!("e (Public exponent): {}\n", private_key.e());
    println!("d (Private exponent): {}\n", private_key.d());
    println!("p (Prime 1): {}\n", private_key.primes()[0]);
    println!("q (Prime 2): {}\n", private_key.primes()[1]);
}