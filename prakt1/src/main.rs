use rsa::{traits::{PrivateKeyParts, PublicKeyParts}, BigUint, RsaPrivateKey, RsaPublicKey};
use rand::{rngs::OsRng, Rng};
use num_traits::One;
use num_bigint_dig::traits::ModInverse;


struct Keypair{
    public_key: RsaPublicKey,
    private_key: RsaPrivateKey
}

fn main() {
    
    let keypair = rsa_key_gen();
    universal_forgery(keypair);
}


fn universal_forgery(keypair: Keypair) {

    let public_key = keypair.public_key;
    let message = BigUint::from(1234u32);
    let e = public_key.e();
    let n = public_key.n();
    let mut r: BigUint;
    let mut rng = rand::thread_rng();

    loop {

        // random r generation
        let lower = BigUint::from(2u32);
        let upper = n.clone();
        r = rng.gen_range(lower..upper);

        println!("r: {}", r);

        // check if r^e % n != 1
        if r.modpow(e, n) != BigUint::one(){
            break;
        }

    }
    println!("r: {}", r);
    // oracle calculating signature s'
    let oracle_signature = &r * message.modpow(&keypair.private_key.d(), &n);


    let inverse = r.mod_inverse(n);

    let s = inverse * oracle_signature % n;
    //TODO


    println!("Message: {}", message);
    println!("Signature from Oracle: {}", &oracle_signature);



}


fn rsa_key_gen() -> Keypair{

    // initiate generator
    let mut rng = OsRng;

    // 3000-Bit private key gen
    let bits = 30;
    let private_key = RsaPrivateKey::new(&mut rng, bits)
        .expect("Fehler beim Erzeugen des privaten Schlüssels");

    let public_key = RsaPublicKey::from(&private_key);

    // print paramenters
    println!("n (Modulus): {}\n", private_key.n());
    println!("e (Public exponent): {}\n", private_key.e());
    println!("d (Private exponent): {}\n", private_key.d());
    println!("p (Prime 1): {}\n", private_key.primes()[0]);
    println!("q (Prime 2): {}\n", private_key.primes()[1]);

    // save keypair for return
    let keypair = Keypair {public_key: public_key, private_key: private_key};
    return keypair;
}


/* 
fn mod_inverse(a: &BigUint, c: &BigUint) -> Option<BigUint> {
    // Iteriere über alle möglichen Werte für b (beginnend bei 1)
    let mut b = BigUint::one();  // Startwert für b ist 1

    loop {
        if (a * &b) % c == BigUint::one() {
            // Wenn a * b mod c == 1, dann haben wir die Inverse gefunden
            return Some(b);
        }
        b += BigUint::one();  // Inkrementiere b
        if b >= *c {
            break; // Falls b >= c, gibt es keine Inverse
        }
    }

    // Keine Inverse gefunden
    None
}*/


