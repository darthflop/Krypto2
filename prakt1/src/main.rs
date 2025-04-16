
use num_bigint::BigUint;
use num_traits::One;
use num_prime::RandPrime;
use rand::thread_rng;


struct KeyPair {
    public_key: PublicKey,
    private_key: PrivateKey
}

struct PublicKey {
    n: BigUint,
    e: BigUint
}

struct PrivateKey {
    p: BigUint,
    q: BigUint,
    d: BigUint
}

fn main() {
    
    // generate rsa keypair
    let keypair = keygen();

    // declare message
    let message: u32 = 4;
    let x: BigUint = BigUint::from(message);

    // sign message
    let s = sign(x, &keypair);

    // print signed message
    println!("Signed message:\n {}\n\n", s);

    // print rsa key values
    print_key_values(&keypair);

}


// signs a message by calculating m^d % n 
fn sign(m: BigUint, key_pair: &KeyPair) -> BigUint {
    return m.modpow(&key_pair.private_key.d, &key_pair.public_key.n);
}


// generates rsa keypair
fn keygen() -> KeyPair {

    let mut rng = thread_rng();

    // generate random primes
    let p: BigUint = rng.gen_prime(1500, None);
    let q: BigUint = rng.gen_prime(1500, None);

    // calculate n, phi, e, d
    let n = &p * &q;

    let one = BigUint::one();
    let phi = (&p - &one) * (&q - &one);

    let e = BigUint::from(65537u32);

    let d = e.modinv(&phi).expect("Modularer Inverser konnte nicht berechnet werden");

    return KeyPair {
        public_key: PublicKey { n, e },
        private_key: PrivateKey {p, q, d},
    };
}


fn print_key_values(keypair: &KeyPair) {
    println!("--------------------------------------------------------------------------\n\n");
    println!("Generated keypair values:\n");
    println!("n = {}\n", keypair.public_key.n);
    println!("p = {}\n", keypair.private_key.p);
    println!("q = {}\n", keypair.private_key.q);
    println!("e = {}\n", keypair.public_key.e);
    println!("d = {}\n", keypair.private_key.d);
}