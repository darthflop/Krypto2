
use num_bigint::BigUint;
use num_traits::One;
use num_prime::RandPrime;
use rand::thread_rng;


struct Keypair {
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
    
    let keypair = keygen();

    // print keypair values
    println!("n = {}", keypair.public_key.n);
    println!("p = {}", keypair.private_key.p);
    println!("q = {}", keypair.private_key.q);
    println!("e = {}", keypair.public_key.e);
    println!("d = {}", keypair.private_key.d);
}

// generates rsa keypair
fn keygen() -> Keypair {

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

    return Keypair {
        public_key: PublicKey { n, e },
        private_key: PrivateKey {p, q, d},
    };
}



