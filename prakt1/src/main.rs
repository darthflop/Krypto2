
use std::time::Instant;
use num_bigint::{BigUint, RandBigInt};
use num_traits::One;
use num_prime::{PrimalityUtils, RandPrime};
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

    // print rsa key values
    print_key_values(&keypair);

    universal_forgery(&keypair);

}

fn universal_forgery(key_pair: &KeyPair) {

    let mut rng = thread_rng();
    let mut r: BigUint = BigUint::from(1u32);

    // find r with r^e mod n != 1
    loop {
        r = rng.gen_biguint(1000);
        if r.modpow(&key_pair.public_key.e, &key_pair.public_key.n) != BigUint::from(1u32) {
            break;
        }
    }

    // declare message
    let message: u32 = 4;
    let m: BigUint = BigUint::from(message);

    // calculate r^e * m % n
    let for_oracle = r.modpow(&key_pair.public_key.e, &key_pair.public_key.n) * &m % &key_pair.public_key.n;
    
    // s' from oracle
    let s_strich = sign(&for_oracle, key_pair);

    let s = r.modinv(&key_pair.public_key.n).unwrap() * s_strich % &key_pair.public_key.n;

    let f = verify(&m, &s, key_pair);

    println!("Verified: {}", f);
    

}


// signs a message by calculating m^d % n 
fn sign(m: &BigUint, key_pair: &KeyPair) -> BigUint {
    return m.modpow(&key_pair.private_key.d, &key_pair.public_key.n);
}

fn verify(m: &BigUint, s: &BigUint, key_pair: &KeyPair)  -> bool {
    return *m == s.modpow(&key_pair.public_key.e, &key_pair.public_key.n);
}


// generates rsa keypair
fn keygen() -> KeyPair {


    let now = Instant::now();
    let mut rng = thread_rng();
    let mut passed = false;

    //prepare p and q
    let mut p = BigUint::from(0u32);
    let mut q = BigUint::from(0u32);

    // loop for prime generation and miller-rabin tests
    while !passed {

        // generate random primes
        p = rng.gen_prime_exact(1500, None);
        q = rng.gen_prime_exact(1500, None);


        // miller-rabin tests
        println!("Performing Miller-Rabin Tests...");
        let number = 60;
        for _num in 0..number {

            // generate base x = {2, 3, ..., p-2} / {2, 3, ..., q-2}
            let base_p = rng.gen_biguint_range(&BigUint::from(2u32), &(&p - &BigUint::from(2u32)));
            let base_q = rng.gen_biguint_range(&BigUint::from(2u32), &(&q - &BigUint::from(2u32)));
            

            // perform miller-rabin test
            if &p.is_sprp(base_p) == &true && &q.is_sprp(base_q) == &true {

                if _num < 10 {
                    println!("  {}/60 passed.", {_num});
                } else {
                    println!(" {}/60 passed.", {_num});
                }
                passed = true;
            } else {
                if _num < 10 {
                    println!("  {}/60 failed.\n Generating new primes.", {_num});
                } else {
                    println!(" {}/60 failed.\n Generating new primes.", {_num});
                }
                passed = false;
                break;
            }
        }
    }


    // calculate n, phi, e, d
    let n = &p * &q;

    let phi = (&p - &BigUint::one()) * (&q - &BigUint::one());

    let e = BigUint::from(65537u32);

    let d = e.modinv(&phi).expect("Couldn't find modular inverse.");

    // benchmark
    let elapsed_time = now.elapsed();
    println!("\n-> All tests passed!");
    println!("-> Key generation took {} ms.\n\n", elapsed_time.as_millis());

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

#[cfg(test)]

#[test]
fn test_verify() {
    let keypair = keygen();
    let keypair2 = keygen();

    // test if keys are not equal
    assert_ne!(keypair.public_key.n, keypair2.public_key.n);

    // declare message
    let message: u32 = 4;
    let x: BigUint = BigUint::from(message);

    // sign message
    let s = sign(&x, &keypair);

    assert_eq!(true, verify(&x, &s, &keypair));
    assert_eq!(false,verify(&x, &s, &keypair2));
}