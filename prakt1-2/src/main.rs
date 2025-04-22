use std::time::Instant;
use num_bigint::{BigUint, RandBigInt};
use num_traits::One;
use num_prime::{nt_funcs::is_prime, RandPrime, PrimalityUtils};
use rand::thread_rng;
use std::fmt::Write as hexHelper;
use sha2::{Sha256, Digest};

#[derive(Default)]
struct KeyPair {
    public_key: PublicKey,
    private_key: PrivateKey
}

#[derive(Default)]
struct PublicKey {
    p: BigUint,
    q: BigUint,
    alpha: BigUint,
    beta: BigUint
}

#[derive(Default)]
struct PrivateKey {
    a: BigUint
}

#[derive(Default)]
struct DigitalSignature {
    gamma: BigUint,
    delta: BigUint
}

fn main() {

    // print values in hex?
    let print_hex = true;

    let keypair = dsa_keygen();
    print_key_values(&keypair, &print_hex);

    // sign and verify message
    let message = b"Hello World";
    let signed_message = sign(message, &keypair);

    // print signed message parameters
    println!("\n\ngamma:\n{}", to_hexdump(&signed_message.gamma));
    println!("delta:\n{}", to_hexdump(&signed_message.delta));
}


fn dsa_keygen() -> KeyPair {

    let now = Instant::now();
    let mut rng = thread_rng();
    let mut passed = false;

    // initiate p, q
    let mut p = BigUint::from(0u32);
    let mut q = BigUint::from(0u32);

    // tries to find p - 1 = c * q
    while !passed {

        q = rng.gen_prime(256, None);

        // generate random c in range
        let mut c = rng.gen_biguint(3072 - 256);
        
        // calculate p
        p = &q * &c + BigUint::one();

        // check if p is probably prime and p - 1 = c * q
        if is_prime(&p, None).probably() && &p - BigUint::one() == &c * &q {
                
            if miller_rabin(&p) && miller_rabin(&q) {
                passed = true;
                break;
            }
        }
    }

    // calculate generator alpha
    let alpha = generate_generator(&p, &q);

     // a = {1, ..., q-1}
    let a = rng.gen_biguint_range(&BigUint::from(1u32), &(&q - BigUint::one()));

    // calculate beta
    let beta = alpha.modpow(&a, &p);

    // benchmark
    let elapsed_time = now.elapsed();
    println!("\n-> All tests passed!");
    println!("-> Key generation took {} ms.\n\n", elapsed_time.as_millis());

    return KeyPair {
        public_key: PublicKey { p, q, alpha, beta },
        private_key: PrivateKey {a},
    };
}


// g = h^((p-1)/q) mod p, wobei h = {2, 3, ..., p − 2}
fn generate_generator(p: &BigUint, q: &BigUint) -> BigUint {
    
    let mut rng = thread_rng();
    let one = BigUint::one();
    let exponent = (p - &one) / q;

    loop {
        let h = rng.gen_biguint_range(&BigUint::from(2u32), &(p - BigUint::from(2u32)));
        let g = h.modpow(&exponent, p);

        if g > one {
            return g;
        }
    }
}


fn sign(message: &[u8], keypair: &KeyPair) -> DigitalSignature{

    let mut rng = thread_rng();

    // random number r
    let r = rng.gen_biguint_range(&BigUint::one(), &(&keypair.public_key.q - BigUint::one()));

    // calculate gamma = (alpha^r mod p) mod q
    let gamma = keypair.public_key.alpha.modpow(&r, &keypair.public_key.p) % &keypair.public_key.q;

    // hash the message
    let hash = Sha256::digest(&message);
    let h = BigUint::from_bytes_be(&hash) % &keypair.public_key.q;

    // print hash (for testing purpose)
    println!("SHA-256 Hash (hex):");
    for byte in hash.iter() {
        print!("{:02x} ", byte);
    }

    // calculate delta = (hash(message) + a * gamma) * r^-1 % q
    let delta = (h + &keypair.private_key.a * &gamma) * r.modinv(&keypair.public_key.q).unwrap() % &keypair.public_key.q;

    return DigitalSignature {gamma, delta};
}


fn miller_rabin(p: &BigUint) -> bool {

    let mut rng = thread_rng();
    let mut passed = false;

        // miller-rabin tests
        println!("Performing Miller-Rabin Tests...");
        let number = 60;
        for _num in 0..number {
    
            // generate base x = {2, 3, ..., p-2} / {2, 3, ..., q-2}
            let base = rng.gen_biguint_range(&BigUint::from(2u32), &(p.clone() - &BigUint::from(2u32)));
            
            // perform miller-rabin test
            if &p.is_sprp(base) == &true {
                passed = true;
            } else {
                if _num < 10 {
                    println!("  {}/60 failed.\n", {_num});
                } else {
                    println!(" {}/60 failed.\n", {_num});
                }
                return false;
        }
    }
    println!("\n");
    return passed;
}


fn print_key_values(keypair: &KeyPair, hex: &bool) {

    // print in hex or decimal
    let format = |n: &BigUint| {
        if *hex {
            to_hexdump(&n)
        } else {
            n.to_string()
        }
    };

    println!("--------------------------------------------------------------------------\n\n");
    println!("Generated keypair values:");

    // Print values in the desired format
    println!("\np: \n{}", format(&keypair.public_key.p));
    println!("\nq: \n{}", format(&keypair.public_key.q));
    println!("\nalpha: \n{}", format(&keypair.public_key.alpha));
    println!("\na: \n{}", format(&keypair.private_key.a));
    println!("\nbeta: \n{}", format(&keypair.public_key.beta));

    println!("--------------------------------------------------------------------------\n\n");
}


// helper function to convert BigUint to hex dump format
fn to_hexdump(n: &BigUint) -> String {
    // Convert BigUint to bytes
    let bytes = n.to_bytes_be();

    let mut output = String::new();
    let block_size = 32; // Number of bytes per block (e.g., 16 bytes)

    // Group bytes in blocks and print as hex
    for chunk in bytes.chunks(block_size) {
        // Print hex bytes as a single line
        let hex_line = chunk.iter()
            .map(|byte| format!("{:02x}", byte)) // Format each byte in 2-digit hex
            .collect::<Vec<String>>()
            .join(" "); // Join bytes with space
        
        // Append to output
        writeln!(output, "{}", hex_line).unwrap();
    }
    output
}

