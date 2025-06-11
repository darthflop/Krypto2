use std::time::Instant;
use num_bigint::{BigUint, RandBigInt};
use num_traits::{One, Zero};
use num_prime::{nt_funcs::is_prime, RandPrime, PrimalityUtils};
use rand::{thread_rng, Rng};
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

    // verify signed message
    let is_valid = verify(message, &signed_message, &keypair.public_key);

    println!("\nVerifikation der Signatur:");
    if is_valid {
        println!("Die Signatur ist gültig.");
    } else {
        println!("Die Signatur ist ungültig.");
    }

    verify_rand_messages(&keypair);

    aufgabe_drei(&keypair);
}

fn aufgabe_drei(keypair: &KeyPair){
    let mut rng = thread_rng();

    // two random numbers
    let msg1: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
    let msg2: Vec<u8> = (0..32).map(|_| rng.gen()).collect();

    // random r
    let r = rng.gen_biguint_range(&BigUint::one(), &(&keypair.public_key.q - BigUint::one()));

    // gamma
    let gamma = keypair.public_key.alpha.modpow(&r, &keypair.public_key.p) % &keypair.public_key.q;

    // hashes
    let h1 = BigUint::from_bytes_be(&Sha256::digest(&msg1)) % &keypair.public_key.q;
    let h2 = BigUint::from_bytes_be(&Sha256::digest(&msg2)) % &keypair.public_key.q;

    // delta1, delta2
    let r_inv = r.modinv(&keypair.public_key.q).unwrap();
    let delta1 = (&h1 + &keypair.private_key.a * &gamma) * &r_inv % &keypair.public_key.q;
    let delta2 = (&h2 + &keypair.private_key.a * &gamma) * &r_inv % &keypair.public_key.q;

    // reconstruct r
    let delta_diff = (&delta1 + &keypair.public_key.q - &delta2) % &keypair.public_key.q;
    let h_diff = (&h1 + &keypair.public_key.q - &h2) % &keypair.public_key.q;

    let delta_diff_inv = delta_diff.modinv(&keypair.public_key.q).unwrap();

    let r_recovered = (&h_diff * &delta_diff_inv) % &keypair.public_key.q;

    // reconstruct private key
    let gamma_inv = gamma.modinv(&keypair.public_key.q).unwrap();
    let a_recovered = ((&delta1 * &r_recovered - &h1) * &gamma_inv) % &keypair.public_key.q;

    println!("===============================");
    println!("Rekonstruiertes r:      {:x}", r_recovered);
    println!("Tatsächliches r:        {:x}", r);
    println!("Rekonstruierter a:      {:x}", a_recovered);
    println!("Tatsächlicher priv. a:  {:x}", keypair.private_key.a);

    if a_recovered == keypair.private_key.a {
        println!("Privater Schlüssel erfolgreich rekonstruiert!");
    } else {
        println!("Fehler bei Rekonstruktion!");
    }
}

// Aufgabe 2b)
fn verify_rand_messages(keypair: &KeyPair){
    // number of random messages
    let num_tests = 5; 
    let mut rng = thread_rng();

    for i in 1..=num_tests {
        // random message
        let msg_len = rng.gen_range(10..=40);
        let message: Vec<u8> = (0..msg_len).map(|_| rng.gen()).collect();

        println!("--- Test #{i} ---");
        //println!("Message: {}", &message);

        // sign
        let signature = sign(&message, &keypair);

        // verify
        let valid = verify(&message, &signature, &keypair.public_key);

        if valid {
            println!("\nVerifikation erfolgreich.");
        } else {
            println!("\nVerifikation fehlgeschlagen.");
        }

        println!();
}
}

fn verify(message: &[u8], signature: &DigitalSignature, public_key: &PublicKey) -> bool {

    let gamma = &signature.gamma;
    let delta = &signature.delta;

    if gamma == &BigUint::zero() || gamma >= &public_key.q || delta.is_zero() || delta >= &public_key.q {
        return false;
    }

    // SHA256 Hash
    let hash = Sha256::digest(message);
    let h = BigUint::from_bytes_be(&hash) % &public_key.q;

    // w = delta^-1 mod q
    let w = delta.modinv(&public_key.q);
    if w.is_none() {
        return false; // Kein Inverses existiert
    }
    let w = w.unwrap();

    // u1 = h * w mod q
    let u1 = &h * &w % &public_key.q;

    // u2 = gamma * w mod q
    let u2 = gamma * &w % &public_key.q;

    // v = ((alpha^u1 * beta^u2) mod p) mod q
    let alpha_u1 = public_key.alpha.modpow(&u1, &public_key.p);
    let beta_u2 = public_key.beta.modpow(&u2, &public_key.p);

    let v = (&alpha_u1 * &beta_u2) % &public_key.p % &public_key.q;

    // compare v and gamma
    &v == gamma
}



fn dsa_keygen() -> KeyPair {

    let now = Instant::now();
    let mut rng = thread_rng();
    let mut passed = false;

    // initiate p, q
    let mut p = BigUint::from(0u32);
    let mut q = BigUint::from(0u32);

    // limit the number of attempts to avoid infinite loop
    let max_attempts = 500; 

    // tries to find p - 1 = c * q
    while !passed {

        q = rng.gen_prime(256, None);

        // generate random c in range
        let mut c = rng.gen_biguint(3072 - 256);

        // reset attempts
        let mut attempts = 0;

        while attempts < max_attempts {

            // calculate p
            p = &q * &c + BigUint::one();

            // check if p is probably prime and p - 1 = c * q
            if is_prime(&p, None).probably() && &p - BigUint::one() == &c * &q {
                
                if miller_rabin(&p) && miller_rabin(&q) {
                    passed = true;
                    break;
                }
            }

            // increase step size to quickly explore larger values of c
            c += 10u32; 
            attempts += 1;
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