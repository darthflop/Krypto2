
use std::{io::Write, time::Instant};
use num_bigint::{BigUint, RandBigInt};
use num_traits::One;
use num_prime::{PrimalityUtils, RandPrime};
use rand::thread_rng;
use std::io;
use std::fmt::Write as a;


#[derive(Default)]
struct KeyPair {
    public_key: PublicKey,
    private_key: PrivateKey
}

#[derive(Default)]
struct PublicKey {
    n: BigUint,
    e: BigUint
}

#[derive(Default)]
struct PrivateKey {
    p: BigUint,
    q: BigUint,
    d: BigUint
}

fn main() {

    // activates commandline
    //cli();

    let print_as_hex = true;

    
    // generate rsa keypair
    let keypair = keygen();

    // print rsa key values
    print_key_values(&keypair, &print_as_hex);



    universal_forgery(&keypair, &print_as_hex);

}

fn universal_forgery(key_pair: &KeyPair, hex: &bool) {

    let mut rng = thread_rng();
    let mut r: BigUint = BigUint::from(1u32);

    // find r with r^e mod n != 1
    loop {
        r = rng.gen_biguint(1000);
        if r.modpow(&key_pair.public_key.e, &key_pair.public_key.n) != BigUint::from(1u32) {
            break;
        }
    }


    // 1. choose a message for forgery
    println!("Please choose a message (int):");
    let mut message = String::new();
    io::stdin().read_line(&mut message).unwrap();
    let number: u32 = message.trim().parse().expect("Please enter a valid u32");
    let m: BigUint = BigUint::from(number);
    

    // 2. calculate r^e * m % n
    let for_oracle = r.modpow(&key_pair.public_key.e, &key_pair.public_key.n) * &m % &key_pair.public_key.n;
    
    // 3. get s' from oracle
    let s_strich = sign(&for_oracle, key_pair);

    // 4. calculate s = r^-1 * s' % n = m^d mod n
    let s = r.modinv(&key_pair.public_key.n).unwrap() * s_strich % &key_pair.public_key.n;

    // print crafted signing and real signing
    if *hex {
        println!("\nForged Message signing (r^-1 * s' % n):\n{}", to_hexdump(&s));
        println!("\nSigning with private parameters (m^d % n):\n{}", to_hexdump(&m.modpow(&key_pair.private_key.d, &key_pair.public_key.n)));
    } else {
        println!("\nForged Message signing (r^-1 * s' % n):\n{}", s);
        println!("\nSigning with private parameters (m^d % n):\n{}", m.modpow(&key_pair.private_key.d, &key_pair.public_key.n));
    }

    // 5. verify message
    let verification = verify(&m, &s, key_pair);

    if verification {
        println!("\nThe forged message was verified.");
    } else {
        println!("\n-> The forged message couldn't be verified.");
    }
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
        println!("\nPerforming Miller-Rabin Tests...");
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


fn print_key_values(keypair: &KeyPair, hex: &bool) {
    // Helper to format numbers either in decimal or hexadecimal
    let format = |n: &BigUint| {
        if *hex {
            to_hexdump(&n)
        } else {
            n.to_string()
        }
    };

    println!("--------------------------------------------------------------------------\n\n");
    println!("Generated keypair values:\n");

    // Print values in the desired format
    println!("n: \n{}", format(&keypair.public_key.n));
    println!("p: \n{}", format(&keypair.private_key.p));
    println!("q: \n{}", format(&keypair.private_key.q));
    println!("e (65537): \n{}", format(&keypair.public_key.e));
    println!("d: \n{}", format(&keypair.private_key.d));

    println!("--------------------------------------------------------------------------\n\n");
}

// Helper function to convert BigUint to hex dump format
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


fn cli() {

    let mut input_string = String::new();
    let mut keypair = KeyPair::default();
    let mut active_key = false;
    
    loop {
        print!("> ");
        io::stdout().flush().unwrap();

        io::stdin().read_line(&mut input_string).unwrap();
        match input_string.trim() {
            "keygen" => {
                if !active_key {
                    keypair = keygen();
                    active_key = true;
                } else {
                    println!("Key already generated. Use -new to overwrite.");
                }
            },
            "keygen -new" => {
                keypair = keygen();  
            },
            "print" => {
                print_key_values(&keypair, &false);
            }
            "print -hex" => {
                print_key_values(&keypair, &true);
            }
            "help" => {
                println!("keygen -> Generates RSA Keypair. No overwrite of current Keypair.");
                println!("keygen -new -> Generates RSA Keypair. Overwrites existing Keypair.");
                println!("print -> Prints current RSA Keypair");
            },
            _=> print!("Unknown command. Use help for commands.\n"),
        }
        input_string.clear();
    }
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