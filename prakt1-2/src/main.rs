use std::time::Instant;
use num_bigint::{BigUint, RandBigInt};
use num_traits::One;
use num_prime::{nt_funcs::is_prime, RandPrime, PrimalityUtils};
use rand::thread_rng;
use std::fmt::Write as hexHelper;



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
    dsa_keygen();
}

fn dsa_keygen() -> KeyPair {

    let now = Instant::now();
    let mut rng = thread_rng();
    let mut passed = false;

    //prepare p and q
    let mut p = BigUint::from(0u32);
    let mut q = BigUint::from(0u32);
    let mut c = BigUint::from(0u32);

    // limit the number of attempts to avoid infinite loop
    let max_attempts = 500; 
    // tries to find p - 1 = c * q
    while !passed {

        q = rng.gen_prime(256, None);

        // calculate c size for 3072 bit key
        c = (BigUint::from(2u64).pow(3072 as u32) - BigUint::one()) / &q;

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

    println!("p:\n{}", &p);
    println!("\nq:\n{}", &q);
    
    println!("\np - 1 = c * q -> {}", &p - BigUint::one() == &c * &q);



    // benchmark
    let elapsed_time = now.elapsed();
    println!("\n-> All tests passed!");
    println!("-> Key generation took {} ms.\n\n", elapsed_time.as_millis());

    return KeyPair::default();
}

fn miller_rabin(p: &BigUint) -> bool {

    let mut rng = thread_rng();
    let mut passed = false;

        // miller-rabin tests
        println!("\nPerforming Miller-Rabin Tests...");
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

