use std::str::FromStr;

use ark_ff::{AdditiveGroup, BigInt, FftField, Field, PrimeField};
// We'll use a field associated with the BLS12-381 pairing-friendly
// group for this example.
// use ark_bn254::{Fq as F, FqConfig as Config};
use ark_starkcurve::{Fq as F, FqConfig as Config};
// `ark-std` is a utility crate that enables `arkworks` libraries
// to easily support `std` and `no_std` workloads, and also re-exports
// useful crates that should be common across the entire ecosystem, such as `rand`.
use ark_std::{One, UniformRand};
use crypto_tools::Polynomial;


fn main() {
    let mut rng = ark_std::test_rng();
    // Let's sample uniformly random field elements:
    let modd = F::MODULUS;
    // let elem = F::new(BigInt([4, 0, 0, 0]));
    println!("modulus: {modd}");
    // println!("{elem}");
    // let a = F::rand(&mut rng);
    // let b = F::rand(&mut rng);
    // // We can perform all the operations from the `AdditiveGroup` trait:
    // // We can add...
    // let c = a + b;
    // // ... subtract ...
    // let d = a - b;
    // // ... double elements ...
    // assert_eq!(c + d, a.double());

    // // ... multiply ...
    // let e = c * d;
    // // ... square elements ...
    // assert_eq!(e, a.square() - b.square());

    // 2^64 = 9223372036854775808
    let root64 = F::get_root_of_unity(2).unwrap();
    let root32 = F::get_root_of_unity(4).unwrap();
    assert_eq!(root32 * root32, root64);

    // ... and compute inverses ...
    // assert_eq!(a.inverse().unwrap() * a, F::one()); // have to unwrap, as `a` could be zero.
    // let one: BigInt<4> = BigInt::from_str("4").unwrap();
    // let poly: Polynomial<Config, 4> = Polynomial::new(1, 
    //     vec![(one, BigInt([4, 0, 0, 0]))]);
    let second = F::get_root_of_unity(2).unwrap();
    println!("second root: {second}");
    let mut p = Polynomial::<Config, 4>::random_poly_coefficient(&mut rng, 2);
    println!("{p}");
    let p2 = p.fft().unwrap();
    println!("{p2}");
    // let poly: Polynomial<Config, 4> = Polynomial::random_poly_fft(&mut rng, 1<<20);
    // print!("{poly}");
}