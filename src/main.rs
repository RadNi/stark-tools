use ark_ff::{BigInt, PrimeField};
use stark_tools::{fields::{Field192, Goldilocks}, merkletree::PedersenTreeConfig, polynomial::{Polynomial, PolynomialCoefficient}};

use crate::proximityproofs::fri::fri_test;

mod proximityproofs;
// use stark_tools::{fields::Goldilocks, polynomial::{Polynomial, PolynomialCoefficient}};


fn main2() {
    let x = Goldilocks::from(10);
    println!("{:#?}", x);
    let mut rng = ark_std::test_rng();

    let p: PolynomialCoefficient<Goldilocks> = PolynomialCoefficient::random_poly_smooth_subgroup(&mut rng, 7);

    println!("{:#?} {}", p.coefficients[0], Goldilocks::MODULUS);
}


fn main() {
    let mut rng = ark_std::test_rng();

    // let root64 = F::get_root_of_unity(2).unwrap();
    // let root32 = F::get_root_of_unity(4).unwrap();
    // assert_eq!(root32 * root32, root64);

    
    // let second = F::get_root_of_unity(2).unwrap();
    // println!("second root: {second}");

    // use std::time::Instant;
    // let now = Instant::now();


    // let p = PolynomialCoefficient::<Config, 4>::random_poly(&mut rng, 3);
    // let elapsed = now.elapsed();
    // println!("Poly generated: {:.2?}", elapsed);
    // println!("{p}");
    // let p2 = p.fft(4);
    // let elapsed = now.elapsed();
    // println!("FFT: {:.2?}", elapsed);
    // println!("FFT {p2}");
    // let pedersen_config = PedersenTreeConfig::new(&mut rng);
    // let commited_poly = p2.fold(4, F::ONE.double()).commit(&pedersen_config);
    // println!("folded {}", commited_poly.data);
    // let elapsed = now.elapsed();
    // println!("Folded: {:.2?}", elapsed);
    // let commitment = commited_poly.ptree.root();
    // println!("Commitment: {commitment}, {:.2?}", elapsed);

    

    // spongefish_test();
    // main_test();
    // println!("############################");
    let pedersen_config = PedersenTreeConfig::new(&mut rng);
    fri_test(&pedersen_config);
}
