use ark_ff::{AdditiveGroup, FftField, Field, PrimeField};
use ark_starkcurve::{Fq as F, FqConfig as Config};
use stark_tools::{hashable::Hashable, Foldable2, Polynomial, PolynomialCoefficient};

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

    use std::time::Instant;
    let now = Instant::now();


    let p = PolynomialCoefficient::<Config, 4>::random_poly(&mut rng, 7);
    let elapsed = now.elapsed();
    println!("Poly generated: {:.2?}", elapsed);
    println!("{p}");
    let p2 = p.fft(4);
    let elapsed = now.elapsed();
    println!("FFT: {:.2?}", elapsed);
    println!("FFT {p2}");
    let f = p2.fold(4, F::ONE.double());
    let elapsed = now.elapsed();
    println!("Folded: {:.2?}", elapsed);
    let commitment = f.commit(&mut rng);
    let elapsed = now.elapsed();
    println!("Commitment: {commitment}, {:.2?}", elapsed);
    println!("Folded {f}");
    // let poly: Polynomial<Config, 4> = Polynomial::random_poly_fft(&mut rng, 1<<20);
    // print!("{poly}");
}