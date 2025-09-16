use std::{collections::HashMap};
use std::fmt::Debug;
use std::{vec};

use ark_ff::{BigInt, BigInteger, PrimeField};
use ark_std::rand::Rng;
use bimap::{BiHashMap};

use crate::point::Point;

// type F<T, const N:usize> = Fp<MontBackend<T, N>, N>;

#[derive(Debug)]
pub struct PolynomialCoefficient<F> where F: PrimeField
{
    // Fiat-Shamir assumes degree is two bytes
    pub degree: u64,
    // pub points: Option<Vec<Point<T, N>>>,
    pub coefficients: Vec<F>
}

impl<F: PrimeField> Clone for PolynomialCoefficient<F>
{
    fn clone(&self) -> Self {
        let mut clonedCoefficients: Vec<F> = vec![];
        self.coefficients.iter().for_each(|c| clonedCoefficients.push(
                c.clone()
            // F::new(c.into_bigint().clone())
        ));
        Self { degree: self.degree.clone(), coefficients: clonedCoefficients }
    }
}

impl<F: PrimeField> std::fmt::Display for PolynomialCoefficient<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result  {
        let d = self.degree;
        write!(f, "Polynomial degree {d} with coefficients:\n")?;
        for (i, coefficient) in self.coefficients.iter().enumerate() {
            let result = write!(f, "{}: {}\n", i, coefficient);
            if result.is_err() {
                return Err(result.unwrap_err()); // or result.unwrap_err() if you needed the error
            }

        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct PolynomialPoints<F: PrimeField> {
    // Fiat-Shamir assumes degree is two bytes
    pub degree: u64,
    pub points: HashMap<F, Box<Point<F>>>,
    pub roots_preimage: Option<BiHashMap<F, u64>>
}

impl<F: PrimeField> Clone for PolynomialPoints<F> {
    fn clone(&self) -> Self {
        let mut points = HashMap::<F, Box<Point<F>>>::new();
        self.points.iter().for_each(|(k, v)| { points.insert(k.clone(), v.clone()); });
        Self { degree: self.degree.clone(), points, roots_preimage: self.roots_preimage.clone() }
    }
}

impl<'a, F: PrimeField> std::fmt::Display for PolynomialPoints<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result  {
        let d = self.degree;
        write!(f, "Polynomial degree {d} with points:\n")?;
        for point in &self.points {
            let result = write!(f, "{}\n", point.1);
            if result.is_err() {
                return Err(result.unwrap_err()); // or result.unwrap_err() if you needed the error
            }
        }
        Ok(())
    }
}

pub trait Polynomial<F: PrimeField, Raw> 
where Self: Clone {
    fn zero(degree: u64) -> Self;
    fn new(degree: u64, raw: Raw) -> Self;
    fn random_poly<R: Rng + ?Sized>(rng: &mut R, degree: u64) -> Self;
    fn random_poly_smooth_subgroup<R: Rng + ?Sized>(rng: &mut R, degree: u64) -> Self;
    fn constant(rate: u64) -> Self;
    fn fft(self, rate: u64) -> PolynomialPoints<F>;
    fn ifft(self, rate: u64) -> PolynomialCoefficient<F>;
}

impl <'a, F: PrimeField> Polynomial<F, Vec<Point<F>>> for PolynomialPoints<F> 
{
    fn zero(degree: u64) -> Self {
        Self {
            degree: degree,
            points: HashMap::new(),
            roots_preimage: None
        }
    }
    
    fn new(degree: u64, raw: Vec<Point<F>>) -> Self {
        Self {
            degree,
            points: raw.iter().map(|p| (p.get_x(), Box::new(p.clone()))).collect(),
            roots_preimage: None
        }
    }

    fn constant(rate: u64) -> Self {
        todo!()
    }

    // fn constant(rate: u64) -> Self {
    //     let omega = F::get_root_of_unity(rate).unwrap();
    //     let root = F::ONE;
    //     Self {
    //         degree: 0,
    //         roots_preimage: (0..rate).map(|_| {})
    //     }
    // }


    fn random_poly<R: Rng + ?Sized>(rng: &mut R, degree: u64) -> Self {
        let points = (0..degree+1).map(|_| {let p = Point::new_random(rng); (p.get_x(), Box::new(p))} ).collect();
        Self { 
            degree, 
            points: points,
            roots_preimage: None
        }
    }

    fn random_poly_smooth_subgroup<R: Rng + ?Sized>(rng: &mut R, degree: u64) -> Self {
        let mut points = HashMap::new();
        let mut roots_preimage = BiHashMap::new();
        let omega = F::get_root_of_unity((degree + 1)).unwrap();
        let mut root = F::ONE;
        for i in 0..(degree + 1) {
            roots_preimage.insert(root, i);
            let point: Point<F> = Point::new_random(rng);
            points.insert(point.get_x(), Box::new(point));
            root = root * omega;
        }
        PolynomialPoints { degree, points, roots_preimage: Some(roots_preimage) }
    }

    fn fft(self, rate: u64) -> PolynomialPoints<F> {
        // TODO add error handling if the extended degree is less than degree
        self
    }

    fn ifft(self, rate: u64) -> PolynomialCoefficient<F> {
        todo!()
    }
}

impl <F: PrimeField> Polynomial<F, Vec<F>> for PolynomialCoefficient<F> 
  {
    fn zero(degree: u64) -> Self {
        Self {
            degree: degree,
            coefficients: vec![]
        }
    }

    fn new(degree: u64, raw: Vec<F>) -> Self {
        assert!(raw.len() >= (degree + 1) as usize);

        Self {
            degree: degree,
            coefficients: raw
        }
    }


    fn random_poly<R: Rng + ?Sized>(rng: &mut R, degree: u64) -> Self {
        let mut coefficients: Vec<F> = vec![];
        for i in 0..(degree + 1) {
            coefficients.push(F::rand(rng));
            // let num: u64 = rand::random_range(0..20);
            // let mut v = [0; N];
            // v[0] = i*2+1;
            // coefficients.push(F::new(BigInt(v)));
            // coefficients.push(F::new(BigInt(v)));
        }
        Self {
            degree,
            coefficients: coefficients
        }
    }
    fn random_poly_smooth_subgroup<R: Rng + ?Sized>(rng: &mut R, degree: u64) -> Self {
        Self::random_poly(rng, degree)
    }

    fn fft(self, rate: u64) -> PolynomialPoints<F> {
        let extended_degree = (self.degree + 1) * rate;
        let omega: F = F::get_root_of_unity(extended_degree as u64).unwrap();
        let mut root = F::ONE;
        if self.degree == 0 {
            let value = self.coefficients.get(0).unwrap();
            let mut points = HashMap::new();
            let mut roots_preimage = BiHashMap::new();
            for i in 0..extended_degree {
                roots_preimage.insert(root, i);
                points.insert(root, Box::new(Point::new(
                    root,
                    // Because it's a degree zero polynomial it's value is always fixed
                    *value
                )));
                root = root * omega;
            }
            return PolynomialPoints { 
                degree: 1, 
                points: points,
                roots_preimage: Some(roots_preimage)
            }
        }
        let p_e: PolynomialPoints<F> = PolynomialCoefficient { 
            degree: self.degree/2, 
            coefficients: self.coefficients.iter().step_by(2).cloned().collect()
        }.fft(rate);
        let p_o: PolynomialPoints<F> = PolynomialCoefficient { 
            degree: self.degree/2, 
            coefficients: self.coefficients.iter().skip(1).step_by(2).cloned().collect()
        }.fft(rate);

        let mut points: HashMap<F, Box<Point<F>>> = HashMap::new();
        let mut roots_preimage = BiHashMap::new();
        // let mut roots: Vec<F<T, N>> = vec![F::ONE];
        for i in 0..extended_degree {
            roots_preimage.insert(root, i);
            root = root * omega;

            let j = if i >= extended_degree/2 { i - extended_degree/2 } else { i };
            let w = *roots_preimage.get_by_right(&j).unwrap();
            let w2 = w*w;
            let y_e_j = p_e.points.get(&w2).unwrap().get_y();
            let y_o_j = p_o.points.get(&w2).unwrap().get_y();
            
            let x = roots_preimage.get_by_right(&i).unwrap();
            if i < extended_degree/2 {
                points.insert(x.clone(),
                    Box::new(Point::new(
                        *x,
                        y_e_j + y_o_j * x
                    ))
                );
            } else {
                let old_root = roots_preimage.get_by_right(&j).unwrap();
                points.insert(x.clone(),
                    Box::new(Point::new(
                        *x,
                        y_e_j - y_o_j * old_root
                    ))
                );
            }
        }
        PolynomialPoints {
            degree: self.degree,
            points: points,
            roots_preimage: Some(roots_preimage)
        }
    }

    fn constant(rate: u64) -> Self {
        todo!()
    }

    fn ifft(self, extended_degree: u64) -> PolynomialCoefficient<F> {
        todo!()
    }
}
pub trait Foldable2<F: PrimeField, const N: usize>
where Self: Sized

{
    fn fold(&self, rate: u64, folding_number: F) -> PolynomialPoints<F>;
    fn fold_bigint(&self, rate: u64, folding_number: BigInt<N>) -> PolynomialPoints<F> {
        self.fold(rate, F::from_be_bytes_mod_order(&folding_number.to_bytes_be()))
    }
}

impl <const N: usize, F: PrimeField> Foldable2<F, N> for PolynomialPoints<F> 
{
    fn fold(&self, rate: u64, folding_number: F) -> PolynomialPoints<F> {
        let extended_degree = (self.degree+1) * rate;
        let omega = F::get_root_of_unity(extended_degree).unwrap();
        let mut root = F::ONE;

        let mut points: HashMap<F, Box<Point<F>>> = HashMap::new();
        let mut roots_preimage: BiHashMap<F, u64> = BiHashMap::new();
        // let p_1 = self.points.get(&(-root)).unwrap();
        for i in 0..extended_degree/2 {
            assert_ne!(folding_number, root);
            let w2 = root * root;
            roots_preimage.insert(w2, i);
            let value = 
                (self.points.get(&root).unwrap().get_y() * (root + folding_number)
                + self.points.get(&(-root)).unwrap().get_y() * (root - folding_number)) / root.double();
            points.insert(w2, Box::new(Point::new(w2, value)));
            root = root * omega
        }

        PolynomialPoints {
            degree: self.degree / 2,
            points,
            roots_preimage: Some(roots_preimage)
        }
    }
}
