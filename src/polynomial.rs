use std::{collections::HashMap};
use std::fmt::Debug;
use std::vec;

use ark_ff::{AdditiveGroup, BigInt, BigInteger, FftField, Field as Field, Fp, MontBackend, MontConfig, PrimeField, UniformRand};
use ark_std::rand::Rng;
use bimap::{BiHashMap};

use crate::point::Point;

type F<T, const N:usize> = Fp<MontBackend<T, N>, N>;

#[derive(Debug)]
pub struct PolynomialCoefficient<
T, const N: usize
> 
where T: MontConfig<N> 
{
    pub degree: u64,
    // pub points: Option<Vec<Point<T, N>>>,
    pub coefficients: Vec<F<T, N>>
}

impl<T, const N: usize> Clone for PolynomialCoefficient<T, N>
where T: MontConfig<N> {
    fn clone(&self) -> Self {
        let mut clonedCoefficients: Vec<F<T, N>> = vec![];
        self.coefficients.iter().for_each(|c| clonedCoefficients.push(
            F::new(c.into_bigint().clone())
        ));
        Self { degree: self.degree.clone(), coefficients: clonedCoefficients }
    }
}

impl<T, const N:usize> std::fmt::Display for PolynomialCoefficient<T, N>
where T: MontConfig<N> {
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

#[derive(Debug, Clone)]
pub struct PolynomialPoints<T, const N: usize> 
where T: MontConfig<N> 
{
    pub degree: u64,
    pub points: HashMap<F<T, N>, Box<Point<T, N>>>,
    pub roots_preimage: Option<BiHashMap<F<T, N>, u64>>
}

impl<'a, T, const N:usize> std::fmt::Display for PolynomialPoints<T, N>
where T: MontConfig<N> {
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

pub trait Polynomial<const N: usize, T, T1> 
where T: MontConfig<N> {
    fn zero(degree: u64) -> Self;
    fn new(degree: u64, raw: T1) -> Self;
    fn random_poly<R: Rng + ?Sized>(rng: &mut R, degree: u64) -> Self;
    fn random_poly_smooth_subgroup<R: Rng + ?Sized>(rng: &mut R, degree: u64) -> Self;
    fn fft(self, rate: u64) -> PolynomialPoints<T, N>;
    fn ifft(self, rate: u64) -> PolynomialCoefficient<T, N>;
}

impl <'a, T, const N: usize> Polynomial<N, T, Vec<Point<T, N>>> for PolynomialPoints<T, N> 
where T: MontConfig<N>,
{
    fn zero(degree: u64) -> Self {
        Self {
            degree: degree,
            points: HashMap::new(),
            roots_preimage: None
        }
    }
    
    fn new(degree: u64, raw: Vec<Point<T, N>>) -> Self {
        Self {
            degree,
            points: raw.iter().map(|p| (p.get_x(), Box::new(p.clone()))).collect(),
            roots_preimage: None
        }
    }


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
            let point: Point<T, N> = Point::new(
                root,
                F::rand(rng)
            );
            points.insert(point.get_x(), Box::new(point));
            root = root * omega;
        }
        PolynomialPoints { degree, points, roots_preimage: Some(roots_preimage) }
    }

    fn fft(self, rate: u64) -> PolynomialPoints<T, N> {
        // TODO add error handling if the extended degree is less than degree
        self
    }

    fn ifft(self, rate: u64) -> PolynomialCoefficient<T, N> {
        todo!()
    }
}

impl <T, const N: usize> Polynomial<N, T, Vec<F<T, N>>> for PolynomialCoefficient<T, N> 
where T: MontConfig<N>
  {
    fn zero(degree: u64) -> Self {
        Self {
            degree: degree,
            coefficients: vec![]
        }
    }

    fn new(degree: u64, raw: Vec<F<T, N>>) -> Self {
        assert!(raw.len() >= (degree + 1) as usize);

        Self {
            degree: degree,
            coefficients: raw
        }
    }


    fn random_poly<R: Rng + ?Sized>(rng: &mut R, degree: u64) -> Self {
        let mut coefficients: Vec<F<T, N>> = vec![];
        for i in 0..(degree + 1) {
            // coefficients.push(F::rand(rng));
            // let num: u64 = rand::random_range(0..20);
            let mut v = [0; N];
            v[0] = i*2+1;
            coefficients.push(F::new(BigInt(v)));
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

    fn fft(self, rate: u64) -> PolynomialPoints<T, N> {
        let extended_degree = (self.degree + 1) * rate;
        let omega: F<T, N> = F::get_root_of_unity(extended_degree as u64).unwrap();
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
        let p_e: PolynomialPoints<T, N> = PolynomialCoefficient { 
            degree: self.degree/2, 
            coefficients: self.coefficients.iter().step_by(2).cloned().collect()
        }.fft(rate);
        let p_o: PolynomialPoints<T, N> = PolynomialCoefficient { 
            degree: self.degree/2, 
            coefficients: self.coefficients.iter().skip(1).step_by(2).cloned().collect()
        }.fft(rate);

        let mut points: HashMap<Fp<MontBackend<T, N>, N>, Box<Point<T, N>>> = HashMap::new();
        let mut roots_preimage = BiHashMap::new();
        // let mut roots: Vec<F<T, N>> = vec![F::ONE];
        for i in 0..extended_degree {
            roots_preimage.insert(root, i);
            root = root * omega;

            let j = if i >= extended_degree/2 { i - extended_degree/2 } else { i };
            let w = roots_preimage.get_by_right(&j).unwrap();
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

    fn ifft(self, extended_degree: u64) -> PolynomialCoefficient<T, N> {
        todo!()
    }
}
pub trait Foldable2<T, const N: usize>
where Self: Sized, T: MontConfig<N>

{
    fn fold(&self, folding_number: F<T, N>) -> PolynomialPoints<T, N>;
    fn fold_bytes(&self, folding_number: [u64; N]) -> PolynomialPoints<T, N> {
        self.fold(F::new(BigInt::<N>::new(folding_number)))
    }
}

impl <T, const N: usize> Foldable2<T, N> for PolynomialPoints<T, N> 
where T: MontConfig<N>
{
    fn fold(&self, folding_number: F<T, N>) -> PolynomialPoints<T, N> {
        let extended_degree = (self.degree+1);
        let omega: F<T, N> = F::get_root_of_unity(extended_degree).unwrap();
        let mut root = F::ONE;

        let mut points: HashMap<F<T, N>, Box<Point<T, N>>> = HashMap::new();
        let mut roots_preimage: BiHashMap<F<T, N>, u64> = BiHashMap::new();
        // let p_1 = self.points.get(&(-root)).unwrap();
        for i in 0..extended_degree/2 {
            assert_ne!(folding_number, root);
            let w2 = root * root;
            roots_preimage.insert(w2, i);
            let value: F<T, N> = 
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
