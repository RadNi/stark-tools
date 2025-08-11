use std::collections::btree_map::Range;
use std::collections::{HashMap, HashSet};
use std::ffi::os_str::Display;
use std::fmt::Debug;
use std::hash::Hash;
use std::ops::Deref;
use std::vec;

use ark_ff::{AdditiveGroup, BigInt, FftField, Field as Field, Fp, FpConfig, MontBackend, MontConfig, UniformRand};
use ark_ff::fields::models::fp::Fp as Fx;
use ark_std::rand::Rng;

// impl<T: MontConfig<N>, const N: usize> Fp<MontBackend<T, N>, N> {
// }
type F<T, const N:usize> = Fp<MontBackend<T, N>, N>;

#[derive(Debug)]
pub struct Point
<T, const N: usize> 
where T: MontConfig<N> 
{
    x: F<T, N>,
    y: F<T, N>,
}

impl<T, const N: usize> Clone for Point<T, N> where T: MontConfig<N> {
    fn clone(&self) -> Self {
        Self { x: self.x.clone(), y: self.y.clone() }
    }
}

impl<T, const N: usize> Point<T, N> where T: MontConfig<N> {
    pub fn get_x(&self) -> F<T, N> {
        self.x
    }
    pub fn get_y(&self) -> F<T, N> {
        
        self.y
    }
    pub const fn new(x: BigInt<N>, y: BigInt<N>) -> Self {
        Point {
            x: F::new(x),
            y: F::new(y)
        }
    }

    pub fn new_random<R: Rng + ?Sized>(rng: &mut R) -> Self {
        let x: F<T, N> = F::rand(rng);
        let y: F<T, N> = F::rand(rng);
        Self { x: x, y: y }
    }
}

impl<T, const N:usize> std::fmt::Display for Point<T, N>
where T: MontConfig<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "({}, {})", self.x, self.y)
    }
}

#[derive(Debug, Clone)]
pub struct PolynomialCoefficient<
T, const N: usize
> 
where T: MontConfig<N> 
{
    pub degree: u64,
    // pub points: Option<Vec<Point<T, N>>>,
    pub coefficients: Vec<F<T, N>>
}
impl<T, const N:usize> std::fmt::Display for PolynomialCoefficient<T, N>
where T: MontConfig<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result  {
                // write!(f, "Polynomial with points:\n")?;
                // for (i, point) in points.iter().enumerate() {
                //     let result = write!(f, "{}: {}\n", i, point);
                //     if result.is_err() {
                //         return Err(result.unwrap_err()); // or result.unwrap_err() if you needed the error
                //     }
                
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
pub struct PolynomialPoints<
T, const N: usize
> 
where T: MontConfig<N> 
{
    pub degree: u64,
    pub points: HashMap<F<T, N>, Point<T, N>>,
}

impl<T, const N:usize> std::fmt::Display for PolynomialPoints<T, N>
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

impl <T, const N: usize> Polynomial<N, T, Vec<(BigInt<N>, BigInt<N>)>> for PolynomialPoints<T, N> 
where T: MontConfig<N>,
{
    fn zero(degree: u64) -> Self {
        Self {
            degree: degree,
            points: HashMap::new()
        }
    }

    fn new(degree: u64, raw: Vec<(BigInt<N>, BigInt<N>)>) -> Self {
        Self {
            degree,
            points: raw.iter().map(|x| (F::new(x.0), Point::<T, N>::new(x.0, x.1))).collect()
        }
    }

    fn random_poly<R: Rng + ?Sized>(rng: &mut R, degree: u64) -> Self {
        Self { 
            degree, 
            points: (0..(degree+1)).map(|_| { let p = Point::new_random(rng); (p.get_x(), p) }).collect()
        }
    }

    fn random_poly_smooth_subgroup<R: Rng + ?Sized>(rng: &mut R, degree: u64) -> Self {
        let mut points = HashMap::new();
        let omega = F::get_root_of_unity((degree + 1)).unwrap();
        let mut root = omega;
        for _ in 0..(degree + 1) {
            let point: Point<T, N> = Point {
                x: root,
                y: F::rand(rng)
            };
            points.insert(point.get_x(), point);
            root = root * omega;
        }
        PolynomialPoints { degree: degree, points: points }
    }

    fn fft(self, rate: u64) -> PolynomialPoints<T, N> {
        // TODO add error handling if the extended degree is less than degree
        todo!()
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


    // fn random_poly_smooth_subgroup<R: Rng + ?Sized>(rng: &mut R, degree: u64) -> Self {
    //     let mut points: Vec<Point<T, N>> = vec![];
    //     let omega: F<T, N> = F::get_root_of_unity(degree).unwrap();
    //     let mut root: F<T, N> = F::ONE;
    //     for i in 0..degree {
    //         points.push(Point{
    //             x: root,
    //             y: F::rand(rng)
    //         });
    //         root = root * omega;
    //     }
    //     Self {
    //         degree,
    //         points: Some(points),
    //         coefficients: None
    //     }
    // }

    // fn new(degree: u64, raw: Vec<(BigInt<N>, BigInt<N>)>) -> Self {
    //     let mut points: Vec<Point<T, N>> = vec![];
    //     assert_eq!(points_raw.len(), degree as usize);
    //     points_raw.iter().for_each(|e| points.push(Point::new(e.0, e.1)));

    //     Self {
    //         degree: degree,
    //         points: Some(points),
    //         coefficients: None
    //     }
    // }

    // pub fn from_coefficients(coefficients: Vec<F<T, N>>) -> Self {
    //     Self {
    //         degree: coefficients.len() as u64,
    //         points: None,
    //         coefficients: Some(coefficients)
    //     }
    // }

    // pub fn random_poly_points<R: Rng + ?Sized>(rng: &mut R, degree: u64) -> Self {
    //     let mut points: Vec<Point<T, N>> = vec![];

    //     for _ in 0..degree {
    //         points.push(Point::new_random(rng));
    //     }
    //     Self {
    //         degree,
    //         points: Some(points),
    //         coefficients: None
    //     }
    // }



    // pub fn split(&self) -> [Self; 2] {
    //     let p_e: Polynomial<T, N> = Polynomial { 
    //         degree: self.degree/2, 
    //         points: None, 
    //         coefficients: 
    //             Some(
    //                 coefficients.iter().step_by(2).cloned().collect()
    //             )
    //     };
    //     let p_o: Polynomial<T, N> = Polynomial { 
    //         degree: self.degree/2, 
    //         points: None, 
    //         coefficients: 
    //             Some(
    //                 coefficients.iter().skip(1).step_by(2).cloned().collect()
    //             )
    //     };

    //     [p_e, p_o]
        
    // }

    fn fft(self, rate: u64) -> PolynomialPoints<T, N> {
        let extended_degree = (self.degree + 1) * rate;
        let omega: F<T, N> = F::get_root_of_unity(extended_degree as u64).unwrap();
        let mut root = F::ONE;
        if self.degree == 0 {
            let value = self.coefficients.get(0).unwrap();
            let mut points = HashMap::new();
            for _ in 0..extended_degree {
                points.insert(root, Point {
                    x: root,
                    // Because it's a degree zero polynomial it's value is always fixed
                    y: *value
                });
                root = root * omega;
            }
            return PolynomialPoints { 
                degree: 1, 
                points: points
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

        let mut points = HashMap::new();
        let mut roots: Vec<F<T, N>> = vec![F::ONE];
        for i in 0..extended_degree {
            let x = roots.get(i as usize).unwrap().clone();
            let new_root = x * omega;
            roots.push(new_root);

            let j = if i >= extended_degree/2 { i - extended_degree/2 } else { i };
            let w = roots.get(j as usize).unwrap();
            let w2 = w*w;
            let y_e_j = p_e.points.get(&w2).unwrap().get_y();
            let y_o_j = p_o.points.get(&w2).unwrap().get_y();
            
            if i < extended_degree/2 {
                points.insert(x,
                    Point{
                        x,
                        y: y_e_j + y_o_j * x
                    }
                );
            } else {
                let old_root = roots.get(j as usize).unwrap().clone();
                points.insert(x,
                    Point{
                        x,
                        y: y_e_j - y_o_j * old_root
                    }
                );
            }
        }
        PolynomialPoints {
            degree: self.degree,
            points: points
        }
    }

    fn ifft(self, extended_degree: u64) -> PolynomialCoefficient<T, N> {
        self
    }


    // pub fn from_coefficients(Vec<F<T, N>>)

    // pub fn to_coefficients(&self) -> Vec<F<T, N>> {

    // }
}
pub trait Foldable2<T, const N: usize>
where Self: Sized, T: MontConfig<N>

{
    fn fold(&self, rate: u64, folding_number: F<T, N>) -> PolynomialPoints<T, N>;
}

impl <T, const N: usize> Foldable2<T, N> for PolynomialPoints<T, N> 
where T: MontConfig<N>
{
    fn fold(&self, rate: u64, folding_number: F<T, N>) -> PolynomialPoints<T, N> {
        let extended_degree = (self.degree+1) * rate;
        let omega: F<T, N> = F::get_root_of_unity(extended_degree).unwrap();
        let mut root = F::ONE;

        let mut points: HashMap<F<T, N>, Point<T, N>> = HashMap::new();
        let p_1 = self.points.get(&(-root)).unwrap();
        for _ in 0..extended_degree/2 {
            assert_ne!(folding_number, root);
            let w2 = root * root;
            let value: F<T, N> = 
                (self.points.get(&root).unwrap().get_y() * (root + folding_number)
                + self.points.get(&(-root)).unwrap().get_y() * (root - folding_number)) / root.double();
            points.insert(w2, Point { x: w2, y: value });
            root = root * omega
        }

        PolynomialPoints {
            degree: self.degree / 2,
            points
        }
    }
}

// impl <T, const N: usize, const L:usize> Foldable<L> for Polynomial<T, N> 
// where T: MontConfig<N> + Debug
// {
//     fn fold(&self) -> [Self; L] {
//         let y: [Polynomial<T, N>; L] = (0..L).map(|_| Polynomial::<T, N>::zero((N/L) as u64))
//             .into_iter()
//             .collect::<Vec<Polynomial<T, N>>>()
//             .try_into()
//             .unwrap();
//         y
        // let x: [Self; L] = (0..N).map(|_| Polynomial::random_poly_coefficient(rng, 1));
        // return x
//     }
// }

