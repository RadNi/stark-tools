use std::collections::btree_map::Range;
use std::collections::HashSet;
use std::ffi::os_str::Display;
use std::fmt::Debug;
use std::ops::Deref;
use std::vec;

use ark_ff::{BigInt, FftField, Field as Field, Fp, FpConfig, MontBackend, MontConfig, UniformRand};
use ark_ff::fields::models::fp::Fp as Fx;
use ark_std::rand::Rng;

// impl<T: MontConfig<N>, const N: usize> Fp<MontBackend<T, N>, N> {
// }
type F<T, const N:usize> = Fp<MontBackend<T, N>, N>;

#[derive(Debug, Clone)]
pub struct Point
<T, const N: usize> 
where T: MontConfig<N> 
{
    x: F<T, N>,
    y: F<T, N>,
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
pub struct Polynomial<
T, const N: usize
> 
where T: MontConfig<N> 
{
    pub degree: u64,
    pub points: Option<Vec<Point<T, N>>>,
    pub coefficients: Option<Vec<F<T, N>>>
}


impl<T, const N:usize> std::fmt::Display for Polynomial<T, N>
where T: MontConfig<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.points {
            Some(points) => {
                write!(f, "Polynomial with points:\n")?;
                for (i, point) in points.iter().enumerate() {
                    let result = write!(f, "{}: {}\n", i, point);
                    if result.is_err() {
                        return Err(result.unwrap_err()); // or result.unwrap_err() if you needed the error
                    }

                }
            },
            None => {
                write!(f, "Polynomial with coefficients:\n")?;
                for (i, coefficient) in self.coefficients.as_ref().unwrap().iter().enumerate() {
                    let result = write!(f, "{}: {}\n", i, coefficient);
                    if result.is_err() {
                        return Err(result.unwrap_err()); // or result.unwrap_err() if you needed the error
                    }

                }

            }
        }
        Ok(())
    }
}


impl <T, const N: usize> Polynomial<T, N> 
where T: MontConfig<N>
  {

    pub fn zero(degree: u64) -> Self {
        Self {
            degree: degree,
            points: Some(vec![]),
            coefficients: Some(vec![])
        }
    }

    pub fn new(degree: u64, points_raw: Vec<(BigInt<N>, BigInt<N>)>) -> Self {
        let mut points: Vec<Point<T, N>> = vec![];
        assert_eq!(points_raw.len(), degree as usize);
        points_raw.iter().for_each(|e| points.push(Point::new(e.0, e.1)));

        Self {
            degree: degree,
            points: Some(points),
            coefficients: None
        }
    }

    pub fn from_coefficients(coefficients: Vec<F<T, N>>) -> Self {
        Self {
            degree: coefficients.len() as u64,
            points: None,
            coefficients: Some(coefficients)
        }
    }

    pub fn random_poly_points<R: Rng + ?Sized>(rng: &mut R, degree: u64) -> Self {
        let mut points: Vec<Point<T, N>> = vec![];

        for _ in 0..degree {
            points.push(Point::new_random(rng));
        }
        Self {
            degree,
            points: Some(points),
            coefficients: None
        }
    }

    pub fn random_poly_roots<R: Rng + ?Sized>(rng: &mut R, degree: u64) -> Self {
        let mut points: Vec<Point<T, N>> = vec![];
        let omega: F<T, N> = F::get_root_of_unity(degree).unwrap();
        let mut root: F<T, N> = F::ONE;
        for i in 0..degree {
            points.push(Point{
                x: root,
                y: F::rand(rng)
            });
            root = root * omega;
        }
        Self {
            degree,
            points: Some(points),
            coefficients: None
        }
    }

    pub fn random_poly_coefficient<R: Rng + ?Sized>(rng: &mut R, degree: u64) -> Self {
        let mut coefficients: Vec<F<T, N>> = vec![];
        for i in 0..degree {
            coefficients.push(F::rand(rng));
            // let num: u64 = rand::random_range(0..20);
            // let mut v = [0; N];
            // v[0] = i*2+1;
            // coefficients.push(F::new(BigInt(v)));
            // coefficients.push(F::new(BigInt(v)));
        }
        Self {
            degree,
            points: None,
            coefficients: Some(coefficients)
        }
    }

    pub fn fft(&mut self) -> Option<Polynomial<T, N>> {
        let omega: F<T, N> = F::get_root_of_unity(self.degree).unwrap();

        let Some(coefficients) = &self.coefficients else {
            return None
        };
        if self.degree == 1 {
            let value = self.coefficients.as_ref().unwrap().get(0).unwrap();
            return Some(
                Polynomial { 
                    degree: 1, 
                    points: Some(vec![Point {
                        x: F::ONE,
                        y: *value, 
                    }]),
                    coefficients: None
                }
            );
        }
        let p_e: Polynomial<T, N> = Polynomial { 
            degree: self.degree/2, 
            points: None, 
            coefficients: 
                Some(
                    coefficients.iter().step_by(2).cloned().collect()
                )
        }.fft().unwrap();
        let p_o: Polynomial<T, N> = Polynomial { 
            degree: self.degree/2, 
            points: None, 
            coefficients: 
                Some(
                    coefficients.iter().skip(1).step_by(2).cloned().collect()
                )
        }.fft().unwrap();

        let mut points: Vec<Point<T, N>> = vec![];
        let mut roots: Vec<F<T, N>> = vec![F::ONE];
        for i in 0..self.degree {
            let j = if i >= self.degree/2 { i - self.degree/2 } else { i };
            let y_e_j = p_e.points.as_ref().unwrap().get(j as usize).unwrap().get_y();
            let y_o_j = p_o.points.as_ref().unwrap().get(j as usize).unwrap().get_y();
            let x = roots.get(i as usize).unwrap().clone();
            roots.push(x * omega);
            if i < self.degree/2 {
                points.push(
                    Point{
                        x,
                        y: y_e_j + y_o_j * x
                    }
                );
            } else {
                let old_root = roots.get(j as usize).unwrap().clone();
                points.push(
                    Point{
                        x,
                        y: y_e_j - y_o_j * old_root
                    }
                );
            }
        }
        Some(Polynomial {
            degree: self.degree,
            coefficients: self.coefficients.clone(),
            points: Some(points)
        })
    }

    // pub fn from_coefficients(Vec<F<T, N>>)

    // pub fn to_coefficients(&self) -> Vec<F<T, N>> {

    // }
}
pub trait Foldable<const N: usize>
where Self: Sized
{
    fn fold(&self) -> [Self; N];
}

impl <T, const N: usize, const L:usize> Foldable<L> for Polynomial<T, N> 
where T: MontConfig<N> + Debug
{
    fn fold(&self) -> [Self; L] {
        let y: [Polynomial<T, N>; L] = (0..L).map(|_| Polynomial::<T, N>::zero((N/L) as u64))
            .into_iter()
            .collect::<Vec<Polynomial<T, N>>>()
            .try_into()
            .unwrap();
        y
        // let x: [Self; L] = (0..N).map(|_| Polynomial::random_poly_coefficient(rng, 1));
        // return x
    }
}

