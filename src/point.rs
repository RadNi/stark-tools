use std::fmt::Debug;
use ark_ff::{Fp, MontBackend, MontConfig, UniformRand};
use ark_std::rand::Rng;

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
    pub const fn new(x: F<T, N>, y: F<T, N>) -> Self {
        Point {
            x,
            y
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
