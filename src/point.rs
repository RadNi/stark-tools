use std::fmt::Debug;
use ark_ff::PrimeField;
use ark_std::rand::Rng;

#[derive(Debug)]
pub struct Point
<F: PrimeField>
{
    x: F,
    y: F,
}

impl<F: PrimeField> Clone for Point<F> {
    fn clone(&self) -> Self {
        Self { x: self.x.clone(), y: self.y.clone() }
    }
}

impl<F: PrimeField> Point<F> {
    pub fn get_x(&self) -> F {
        self.x
    }
    pub fn get_y(&self) -> F {
        
        self.y
    }
    pub const fn new(x: F, y: F) -> Self {
        Point {
            x,
            y
        }
    }

    pub fn new_random<R: Rng + ?Sized>(rng: &mut R) -> Self {
        let x: F = F::rand(rng);
        let y: F = F::rand(rng);
        Self { x: x, y: y }
    }
}

impl<F: PrimeField> std::fmt::Display for Point<F>{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "({}, {})", self.x, self.y)
    }
}
