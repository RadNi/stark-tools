use ark_ff::{Fp, MontBackend, MontConfig};
use ark_std::rand::Rng;

type F<T, const N:usize> = Fp<MontBackend<T, N>, N>;

use crate::{merkletree::{new_pedersen_merkle_tree, Root}, Point, PolynomialPoints};
pub trait Hashable<T, const N: usize>
where Self: Sized, T: MontConfig<N> {

    fn commit<R: Rng>(&self, rng:&mut R) -> Root;
}

impl <T, const N: usize> Hashable<T, N> for PolynomialPoints<T, N> 
where T: MontConfig<N> {
    fn commit<R: Rng>(&self, rng: &mut R) -> Root {
        // let leaf_hash_param = sha256::Sha256::T1::setup(rng);
        let mut points_vectorized = self.points.clone()
            .into_iter().collect::<Vec<(F<T, N>, Box<Point<T, N>>)>>();
        points_vectorized.sort_by(|p1, p2| p1.0.cmp(&p2.0));

        let tree = new_pedersen_merkle_tree(rng, 
            points_vectorized.iter().map(|p| p.1.get_y()).collect::<Vec<F<T, N>>>()
        );
        // let tree = MerkleTree::blank(sha256::Sha256 as TwoToOneCRHScheme, sha256::Sha256::setup(rng), 10);
        // let tree = MerkleTree::new::<BigInt<N>>(
        //     &(), 
        //     &(),
        //     x
        // ).unwrap();
        tree.root()
        // todo!()
    }
}