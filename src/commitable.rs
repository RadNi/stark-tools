use ark_ed_on_bls12_381::{EdwardsProjective};

use ark_ff::{BigInteger, Fp, MontBackend, MontConfig, PrimeField};
use ark_std::rand::Rng;

type F<T, const N:usize> = Fp<MontBackend<T, N>, N>;

use crate::{merkletree::{new_pedersen_merkletree, PedersenMerkleTree, PedersenTreeConfig}, point::Point, polynomial::PolynomialPoints};

pub struct Commited<T> {
    pub data: T,
    pub ptree: PedersenMerkleTree
}

pub trait Commitable<T, const N: usize>
where Self: Sized, T: MontConfig<N> {

    fn commit<R: Rng>(self, rng:&mut R, pedersen_config: &PedersenTreeConfig) -> Commited<Self>;
}

impl <T, const N: usize> Commitable<T, N> for PolynomialPoints<T, N> 
where T: MontConfig<N> {
    fn commit<R: Rng>(self, rng: &mut R, pedersen_config: &PedersenTreeConfig) -> Commited<Self> {
        // let leaf_hash_param = sha256::Sha256::T1::setup(rng);
        let mut points_vectorized = self.points.clone()
            .into_iter().collect::<Vec<(F<T, N>, Box<Point<T, N>>)>>();
        let roots = &self.roots_preimage;
        println!("{:?}", roots);
        points_vectorized.sort_by(|p1, p2| 
            roots.as_ref()
            .unwrap()
            .get_by_left(&p1.0)
            .cmp(
                &roots.as_ref()
                .unwrap()
                .get_by_left(&p2.0)
            )
        );
        let list = points_vectorized.iter().map(|p| p.1.get_y()).collect::<Vec<F< T, N>>>();
        println!("listt: {:?}", list.iter()
            .map(|x| x.into_bigint().to_bytes_be()).collect::<Vec<Vec<u8>>>()
        );
        let ptree = new_pedersen_merkletree(
            pedersen_config,
            list
        );
        // let tree = MerkleTree::blank(sha256::Sha256 as TwoToOneCRHScheme, sha256::Sha256::setup(rng), 10);
        // let tree = MerkleTree::new::<BigInt<N>>(
        //     &(), 
        //     &(),
        //     x
        // ).unwrap();
        Commited {
            data: self,
            ptree
        }
        // todo!()
    }
}