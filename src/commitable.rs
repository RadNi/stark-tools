use ark_ff::PrimeField;

use crate::{merkletree::{new_pedersen_merkletree, PedersenMerkleTree, PedersenTreeConfig}, point::Point, polynomial::PolynomialPoints};

pub struct Commited<T> {
    pub data: T,
    pub ptree: PedersenMerkleTree
}

impl<T> Commited<T> {
    pub fn new(ptree: PedersenMerkleTree, data: T ) -> Commited<T> {
        Commited {
            data,
            ptree
        }
    }
}

pub trait Commitable<F: PrimeField>
where Self: Sized {
    fn commit(self, pedersen_config: &PedersenTreeConfig) -> Commited<Self>;
}

impl <F: PrimeField> Commitable<F> for PolynomialPoints<F> {
    fn commit(self, pedersen_config: &PedersenTreeConfig) -> Commited<Self> {
        // let leaf_hash_param = sha256::Sha256::T1::setup(rng);
        let mut points_vectorized = self.points.clone()
            .into_iter().collect::<Vec<(F, Box<Point<F>>)>>();
        let roots = &self.roots_preimage;
        // println!("{:?}", roots);
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
        let list = points_vectorized.iter().map(|p| p.1.get_y()).collect::<Vec<F>>();
        // println!("listt: {:?}", list.iter()
            // .map(|x| x.into_bigint().to_bytes_be()).collect::<Vec<Vec<u8>>>()
        // );
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