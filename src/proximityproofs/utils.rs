use ark_crypto_primitives::{merkle_tree::Path, sponge::Absorb};
use ark_ff::{BigInt, PrimeField};
use stark_tools::{commitable::Commited, merkletree::MerkleConfig, polynomial::PolynomialPoints};

pub fn path_to_bytes(path: Path<MerkleConfig>) -> Result<Vec<[u8; 32]>, String> {
    // println!("path to bytes: {:?}", path);
    let mut res: Vec<[u8; 32]> = vec![];
    res.push(path.leaf_sibling_hash.to_sponge_bytes_as_vec().try_into().map_err(|v: Vec<u8>| format!("expected 32 bytes, got {}", v.len()))?);
    res[0].reverse();
    for i in 0..path.auth_path.len() {
        res.push(path.auth_path[i].to_sponge_bytes_as_vec().try_into().map_err(|v: Vec<u8>| format!("expected 32 bytes, got {}", v.len()))?);
        res[i + 1].reverse();
    }
    Ok(res)
}
// path to bytes: Path { leaf_sibling_hash: 29019666737956306800262246500759730249651687828223212625784994980408929564802, auth_path: [4982699993606047466420604557841274890212484493052668191907527988462817840057, 30034249863412613020425381884716586586712030053712760496840581412335049614427], leaf_index: 1 }
// Path:       Ok(Path { leaf_sibling_hash: 5900475631263479918354771766276089294664006478654606367786112, auth_path: [6226884921503587318036801755921584717323419914465477444764292, 6182945209355880552831848976965162391676867545781016050271157], leaf_index: 1 })
pub fn bytes_to_path(proof: Vec<[u8; 32]>, query_index: usize) -> Result<Path<MerkleConfig>, String> {

    // let bn: BigIntCanonical<4> = bytes_to_bigints_canonical(proof[0]);
    // let sibling = ark_ed_on_bls12_381::Fq::new(bn);
    Ok(Path {
            leaf_sibling_hash: bytes_to_bls(proof[0]),
            auth_path: proof[1..].iter().map(|e| bytes_to_bls(*e)).collect(),
            leaf_index: query_index,
        })
}

pub fn prove_leaf_index <F: PrimeField> (
    commited_poly: &Commited<PolynomialPoints<F>>, index: u64) -> Result<(F, Path<MerkleConfig>), String> {
    let roots = commited_poly.data.roots_preimage.as_ref().ok_or_else(|| format!("roots_preimage is None!"))?;
    let queried_x = roots.get_by_right(&index).ok_or_else(|| format!("could not find index {index}"))?;
    let leaf_value = commited_poly.data.points.get(queried_x).and_then(|y| Some(y.get_y())).ok_or_else(|| format!("could not find leaf_value for index {index}"))?;
    let path = commited_poly.ptree.generate_proof(index as usize).map_err(|e| format!("faild to generate proof! {e}"))?;
    Ok((leaf_value, path))
}


pub fn bytes_to_bigints<const N: usize>(bytes: Vec<u8>) -> BigInt<N> {
    assert_eq!(bytes.len() / 8, N);
    let mut res = [0u64; N];
    for i in 0..N {
        let mut sum: u64 = 0;
        for j in 0..8 {
            sum = (sum << 8) | (bytes[i * 8 + j] as u64);
        }
        res[i] = sum;
    }
    res.reverse();

    BigInt::new(res)
}



pub fn bytes_to_bigints_canonical<const N1: usize, const N2: usize>(bytes: [u8; N1]) -> BigInt<N2> {
    let mut res: [u64; N2] = [0; N2];
    for i in 0..N2 {
        let mut sum: u64 = 0;
        for j in 0..8 {
            sum *= 256;
            sum += bytes[i * 8 + j] as u64;
        }
        res[i] = sum;
    }
    // println!("input: {:?} output: {:?}", bytes, res);
    res.reverse();
    BigInt::new(res)
}

pub fn bytes_to_bls(bytes: [u8; 32]) -> ark_ed_on_bls12_381::Fq {
    ark_ed_on_bls12_381::Fq::new(bytes_to_bigints_canonical::<32, 4>(bytes))
}
