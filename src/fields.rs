use ark_ff::{Fp192, Fp64, MontBackend, MontConfig};

#[derive(MontConfig)]
#[modulus = "18446744069414584321"]
#[generator = "7"]
pub struct FrConfig64;
pub type Goldilocks = Fp64<MontBackend<FrConfig64, 1>>;

#[derive(MontConfig)]
#[modulus = "4787605948707450321761805915146316350821882368518086721537"]
#[generator = "3"]
pub struct FrConfig192;
pub type Field192 = Fp192<MontBackend<FrConfig192, 3>>;