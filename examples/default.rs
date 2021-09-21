use paranoid_hash::{ParanoidHash,OsAlgorithm};

fn main(){
    // Default Config
        // [LIB] BLAKE2B_64
        // [OS] SHA512
    let context = ParanoidHash::default();

    // Blake2B and SHA512 Hash Function Returns
    let (hash1,hash2) = context.read("example_file.txt");

}