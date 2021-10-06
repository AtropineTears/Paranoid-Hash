use paranoid_hash::{ParanoidHash};

fn main(){
    // Default Config
        // [LIB] BLAKE2B_64
        // [OS] SHA512
    let context = ParanoidHash::default();

    // Blake2B and SHA512 Hash Function Returns
    let (blake_64,sha512) = context.read("example_file.txt").expect("Failed To Read File");
    
    let _compare_blake2b = ParanoidHash::compare_hash(blake_64,String::from("<INSERT_HASH>"));
    let _compare_sha512: bool = ParanoidHash::compare_hash(sha512,String::from("<INSERT_HASH>"));
}