use paranoid_hash::{ParanoidHash};

fn main(){
    // Default Config
        // [LIB] BLAKE2B_64
        // [OS] SHA512
    let context = ParanoidHash::default();

    // Blake2B and SHA512 Hash Function Returns
    let (_blake,_sha256) = context.read("example_file.txt");

}