# Paranoid-Hash

[![Crates.io](https://img.shields.io/crates/v/paranoid-hash?style=flat-square)](https://crates.io/crates/paranoid-hash)![Crates.io](https://img.shields.io/crates/l/paranoid-hash?style=flat-square)

**Paranoid-Hash** is a rust crate for hashing files, strings, or bytes using a hash function provided by a Rust Library and the hash function provided by the Operating System.

## Features

### Hash Functions

The **Library Hash Function** that is used is **Blake2b** with any given digest size between 1 and 64.

The **Operating System Hash Function** can be either **SHA1**, **SHA256**, or **SHA512**.

### Compare Hashes

A function to compare hash functions is included and attempts to be constant-time.

### Hexadecimal Representation

The hash function returns two strings that are encoded in **hexadecimal**. You can get the **byte representation** by using the function `decode_from_hex()`.

## How To Use

### Choose Digest Size and Hash Function

```rust
use paranoid_hash::{ParanoidHash,OsAlgorithm};

fn main(){
	// Hash Using Blake2b (32 bytes) and SHA256
	let context = ParanoidHash::new(32usize,OsAlgorithm::SHA256);
}
```

### Hash A File

```rust
use paranoid_hash::{ParanoidHash};

fn main(){
    // Default Config
        // [LIB] BLAKE2B_64
        // [OS] SHA512
    let context = ParanoidHash::default();

    // Blake2B and SHA512 Hash Function Returns
    let (blake_64,sha512) = context.read("example_file.txt").expect("Failed To Read File");
}
```

### Hash A String

```rust
use paranoid_hash::{ParanoidHash};

fn main(){
	let s: String = String::from("Hello. This string will be hashed");

	let context = ParanoidHash::default();
	
	let (blake2b,sha512) = context.read_str(s);

}
```

### Hash Bytes

```rust
use paranoid_hash::{ParanoidHash};

fn main(){
	let bytes: Vec<u8> = vec![78,32,48,64];

	let context = ParanoidHash::default();
	
	let (blake2b,sha512) = context.read_bytes(&bytes);

}
```

### Decode From Hexadecimal

```rust
use paranoid_hash::{ParanoidHash};

fn main(){
	let bytes: Vec<u8> = vec![78,32,48,64];

	let context = ParanoidHash::default();
	
	let (blake2b,sha512) = context.read_bytes(&bytes);
    
    let hash_bytes = ParanoidHash::decode_from_hex(blake2b);

}
```

## License

This is licensed under:

* MIT License
* Apache 2.0

