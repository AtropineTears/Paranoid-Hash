// Developed By @AtropineTears | @OpenNightshade
// 21 September 2021

//! # Paranoid-Hash
//! 
//! Paranoid-Hash is a **cross-platform**, **memory-safe**, **simple to use** library for hashing files securely with use of two hash functions. 
//! 
//! The two hash functions are provided by a library in **pure rust** and the **operating system hash function**.
//! 
//! It supports the following hash functions
//! * [Library] BLAKE2B
//! * [OS] SHA1
//! * [OS] SHA256
//! * [OS] SHA512
//! 
//! For optimal security with a large security margin, it is recommended to use BLAKE2B with atleast a 48 byte digest and SHA256/SHA512.
//! 
//! ## Default
//! 
//! The **Default Configuration** has a large security margin. It uses:
//! * BLAKE2B with a digest size of 64 bytes
//! * SHA512
//! 
//! ## Filebuffer: Fast and Simple File Reading In Rust
//! 
//! Paranoid-Hash uses a simple file reading library called `Filebuffer` that is faster than rust's std::io.
//! 
//! If you wish to use the standard library instead, you can use `read_using_fs()`
//! 
//! ## Handling The Return Type
//! 
//! After hashing, two variables are returned. The first one is the Blake2B hash digest. The second one is the chosen operating system digest.
//! 
//! ## How To Use
//! 
//! This is an example using Blake2B (64 byte digest) and SHA256 (OS) to hash a file
//! 
//! ```rust
//! use paranoid_hash::{ParanoidHash,OsAlgorithm};
//! fn main(){
//!     let context = ParanoidHash::new(64,OsAlgorithm::SHA256);
//! 
//!     let (blake2,sha256) = context.read("example_file.txt");
//! 
//!     let bytes_b2 = ParanoidHash::as_bytes(&blake2);
//!     let bytes_sha = ParanoidHash::as_bytes(&sha256);
//! }
//! ```

#![forbid(unsafe_code)]


use blake2_rfc::blake2b::Blake2b;
use crypto_hash::{Algorithm, Hasher};
use std::io::Write;

use filebuffer::FileBuffer;
use std::path::Path;


// For Reading Files without use FileBuffer
use std::fs;

// For Developer:
// * All outputs are in upper hexadecimal
// * You can use `as_bytes()` to convert from hexadecimal string to bytes
// * Blake2b digest size is between 1 and 64 bytes and will always be returned in hexadecimal format as a `String`
// * One function `read_using_fs()` uses the standard library as opposed to filebuffer to read files.

/// # SecureHash Hashing Constructor
/// 
/// This struct is used to get the configuration for hashing
#[derive(Debug,Clone,PartialEq,PartialOrd,Hash)]
pub struct ParanoidHash {
    digest_size: usize,
    os_hash_function: OsAlgorithm,
}

/// # OS Hashing Function
/// 
/// This enum contains three hash functions that is performed by the operating system. It does not use MD5 which is deprecated and insecure.
/// 
/// It contains the following hash functions:
/// * SHA1
/// * SHA256
/// * SHA512
/// 
/// **Default** uses **SHA512**
#[derive(Debug,Clone,PartialEq,PartialOrd,Hash)]
pub enum OsAlgorithm {
    SHA1,
    SHA256,
    SHA512,
}
#[derive(Debug,Clone,PartialEq,PartialOrd,Hash)]
pub enum FileError {
    FileNotFound,
    OsHashingError,
}

impl Default for OsAlgorithm {
    fn default() -> Self { OsAlgorithm::SHA512 }
}

impl Default for ParanoidHash {
    fn default() -> Self {
        return Self {
            digest_size: 64usize,
            os_hash_function: OsAlgorithm::SHA512
        }
    }
}

impl ParanoidHash {
    /// # New Hasher
    /// 
    /// This method allows you to construct the hasher.
    /// 
    /// It accepts the following:
    /// 
    /// * BLAKE2B Digest Size In Bytes `[1-64]`
    /// * Operating System Hash Function `{SHA1,SHA256,SHA512}`
    /// 
    /// You can choose to use the default if you want optimal security.
    /// 
    /// ## Example Code
    /// ```rust
    /// use paranoid_hash::{ParanoidHash,OsAlgorithm};
    /// 
    /// fn main(){
    ///     let context = ParanoidHash::new(64,OsAlgorithm::SHA256);
    /// }
    /// ```
    pub fn new(digest: usize,os_hash: OsAlgorithm) -> Self {
        if digest > 0 && digest <= 64 {
            return ParanoidHash {
                digest_size: digest,
                os_hash_function: os_hash,
            }
        }
        else {
            panic!("[Error] Digest Size is either too large or too small. It should be 1-64.")
        }
    }
    pub fn read<T: AsRef<Path>>(&self, path: T) -> Result<(String,String),FileError> {
        
        // Checks whether file exists. If file does not exist, returns error as FileError.
        let does_file_exist = path.as_ref().exists();
        if does_file_exist == false {
            return Err(FileError::FileNotFound)
        }

        // Opens File Using File Buffer
        let fbuffer = FileBuffer::open(path).expect("Failed To Read File");
        
        // Sets Blake2b Context at the given digest size
        let mut context = Blake2b::new(self.digest_size);
        context.update(&fbuffer);
        let hash = context.finalize();

        // Operating System Hashing
        let mut os_hasher: Hasher = match self.os_hash_function {
            OsAlgorithm::SHA1 => Hasher::new(Algorithm::SHA1),
            OsAlgorithm::SHA256 => Hasher::new(Algorithm::SHA256),
            OsAlgorithm::SHA512 => Hasher::new(Algorithm::SHA512),
        };

        // Finish Operating System Hashing
        os_hasher.write_all(&fbuffer).expect("[Error] Failed To Hash File Using Operating System Hash Function");
        let os_hash = os_hasher.finish();
        
        // Return as Upper Hexadecimal Encoded String
        return Ok((hex::encode_upper(hash.as_bytes()),hex::encode_upper(os_hash)))
    }
    /// # Read With Key
    /// 
    /// This method reads the file and uses a key with the Blake2b hash function. It does not and cannot use the key with the operating system hash function.
    pub fn read_with_key<T: AsRef<Path>>(&self, path: T, key: &[u8]) -> Result<(String,String),FileError> {
        
        // Checks if file exists. If file does not exist, returns error.
        let does_file_exist = path.as_ref().exists();
        if does_file_exist == false {
            return Err(FileError::FileNotFound)
        }

        // Opens File Using File Buffer
        let fbuffer = FileBuffer::open(path).expect("failed to open file");
        
        // Sets Blake2b Context at the given digest size and hashes with the provided key
        let mut context = Blake2b::with_key(self.digest_size, key);
        context.update(&fbuffer);
        let hash = context.finalize();
        
        // Operating System Hashing
        let mut os_hasher: Hasher = match self.os_hash_function {
            OsAlgorithm::SHA1 => Hasher::new(Algorithm::SHA1),
            OsAlgorithm::SHA256 => Hasher::new(Algorithm::SHA256),
            OsAlgorithm::SHA512 => Hasher::new(Algorithm::SHA512),
        };

        // Finish Operating System Hashing
        os_hasher.write_all(&fbuffer).expect("[Error] Failed To Hash File Using Operating System Hash Function");
        let os_hash = os_hasher.finish();
        
        // Return as Upper Hexadecimal Encoded String
        return Ok((hex::encode_upper(hash.as_bytes()),hex::encode_upper(os_hash)))
    }
    /// # Read useing std::fs
    /// 
    /// This function allows you to read files using `std::fs`. This is rust's default way of reading files.
    pub fn read_using_std<T: AsRef<Path>>(&self, path: T) -> Result<(String,String),FileError> {

        // Checks whether file exists and if it doesn't, returns error. For Error-Handling.
        let does_file_exist = path.as_ref().exists();
        if does_file_exist == false {
            return Err(FileError::FileNotFound)
        }

        // Opens File Using Standard Library (fs) and read file to string
        let fbuffer = fs::read(path).expect("failed to open file");

        
        // Sets Blake2b Context at the given digest size
        let mut context = Blake2b::new(self.digest_size);
        // Convert str to bytes and updated context
        context.update(&fbuffer);
        let hash = context.finalize();
        
        // Operating System Hashing
        let mut os_hasher = match self.os_hash_function {
            OsAlgorithm::SHA1 => Hasher::new(Algorithm::SHA1),
            OsAlgorithm::SHA256 => Hasher::new(Algorithm::SHA256),
            OsAlgorithm::SHA512 => Hasher::new(Algorithm::SHA512),
        };

        // Finish Operating System Hashing
        os_hasher.write_all(&fbuffer).expect("[Error] Failed To Hash File Using Operating System Hash Function");
        let os_hash = os_hasher.finish();
        
        // Return as Upper Hexadecimal Encoded String
        return Ok((hex::encode_upper(hash.as_bytes()),hex::encode_upper(os_hash)))
    }
    /// # Read String
    /// This function will allow you to take a `String` or `str`, convert it to bytes, then hash it.
    pub fn read_str<T: AsRef<str>>(&self, string: T) -> (String,String) {
        
        // Sets Blake2b Context at the given digest size
        let mut context = Blake2b::new(self.digest_size);
        // Convert str to bytes
        context.update(string.as_ref().as_bytes());
        let hash = context.finalize();
        
        // Operating System Hashing
        let mut os_hasher = match self.os_hash_function {
            OsAlgorithm::SHA1 => Hasher::new(Algorithm::SHA1),
            OsAlgorithm::SHA256 => Hasher::new(Algorithm::SHA256),
            OsAlgorithm::SHA512 => Hasher::new(Algorithm::SHA512),
        };

        // Finish Operating System Hashing
        os_hasher.write_all(string.as_ref().as_bytes()).expect("[Error] Failed To Hash File Using Operating System Hash Function");
        let os_hash = os_hasher.finish();
        
        // Return as Upper Hexadecimal Encoded String
        return (hex::encode_upper(hash.as_bytes()),hex::encode_upper(os_hash))
    }
    /// # Read Bytes
    /// 
    /// This function will hash bytes and return the output as two seperate strings.
    pub fn read_bytes(&self, bytes: &[u8]) -> (String,String) {
        
        // Sets Blake2b Context at the given digest size
        let mut context = Blake2b::new(self.digest_size);
        context.update(bytes);
        let hash = context.finalize();

        // Operating System Hashing
        let mut os_hasher = match self.os_hash_function {
            OsAlgorithm::SHA1 => Hasher::new(Algorithm::SHA1),
            OsAlgorithm::SHA256 => Hasher::new(Algorithm::SHA256),
            OsAlgorithm::SHA512 => Hasher::new(Algorithm::SHA512),
        };

        // Finish Operating System Hashing
        os_hasher.write_all(&bytes).expect("[Error] Failed To Hash File Using Operating System Hash Function");
        let os_hash = os_hasher.finish();
        
        // Return as Upper Hexadecimal Encoded String
        return (hex::encode_upper(hash.as_bytes()),hex::encode_upper(os_hash))
    }
    /// ## decode_from_hex()
    /// `decode_from_hex()` (which was `as_bytes()`) converts from a **Hexadecimal String** to a **Vector of Bytes**
    pub fn decode_from_hex<T: AsRef<str>>(s: T) -> Vec<u8> {
        return hex::decode(s.as_ref()).unwrap()
    }
    /// ## Return Digest Size
    /// This method will return the provided digest size that the struct contains. It should be between 1 and 64 of type `usize`.
    pub fn return_digest_size(&self) -> usize {
        return self.digest_size
    }
    /// ## Return Operating System Hash Function
    /// 
    /// This method will return the hash function used by the operating system that was chosen
    pub fn return_os_hash_algorithm(&self) -> OsAlgorithm {
        return self.os_hash_function.clone()
    }
    /// ## Compare Hash
    /// 
    /// **Notice:** This function attempts to use constant-time operations in comparing strings based on [this](https://stackoverflow.com/questions/44691363/how-to-compare-strings-in-constant-time).
    /// 
    /// **Description:** Compares two hash functions (case-insensitive) and if they are the same, returns true. If they are different, returns false.
    pub fn compare_hash<T: AsRef<str>>(hash1: T,hash2: T) -> bool {
        let hash1_lowercase = hash1.as_ref().to_lowercase();
        let hash2_lowercase: String = hash2.as_ref().to_lowercase();
        
        if hash1_lowercase.len() != hash2_lowercase.len() {
            return false;
        }
        hash1_lowercase.bytes().zip(hash2_lowercase.bytes())
            .fold(0, |acc, (a, b)| acc | (a ^ b) ) == 0
    }
    
}