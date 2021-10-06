use paranoid_hash::ParanoidHash;

#[test]
fn compare_strings(){
    let compare_same_str = ParanoidHash::compare_hash("Hello World", "Hello World");
    assert_eq!(compare_same_str,true);

    let compare_same_string: bool = ParanoidHash::compare_hash(String::from("This is America!"), String::from("This is America!"));
    assert_eq!(compare_same_string,true);

    let hash_comparison: bool = ParanoidHash::compare_hash("333fcb4ee1aa7c115355ec66ceac917c8bfd815bf7587d325aec1864edd24e34d5abe2c6b1b5ee3face62fed78dbef802f2a85cb91d455a8f5249d330853cb3c", "333fcb4ee1aa7c115355ec66ceac917c8bfd815bf7587d325aec1864edd24e34d5abe2c6b1b5ee3face62fed78dbef802f2a85cb91d455a8f5249d330853cb3c");
    assert_eq!(hash_comparison,true);
}

#[test]
fn compare_invalid_str(){
    let compare_different_str: bool = ParanoidHash::compare_hash("Hello Worls", "Hello World");
    assert_eq!(compare_different_str,false);

    let compare_different_length: bool = ParanoidHash::compare_hash("Hello World!", "Hello World");
    assert_eq!(compare_different_length,false);

    let hello: bool = ParanoidHash::compare_hash(String::from("Hello"),String::from("Hella"));
    assert_eq!(hello,false);
}

#[test]
fn compare_invalid_case(){
    let invalid_case: bool = ParanoidHash::compare_hash("333fcb4ee1aa7c115355ec66ceac917c8bfd815bf7587d325aec1864edd24e34d5abe2c6b1b5ee3face62fed78dbef802f2a85cb91d455a8f5249d330853cb3c","333FCB4EE1AA7C115355EC66CEAC917C8BFD815BF7587D325AEC1864EDD24E34D5ABE2C6B1B5EE3FACE62FED78DBEF802F2A85CB91D455A8F5249D330853CB3C");
    assert_eq!(invalid_case,false);
}