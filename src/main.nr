use dep::std;
use dep::std::println;
use dep::ecrecover;

fn main(x: [u32; 5], y: pub [u32; 5]) {
    // assert(x != y);
    let mut score = 0;
    for i in 0..5 {
        println(x[i]);
        println(y[i]);
        score += x[i] * y[i];
    }
    println("Score: ");
    println(score);
    let is_ok = (score > 10);
    println(is_ok);
    assert(is_ok == true);
}


#[test]
fn test_main() {
    main([1, 1, 1, 1, 1], [1, 2, 3, 4, 5]);
}


fn verify_signature(message_hash : [u8;32], pub_key_x : [u8;32], pub_key_y : [u8;32], signature : [u8;64]) {
    // hash the message again (this happens when we generate a deterministic signature)
    // the reason we do this is to ensure persistent input message length (always 32 bytes)
    let message_hash_2 = std::hash::sha256(message_hash);

    let valid_signature = std::ecdsa_secp256k1::verify_signature(pub_key_x, pub_key_y, signature, message_hash_2);
    assert(valid_signature);
}

#[test]
fn test_verify_signature() {
    let message_hash = [245, 223, 58, 50, 74, 76, 120, 255, 154, 66, 228, 77, 1, 67, 64, 61, 149, 67, 119, 15, 48, 228, 152, 123, 172, 4, 232, 97, 108, 104, 20, 218];
    let signature = [166, 5, 102, 196, 4, 203, 205, 221, 56, 19, 228, 3, 222, 136, 61, 36, 112, 92, 79, 87, 206, 201, 77, 255, 128, 33, 243, 19, 6, 203, 117, 68, 64, 145, 153, 152, 123, 48, 10, 242, 213, 114, 82, 234, 207, 147, 47, 163, 107, 163, 86, 100, 139, 143, 24, 187, 239, 255, 38, 96, 57, 176, 217, 97];
    let pub_key_x = [65, 34, 212, 75, 36, 198, 55, 190, 216, 124, 123, 16, 155, 212, 157, 97, 134, 53, 129, 94, 77, 244, 77, 51, 6, 129, 50, 68, 74, 235, 37, 210];
    let pub_key_y = [211, 232, 46, 182, 4, 74, 247, 123, 164, 157, 138, 102, 69, 90, 221, 123, 163, 149, 197, 48, 99, 43, 123, 165, 161, 23, 43, 120, 28, 250, 107, 209];
    verify_signature(message_hash, pub_key_x, pub_key_y, signature);
}


fn ecdsa_recover(message_hash : [u8;32], pub_key_x : [u8;32], pub_key_y : [u8;32], signature : [u8;64], hashes: pub [str<11>], providers: [str<12>], trusted_signer: Field) {
    // https://github.com/colinnielsen/ecrecover-noir/tree/main
    let message_hash_2 = std::hash::sha256(message_hash);
    let recovered_signer = ecrecover::ecrecover(pub_key_x, pub_key_y, signature, message_hash_2);


    assert(recovered_signer == trusted_signer);

    // let mut score = 0;
    // for i in 0..11 {
    //     let mut found = false;
    //     for j in 0..12 {
    //         if hashes[i] == std::hash::sha256(providers[j]) {
    //             found = true;
    //             break;
    //         }
    //     }
    //     if found {
    //         score += 1;
    //     }
    // }
    // assert(score >= 8);
}

#[test]
fn test_ecdsa_recover() {
    let message_hash = [245, 223, 58, 50, 74, 76, 120, 255, 154, 66, 228, 77, 1, 67, 64, 61, 149, 67, 119, 15, 48, 228, 152, 123, 172, 4, 232, 97, 108, 104, 20, 218];
    let signature = [166, 5, 102, 196, 4, 203, 205, 221, 56, 19, 228, 3, 222, 136, 61, 36, 112, 92, 79, 87, 206, 201, 77, 255, 128, 33, 243, 19, 6, 203, 117, 68, 64, 145, 153, 152, 123, 48, 10, 242, 213, 114, 82, 234, 207, 147, 47, 163, 107, 163, 86, 100, 139, 143, 24, 187, 239, 255, 38, 96, 57, 176, 217, 97];
    let pub_key_x = [65, 34, 212, 75, 36, 198, 55, 190, 216, 124, 123, 16, 155, 212, 157, 97, 134, 53, 129, 94, 77, 244, 77, 51, 6, 129, 50, 68, 74, 235, 37, 210];
    let pub_key_y = [211, 232, 46, 182, 4, 74, 247, 123, 164, 157, 138, 102, 69, 90, 221, 123, 163, 149, 197, 48, 99, 43, 123, 165, 161, 23, 43, 120, 28, 250, 107, 209];
    ecdsa_recover(message_hash, pub_key_x, pub_key_y, signature, [], [], 0xc7f222aadac8eef0039f5a8f01b9188e7a715a81);
}

fn verify_hashed_stamp(message_hash: pub Field, message_and_key_hash: Field, private_key: ) {
    
}

#[test]
fn test_verify_stamp() {
    let message_bytes = [
     71, 111, 111, 103, 108, 101,  58, 118,  48,  46,  48,  46,
     48,  58,  71, 113, 109,  75,  56,  67, 108, 109,  67,  70,
     54,  69,  57,  68,  97,  81,  89, 101,  51, 101, 105,  51,
     75,  71, 108, 119, 121,  74,  79,  87,  68,  80,  78, 116,
    104,  76,  88,  52,  78,  82, 102, 116,  81,  61,  58, 115,
    101,  99, 114, 101, 116
  ];

  let message_and_key_bytes = [71,111,111,103,108,101,58,118,48,46,48,46,48,58,71,113,109,75,56,67,108,109,67,70,54,69,57,68,97,81,89,101,51,101,105,51,75,71,108,119,121,74,79,87,68,80,78,116,104,76,88,52,78,82,102,116,81,61,58,115,101,99,114,101,116,48,120,97,99,48,57,55,52,98,101,99,51,57,97,49,55,101,51,54,98,97,52,97,54,98,52,100,50,51,56,102,102,57,52,52,98,97,99,98,52,55,56,99,98,101,100,53,101,102,99,97,101,55,56,52,100,55,98,102,52,102,50,102,102,56,48];

  let message_hash = std::hash::pedersen_hash(messageBytes);

  let message_and_key_hash = std::hash::pedersen_hash(message_and_key_bytes);



//   let message


  verify_hashed_stamp(message_hash, message_and_key_hash, private_key);
}

