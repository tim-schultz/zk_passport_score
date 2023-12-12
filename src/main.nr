use dep::std;

fn main(x: [u32; 5], y: pub [u32; 5]) {
    // assert(x != y);
    let mut score = 0;
    for i in 0..5 {
        std::println(x[i]);
        std::println(y[i]);
        score += x[i] * y[i];
    }
    std::println("Score: ");
    std::println(score);
    let is_ok = (score > 10);
    std::println(is_ok);
    assert(is_ok == true);
}


fn verify_signature(message_hash : [u8;32], pub_key_x : [u8;32], pub_key_y : [u8;32], signature : [u8;64]) {
    // hash the message again (this happens when we generate a deterministic signature)
    // the reason we do this is to ensure persistent input message length (always 32 bytes)
    let message_hash_2 = std::hash::sha256(message_hash);

    let valid_signature = std::ecdsa_secp256k1::verify_signature(pub_key_x, pub_key_y, signature, message_hash_2);
    assert(valid_signature);
}

#[test]
fn test_main() {
    main([1, 1, 1, 1, 1], [1, 2, 3, 4, 5]);
    // Uncomment to make test fail
    // main(1, 1);
}

#[test]
fn test_verify_signature() {
    let message_hash = [245, 223, 58, 50, 74, 76, 120, 255, 154, 66, 228, 77, 1, 67, 64, 61, 149, 67, 119, 15, 48, 228, 152, 123, 172, 4, 232, 97, 108, 104, 20, 218];
    let signature = [166, 5, 102, 196, 4, 203, 205, 221, 56, 19, 228, 3, 222, 136, 61, 36, 112, 92, 79, 87, 206, 201, 77, 255, 128, 33, 243, 19, 6, 203, 117, 68, 64, 145, 153, 152, 123, 48, 10, 242, 213, 114, 82, 234, 207, 147, 47, 163, 107, 163, 86, 100, 139, 143, 24, 187, 239, 255, 38, 96, 57, 176, 217, 97];
    let pub_key_x = [65, 34, 212, 75, 36, 198, 55, 190, 216, 124, 123, 16, 155, 212, 157, 97, 134, 53, 129, 94, 77, 244, 77, 51, 6, 129, 50, 68, 74, 235, 37, 210];
    let pub_key_y = [211, 232, 46, 182, 4, 74, 247, 123, 164, 157, 138, 102, 69, 90, 221, 123, 163, 149, 197, 48, 99, 43, 123, 165, 161, 23, 43, 120, 28, 250, 107, 209];
    verify_signature(message_hash, pub_key_x, pub_key_y, signature);
}
