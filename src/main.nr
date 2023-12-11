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

#[test]
fn test_main() {
    main([1, 1, 0, 0, 0], [1, 2, 3, 4, 5]);
    // Uncomment to make test fail
    // main(1, 1);
}
