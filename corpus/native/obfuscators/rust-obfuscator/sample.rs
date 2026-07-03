fn classify(n: i32) -> i32 {
    if n > 10 {
        n * 2
    } else {
        n + 1
    }
}

fn main() {
    let secret = "the-hidden-flag-value";
    println!("classify={},{}", classify(7), classify(20));
    println!("secret={}", secret);
}
