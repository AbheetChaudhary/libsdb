use std::time;

fn main() {
    let secs = 10;
    for i in 1..=secs {
        std::thread::sleep(time::Duration::from_secs(1));
        println!("{}...{}", std::process::id(), i);
    }
}
