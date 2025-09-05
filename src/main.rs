use std::io::BufRead as _;

use chumsky::Parser as _;

mod strace;

fn main() {
    let stdin = std::io::stdin().lock();
    for (n, line) in stdin.lines().enumerate() {
        let n = n + 1;
        let line = line.unwrap();
        println!("{n}: {line:?}");
        let strace = strace::line_parser().parse(&line).into_result().unwrap();
        println!("{strace:#?}");
    }
}
