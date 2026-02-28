use isa_classifier::{heuristics, ClassifierOptions};
use std::fs;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 { return; }
    let data = fs::read(&args[1]).unwrap();
    let opts = ClassifierOptions::thorough();
    let mut scores = heuristics::score_all_architectures(&data, &opts);
    scores.sort_by(|a, b| b.raw_score.cmp(&a.raw_score));
    
    for (i, s) in scores.iter().take(10).enumerate() {
        println!("{}. {:?} - score: {}", i+1, s.isa, s.raw_score);
    }
}
