use polkitguard::Scanner;

fn main() {
    let scanner = Scanner::new();

    match scanner.scan_sync(None, "low") {
        Ok(result) => {
            println!("Scan complete: {} findings", result.stats.total);

            let risk = scanner.calculate_risk_score(&result.findings);
            println!("Risk Score: {:.1} ({})", risk.overall, risk.level);

            if !risk.recommendations.is_empty() {
                println!("\nRecommendations:");
                for rec in &risk.recommendations {
                    println!("  - {}", rec);
                }
            }
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}