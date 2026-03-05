use clap::Parser;

#[derive(Parser)]
#[command(name = "ferrous-dns")]
#[command(version = "0.1.0")]
#[command(about = "Ferrous DNS - High-performance DNS server with ad-blocking")]
pub struct Cli {
    #[arg(short = 'c', long, value_name = "FILE")]
    pub config: Option<String>,

    #[arg(short = 'd', long)]
    pub dns_port: Option<u16>,

    #[arg(short = 'w', long)]
    pub web_port: Option<u16>,

    #[arg(short = 'b', long)]
    pub bind: Option<String>,

    #[arg(long)]
    pub database: Option<String>,

    #[arg(long)]
    pub log_level: Option<String>,
}
