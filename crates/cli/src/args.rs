use clap::Parser;
use std::net::IpAddr;

#[derive(Parser)]
#[command(name = "ferrous-dns")]
#[command(version)]
#[command(about = "Ferrous DNS - High-performance DNS server with ad-blocking")]
pub struct Cli {
    #[arg(short = 'c', long, value_name = "FILE")]
    pub config: Option<String>,

    #[arg(short = 'd', long)]
    pub dns_port: Option<u16>,

    #[arg(short = 'w', long)]
    pub web_port: Option<u16>,

    #[arg(short = 'b', long, value_parser = ferrous_dns_domain::config::server::parse_bind_host)]
    pub bind: Option<IpAddr>,

    #[arg(long)]
    pub database: Option<String>,

    #[arg(long)]
    pub log_level: Option<String>,

    /// Rewrite the database file without its free space, then exit. Stop the server first.
    #[arg(long)]
    pub compact_database: bool,
}
