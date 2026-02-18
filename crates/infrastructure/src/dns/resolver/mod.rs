pub mod builder;
pub mod cache_layer;
pub mod config;
pub mod core;
pub mod dnssec_layer;
pub mod filtered_resolver;
pub mod filters;
pub mod legacy;

pub use builder::ResolverBuilder;
pub use cache_layer::CachedResolver;
pub use config::{QueryFiltersConfig, ResolverConfig};
pub use core::CoreResolver;
pub use dnssec_layer::DnssecResolver;
pub use filtered_resolver::FilteredResolver;
pub use filters::QueryFilters;
pub use legacy::HickoryDnsResolver;
