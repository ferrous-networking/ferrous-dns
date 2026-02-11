//! DNS Resolver module with Decorator Pattern
//!
//! This module implements a flexible resolver architecture using the Decorator Pattern.
//! Each decorator adds a specific responsibility:
//!
//! - **Filters**: Query validation and transformation (outermost)
//! - **Cache**: Response caching with prefetch support
//! - **DNSSEC**: Response validation with DNSSEC
//! - **Core**: Actual DNS resolution (innermost)
//!
//! ## Example Usage
//!
//! ```no_run
//! use ferrous_dns_infrastructure::dns::resolver::ResolverBuilder;
//! use ferrous_dns_infrastructure::dns::resolver::QueryFilters;
//!
//! let resolver = ResolverBuilder::new(pool_manager)
//!     .with_cache(cache)
//!     .with_dnssec()
//!     .with_filters(QueryFilters::default())
//!     .build();
//! ```

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
