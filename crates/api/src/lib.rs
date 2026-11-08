pub mod dto;
pub mod errors;
pub mod handlers;
pub mod middleware;
pub mod openapi;
pub mod routes;
pub mod state;
pub mod utils;

pub use errors::ApiError;
pub use handlers::{metrics_routes, render_metrics, MetricsInputs};
pub use openapi::ApiDoc;
pub use routes::create_api_router_with_openapi;
pub use state::{
    AppState, AuthUseCases, BackupUseCases, BlockingUseCases, ClientUseCases, DnsUseCases,
    DohIdUseCases, GroupUseCases, QueryUseCases, SafeSearchUseCases, ScheduleUseCases,
    ServiceUseCases,
};
