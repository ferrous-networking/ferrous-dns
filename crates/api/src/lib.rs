pub mod dto;
pub mod errors;
pub mod handlers;
pub mod middleware;
pub mod openapi;
pub mod routes;
pub mod state;
pub mod utils;

pub use errors::ApiError;
pub use openapi::ApiDoc;
pub use routes::{create_api_router_with_openapi, create_api_routes};
pub use state::{
    AppState, AuthUseCases, BackupUseCases, BlockingUseCases, ClientUseCases, DnsUseCases,
    GroupUseCases, QueryUseCases, SafeSearchUseCases, ScheduleUseCases, ServiceUseCases,
};
