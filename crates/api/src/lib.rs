pub mod dto;
pub mod errors;
pub mod handlers;
pub mod middleware;
pub mod routes;
pub mod state;
pub mod utils;

pub use errors::ApiError;
pub use routes::create_api_routes;
pub use state::{
    AppState, AuthUseCases, BlockingUseCases, ClientUseCases, DnsUseCases, GroupUseCases,
    QueryUseCases, SafeSearchUseCases, ScheduleUseCases, ServiceUseCases,
};
