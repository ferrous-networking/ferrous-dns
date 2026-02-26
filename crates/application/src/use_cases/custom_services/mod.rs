mod create_custom_service;
mod delete_custom_service;
mod get_custom_services;
mod update_custom_service;

pub use create_custom_service::CreateCustomServiceUseCase;
pub use delete_custom_service::DeleteCustomServiceUseCase;
pub use get_custom_services::GetCustomServicesUseCase;
pub use update_custom_service::UpdateCustomServiceUseCase;

use ferrous_dns_domain::{CustomService, ServiceDefinition};
use std::sync::Arc;

const GENERIC_GLOBE_SVG: &str = r#"<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"/><path d="M2 12h20"/></svg>"#;

pub fn custom_to_definition(cs: &CustomService) -> ServiceDefinition {
    let rules: Vec<Arc<str>> = cs
        .domains
        .iter()
        .map(|d| {
            let rule = format!("||{}^", d);
            Arc::from(rule.as_str())
        })
        .collect();

    ServiceDefinition {
        id: Arc::clone(&cs.service_id),
        name: Arc::clone(&cs.name),
        category_id: Arc::from("custom"),
        category_name: Arc::clone(&cs.category_name),
        icon_svg: Arc::from(GENERIC_GLOBE_SVG),
        rules,
        is_custom: true,
    }
}
