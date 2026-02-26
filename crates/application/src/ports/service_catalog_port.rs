use ferrous_dns_domain::ServiceDefinition;

pub trait ServiceCatalogPort: Send + Sync {
    fn get_by_id(&self, id: &str) -> Option<ServiceDefinition>;
    fn all(&self) -> Vec<ServiceDefinition>;
    fn normalized_rules_for(&self, service_id: &str) -> Vec<String>;
    fn reload_custom(&self, custom: Vec<ServiceDefinition>);
}
