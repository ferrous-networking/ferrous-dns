use ferrous_dns_domain::ServiceDefinition;
use std::sync::Arc;

use crate::ports::ServiceCatalogPort;

pub struct GetServiceCatalogUseCase {
    catalog: Arc<dyn ServiceCatalogPort>,
}

impl GetServiceCatalogUseCase {
    pub fn new(catalog: Arc<dyn ServiceCatalogPort>) -> Self {
        Self { catalog }
    }

    pub fn get_all(&self) -> Vec<ServiceDefinition> {
        self.catalog.all()
    }

    pub fn get_by_id(&self, id: &str) -> Option<ServiceDefinition> {
        self.catalog.get_by_id(id)
    }
}
