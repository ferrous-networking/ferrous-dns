use ferrous_dns_application::ports::ServiceCatalogPort;
use ferrous_dns_domain::ServiceDefinition;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use super::ServiceCatalog;

/// Composite catalog that merges built-in (static) and custom (dynamic) services.
pub struct CompositeServiceCatalog {
    static_catalog: ServiceCatalog,
    custom_services: RwLock<Vec<ServiceDefinition>>,
    custom_by_id: RwLock<HashMap<Arc<str>, usize>>,
}

impl CompositeServiceCatalog {
    pub fn new(static_catalog: ServiceCatalog) -> Self {
        Self {
            static_catalog,
            custom_services: RwLock::new(Vec::new()),
            custom_by_id: RwLock::new(HashMap::new()),
        }
    }
}

impl ServiceCatalogPort for CompositeServiceCatalog {
    fn get_by_id(&self, id: &str) -> Option<ServiceDefinition> {
        if let Some(def) = self.static_catalog.get_by_id(id) {
            return Some(def.clone());
        }

        let by_id = self.custom_by_id.read().unwrap_or_else(|e| e.into_inner());
        if let Some(&idx) = by_id.get(id) {
            let customs = self
                .custom_services
                .read()
                .unwrap_or_else(|e| e.into_inner());
            return customs.get(idx).cloned();
        }

        None
    }

    fn all(&self) -> Vec<ServiceDefinition> {
        let static_all = self.static_catalog.all();
        let customs = self
            .custom_services
            .read()
            .unwrap_or_else(|e| e.into_inner());

        let mut result = Vec::with_capacity(static_all.len() + customs.len());
        for def in static_all {
            result.push(def.clone());
        }
        result.extend(customs.iter().cloned());
        result
    }

    fn normalized_rules_for(&self, service_id: &str) -> Vec<String> {
        if let Some(svc) = self.get_by_id(service_id) {
            return svc
                .rules
                .iter()
                .filter_map(|r| ServiceCatalog::normalize_rule(r))
                .collect();
        }
        vec![]
    }

    fn reload_custom(&self, custom: Vec<ServiceDefinition>) {
        let mut by_id = HashMap::with_capacity(custom.len());
        for (idx, def) in custom.iter().enumerate() {
            by_id.insert(Arc::clone(&def.id), idx);
        }

        let mut lock = self
            .custom_services
            .write()
            .unwrap_or_else(|e| e.into_inner());
        *lock = custom;
        drop(lock);

        let mut id_lock = self.custom_by_id.write().unwrap_or_else(|e| e.into_inner());
        *id_lock = by_id;
    }
}
