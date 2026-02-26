mod composite;

pub use composite::CompositeServiceCatalog;

use ferrous_dns_domain::ServiceDefinition;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Deserialize)]
struct RawService {
    id: String,
    name: String,
    category_id: String,
    category_name: String,
    icon_svg: String,
    rules: Vec<String>,
}

/// Embedded service catalog loaded from catalog.json at compile time.
pub struct ServiceCatalog {
    services: Vec<ServiceDefinition>,
    by_id: HashMap<Arc<str>, usize>,
}

impl ServiceCatalog {
    pub fn load() -> Self {
        let json = include_str!("catalog.json");
        let raw: Vec<RawService> =
            serde_json::from_str(json).expect("catalog.json must be valid JSON");

        let mut services = Vec::with_capacity(raw.len());
        let mut by_id = HashMap::with_capacity(raw.len());

        for (idx, r) in raw.into_iter().enumerate() {
            let id: Arc<str> = Arc::from(r.id.as_str());
            by_id.insert(Arc::clone(&id), idx);
            services.push(ServiceDefinition {
                id,
                name: Arc::from(r.name.as_str()),
                category_id: Arc::from(r.category_id.as_str()),
                category_name: Arc::from(r.category_name.as_str()),
                icon_svg: Arc::from(r.icon_svg.as_str()),
                rules: r.rules.iter().map(|s| Arc::from(s.as_str())).collect(),
                is_custom: false,
            });
        }

        Self { services, by_id }
    }

    pub fn get_by_id(&self, id: &str) -> Option<&ServiceDefinition> {
        self.by_id.get(id).map(|&idx| &self.services[idx])
    }

    pub fn all(&self) -> &[ServiceDefinition] {
        &self.services
    }

    pub fn categories(&self) -> Vec<(Arc<str>, Arc<str>)> {
        let mut seen = HashMap::new();
        for svc in &self.services {
            seen.entry(Arc::clone(&svc.category_id))
                .or_insert_with(|| Arc::clone(&svc.category_name));
        }
        let mut cats: Vec<_> = seen.into_iter().collect();
        cats.sort_by(|a, b| a.1.cmp(&b.1));
        cats
    }

    /// Converts an AdGuard rule (`||domain^`) to a managed domain pattern.
    pub fn normalize_rule(rule: &str) -> Option<String> {
        let trimmed = rule.trim();
        if trimmed.is_empty() || trimmed.starts_with('!') || trimmed.starts_with('#') {
            return None;
        }

        let stripped = trimmed.strip_prefix("||")?;
        let domain = stripped.strip_suffix('^').unwrap_or(stripped);

        if domain.is_empty() {
            return None;
        }

        if domain.starts_with("*.") {
            return Some(domain.to_string());
        }

        if let Some(rest) = domain.strip_prefix('*') {
            return Some(format!("*.{}", rest));
        }

        Some(domain.to_string())
    }
}
