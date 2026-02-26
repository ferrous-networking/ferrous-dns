ALTER TABLE managed_domains ADD COLUMN service_id TEXT;
CREATE INDEX idx_managed_domains_service ON managed_domains(service_id);
