use super::types::DnskeyRecord;
use base64::{engine::general_purpose::STANDARD, Engine};

#[derive(Debug, Clone)]
pub struct TrustAnchor {
    
    pub domain: String,

    pub dnskey: DnskeyRecord,

    pub description: String,
}

impl TrustAnchor {
    
    pub fn new(domain: String, dnskey: DnskeyRecord, description: String) -> Self {
        Self {
            domain,
            dnskey,
            description,
        }
    }

    pub fn matches(&self, dnskey: &DnskeyRecord) -> bool {
        
        if self.dnskey.calculate_key_tag() != dnskey.calculate_key_tag() {
            return false;
        }

        if self.dnskey.algorithm != dnskey.algorithm {
            return false;
        }

        self.dnskey.public_key == dnskey.public_key
    }
}

#[derive(Debug, Clone)]
pub struct TrustAnchorStore {
    anchors: Vec<TrustAnchor>,
}

impl TrustAnchorStore {
    
    pub fn new() -> Self {
        Self {
            anchors: Self::default_root_anchors(),
        }
    }

    pub fn empty() -> Self {
        Self {
            anchors: Vec::new(),
        }
    }

    pub fn default_root_anchors() -> Vec<TrustAnchor> {
        vec![
            
            TrustAnchor::new(
                ".".to_string(),
                Self::root_ksk_20326(),
                "Root KSK-2017 (20326)".to_string(),
            ),
        ]
    }

    fn root_ksk_20326() -> DnskeyRecord {
        
        let public_key_b64 = concat!(
            "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3",
            "+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kv",
            "ArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF",
            "0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+e",
            "oZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfd",
            "RUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwN",
            "R1AkUTV74bU="
        );

        let public_key = STANDARD
            .decode(public_key_b64)
            .expect("Failed to decode root KSK public key");

        DnskeyRecord {
            flags: 257, 
            protocol: 3,
            algorithm: 8, 
            public_key,
        }
    }

    pub fn add_anchor(&mut self, anchor: TrustAnchor) {
        self.anchors.push(anchor);
    }

    pub fn is_trusted(&self, dnskey: &DnskeyRecord, domain: &str) -> bool {
        
        let normalized_domain = if domain.ends_with('.') {
            domain.to_string()
        } else if domain.is_empty() || domain == "." {
            ".".to_string()
        } else {
            format!("{}.", domain)
        };

        self.anchors
            .iter()
            .any(|anchor| anchor.domain == normalized_domain && anchor.matches(dnskey))
    }

    pub fn get_anchor(&self, domain: &str) -> Option<&TrustAnchor> {
        let normalized_domain = if domain.ends_with('.') {
            domain.to_string()
        } else {
            format!("{}.", domain)
        };

        self.anchors
            .iter()
            .find(|anchor| anchor.domain == normalized_domain)
    }

    pub fn get_all_anchors(&self) -> &[TrustAnchor] {
        &self.anchors
    }

    #[allow(dead_code)]
    pub fn load_from_xml(&mut self, _xml_content: &str) -> Result<(), String> {
        
        Err("XML trust anchor loading not yet implemented".to_string())
    }
}

impl Default for TrustAnchorStore {
    fn default() -> Self {
        Self::new()
    }
}
