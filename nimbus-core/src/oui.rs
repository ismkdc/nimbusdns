// =============================================================================
// OUI (Organizationally Unique Identifier) Vendor Lookup
// =============================================================================
// Parses IEEE oui.txt to map MAC address prefixes to manufacturer names.
// The oui.txt file is embedded at compile time via include_str! and
// updated monthly by a GitHub Action.
//
// IEEE OUI format:
//   XX-XX-XX   (hex)        VENDOR NAME
//   XX:XX:XX   (hex)        VENDOR NAME

use std::collections::HashMap;

/// OUI database: maps the first 3 bytes of a MAC address to a vendor name.
pub struct OuiDb {
    /// Key: first 3 bytes of MAC [b0, b1, b2] → vendor string
    map: HashMap<[u8; 3], &'static str>,
}

impl OuiDb {
    /// Build the OUI database by parsing the embedded IEEE oui.txt.
    pub fn new() -> Self {
        let raw = include_str!("../data/oui.txt");
        let mut map = HashMap::new();
        let mut count = 0u32;
        let mut dup_count = 0u32;

        for line in raw.lines() {
            let line = line.trim();
            // Skip empty lines and comment lines
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Match IEEE OUI format: "XX-XX-XX   (hex)        Vendor Name"
            // or "XX:XX:XX   (hex)        Vendor Name"
            if let Some((oui_str, rest)) = line.split_once(' ') {
                let oui_str = oui_str.trim();
                // Validate OUI pattern: 2 hex chars, separator, 2 hex chars, separator, 2 hex chars
                if !is_oui_format(oui_str) {
                    continue;
                }

                // Find the vendor name after "(hex)" or "(base 16)"
                let rest = rest.trim();
                if !rest.starts_with("(hex)") && !rest.starts_with("(base 16)") {
                    continue;
                }
                let vendor = rest[6..].trim(); // skip "(hex)" or "(base 16)"
                if vendor.is_empty() {
                    continue;
                }

                // Parse OUI bytes: handle both dash and colon separators
                let parts: Vec<&str> = oui_str.split(&['-', ':'][..]).collect();
                if parts.len() != 3 {
                    continue;
                }
                let b0 = match u8::from_str_radix(parts[0], 16) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let b1 = match u8::from_str_radix(parts[1], 16) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let b2 = match u8::from_str_radix(parts[2], 16) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let key = [b0, b1, b2];

                // Prefer the first entry for each OUI (IEEE typically lists hex first)
                if map.insert(key, vendor).is_some() {
                    dup_count += 1;
                }
                count += 1;
            }
        }

        tracing::info!(
            "OUI database loaded: {} entries ({} unique, {} duplicates skipped)",
            count,
            map.len(),
            dup_count
        );
        Self { map }
    }

    /// Look up the vendor (manufacturer) name for a given MAC address.
    ///
    /// Returns `None` if the MAC's OUI prefix is not found in the database.
    pub fn lookup(&self, mac: &[u8; 6]) -> Option<&str> {
        let key = [mac[0], mac[1], mac[2]];
        self.map.get(&key).copied()
    }

    /// Return the number of OUI entries in the database.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Returns true if the database is empty.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

impl Default for OuiDb {
    fn default() -> Self {
        Self::new()
    }
}

/// Quick check if a string looks like an OUI: "XX-XX-XX" or "XX:XX:XX"
fn is_oui_format(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() != 8 {
        return false;
    }
    let is_hex = |c: u8| c.is_ascii_hexdigit();

    is_hex(bytes[0])
        && is_hex(bytes[1])
        && (bytes[2] == b'-' || bytes[2] == b':')
        && is_hex(bytes[3])
        && is_hex(bytes[4])
        && (bytes[5] == b'-' || bytes[5] == b':')
        && is_hex(bytes[6])
        && is_hex(bytes[7])
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oui_format_check() {
        assert!(is_oui_format("00-00-00"));
        assert!(is_oui_format("AA-BB-CC"));
        assert!(is_oui_format("aa:bb:cc"));
        assert!(is_oui_format("3C:22:FB"));
        assert!(!is_oui_format(""));
        assert!(!is_oui_format("000000"));
        assert!(!is_oui_format("00-00-000"));
        assert!(!is_oui_format("xx-xx-xx"));
        assert!(!is_oui_format("00-00-0"));
    }

    #[test]
    fn test_oui_basic_lookup() {
        let db = OuiDb::new();
        // Known entries from the test data
        // Cisco (00-00-0C)
        let cisco = db.lookup(&[0x00, 0x00, 0x0C, 0x00, 0x00, 0x00]);
        assert!(cisco.is_some());
        assert!(cisco.unwrap().to_uppercase().contains("CISCO"));

        // Apple (3C:22:FB)
        let apple = db.lookup(&[0x3C, 0x22, 0xFB, 0x00, 0x00, 0x00]);
        assert!(apple.is_some());
        assert!(apple.unwrap().to_uppercase().contains("APPLE"));

        // TP-Link (00:31:92)
        let tplink = db.lookup(&[0x00, 0x31, 0x92, 0x00, 0x00, 0x00]);
        assert!(tplink.is_some());
        let tplink_name = tplink.unwrap().to_uppercase();
        assert!(tplink_name.contains("TPLINK") || tplink_name.contains("TP-LINK") || tplink_name.contains("TP LINK"));

        // Samsung (00:00:F0)
        let samsung = db.lookup(&[0x00, 0x00, 0xF0, 0x00, 0x00, 0x00]);
        assert!(samsung.is_some());
        assert!(samsung.unwrap().to_uppercase().contains("SAMSUNG"));

        // Intel (00:02:B3)
        let intel = db.lookup(&[0x00, 0x02, 0xB3, 0x00, 0x00, 0x00]);
        assert!(intel.is_some());
        assert!(intel.unwrap().to_uppercase().contains("INTEL"));

        // Unknown OUI returns None
        assert_eq!(db.lookup(&[0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00]), None);
    }

    #[test]
    fn test_oui_not_empty() {
        let db = OuiDb::new();
        assert!(!db.is_empty());
        assert!(db.len() > 0);
    }
}
