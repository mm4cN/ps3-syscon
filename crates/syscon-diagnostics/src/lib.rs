//! Conservative, source-carrying PS3 SYSCON error-code lookup.

use serde::{Deserialize, Serialize};
use std::fmt::{self, Write as _};

pub const SYSCON_WIKI_URL: &str = "https://www.psdevwiki.com/ps3/Syscon_Error_Codes";
pub const DISCLAIMER: &str = "Reference only. A code is not a definitive component diagnosis; correlate it with board revision, timing, symptoms, and measurements.";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecodedError {
    pub input: String,
    pub normalized_code: String,
    pub error_suffix: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp_raw: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub occurred_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp_warning: Option<String>,
    pub title: Option<String>,
    pub summary: Option<String>,
    pub source_url: Option<String>,
    pub known: bool,
    pub caution: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosticReport {
    pub entries: Vec<DecodedError>,
}

impl DiagnosticReport {
    pub fn new(entries: Vec<DecodedError>) -> Self {
        Self { entries }
    }

    pub fn to_text(&self) -> String {
        let mut output = String::new();
        for (index, entry) in self.entries.iter().enumerate() {
            let occurred_at = entry.occurred_at.as_deref().unwrap_or("N/A");
            let title = entry.title.as_deref().unwrap_or("unknown");
            let _ = writeln!(
                output,
                "{:02} {occurred_at} {} {title}",
                index + 1,
                entry.normalized_code
            );
        }
        output
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseCodeError(pub String);

impl fmt::Display for ParseCodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for ParseCodeError {}

struct KnownCode {
    suffix: &'static str,
    title: &'static str,
    summary: &'static str,
}

// Labels below are deliberately concise transcriptions of entries explicitly
// documented by the linked community wiki. Keep the source attached to output.
const KNOWN_CODES: &[KnownCode] = &[
    KnownCode {
        suffix: "1001",
        title: "Power CELL",
        summary: "CELL power-related system error; the source warns that context is required and this code alone does not prove a capacitor fault.",
    },
    KnownCode {
        suffix: "1002",
        title: "Power RSX",
        summary: "RSX power-related system error; treat this as a diagnostic direction, not a component verdict.",
    },
    KnownCode {
        suffix: "1A01",
        title: "BE fan",
        summary: "BE fan is not operational.",
    },
    KnownCode {
        suffix: "1A02",
        title: "RSX fan",
        summary: "RSX fan is not operational.",
    },
    KnownCode {
        suffix: "1AA0",
        title: "Front fan",
        summary: "Front fan is not operational.",
    },
    KnownCode {
        suffix: "1AA1",
        title: "Rear fan 1",
        summary: "Rear fan 1 is not operational.",
    },
    KnownCode {
        suffix: "1AA2",
        title: "Rear fan 2",
        summary: "Rear fan 2 is not operational.",
    },
    KnownCode {
        suffix: "1B01",
        title: "CELL initialization",
        summary: "CPU thermal-sense error during CELL initialization.",
    },
    KnownCode {
        suffix: "1B02",
        title: "RSX initialization",
        summary: "RSX thermal-sense error during RSX initialization.",
    },
    KnownCode {
        suffix: "2001",
        title: "CELL fatal error",
        summary: "Fatal error associated with CELL.",
    },
    KnownCode {
        suffix: "2002",
        title: "RSX fatal error",
        summary: "Fatal error associated with RSX.",
    },
    KnownCode {
        suffix: "2003",
        title: "South Bridge fatal error",
        summary: "Fatal error associated with the South Bridge.",
    },
    KnownCode {
        suffix: "2010",
        title: "Clock subsystems",
        summary: "Clock generator error.",
    },
    KnownCode {
        suffix: "3000",
        title: "Pre-boot check",
        summary: "Pre-boot check error.",
    },
    KnownCode {
        suffix: "3001",
        title: "12 V power failure",
        summary: "Failure involving the 12 V supply or its detection path.",
    },
    KnownCode {
        suffix: "3002",
        title: "Power failure",
        summary: "Power failure.",
    },
    KnownCode {
        suffix: "3003",
        title: "CELL core power failure",
        summary: "Failure on the CELL core power rail; multiple causes are possible.",
    },
];

pub fn decode(input: &str) -> Result<DecodedError, ParseCodeError> {
    let normalized = normalize_code(input)?;
    let suffix = normalized[normalized.len() - 4..].to_string();
    let known = KNOWN_CODES.iter().find(|entry| entry.suffix == suffix);
    Ok(match known {
        Some(entry) => DecodedError {
            input: input.into(),
            normalized_code: normalized,
            error_suffix: suffix,
            timestamp_raw: None,
            occurred_at: None,
            timestamp_warning: None,
            title: Some(entry.title.into()),
            summary: Some(entry.summary.into()),
            source_url: Some(SYSCON_WIKI_URL.into()),
            known: true,
            caution: DISCLAIMER.into(),
        },
        None => DecodedError {
            input: input.into(),
            normalized_code: normalized,
            error_suffix: suffix,
            timestamp_raw: None,
            occurred_at: None,
            timestamp_warning: None,
            title: None,
            summary: None,
            source_url: None,
            known: false,
            caution: "Unknown code: no interpretation is provided.".into(),
        },
    })
}

fn normalize_code(input: &str) -> Result<String, ParseCodeError> {
    let trimmed = input.trim();
    let without_prefix = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    let compact: String = without_prefix
        .chars()
        .filter(|character| !character.is_whitespace() && *character != '_' && *character != '-')
        .collect();
    if compact.len() != 4 && compact.len() != 8 {
        return Err(ParseCodeError(
            "expected exactly 4 or 8 hexadecimal digits (for example A0801001 or 1001)".into(),
        ));
    }
    if !compact
        .chars()
        .all(|character| character.is_ascii_hexdigit())
    {
        return Err(ParseCodeError(
            "code contains a non-hexadecimal character".into(),
        ));
    }
    let normalized = compact.to_ascii_uppercase();
    if normalized.len() == 8 && !normalized.starts_with('A') {
        return Err(ParseCodeError(
            "an 8-digit SYSCON log code must start with A".into(),
        ));
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_full_known_code_by_documented_suffix() {
        let result = decode("0xa0801001").unwrap();
        assert!(result.known);
        assert_eq!(result.error_suffix, "1001");
        assert_eq!(result.source_url.as_deref(), Some(SYSCON_WIKI_URL));
    }

    #[test]
    fn accepts_separators_and_short_form() {
        let result = decode("1a-01").unwrap();
        assert_eq!(result.normalized_code, "1A01");
        assert_eq!(result.title.as_deref(), Some("BE fan"));
    }

    #[test]
    fn unknown_code_gets_no_fabricated_interpretation() {
        let result = decode("A080DEAD").unwrap();
        assert!(!result.known);
        assert!(result.title.is_none());
        assert!(result.summary.is_none());
        assert!(result.source_url.is_none());
    }

    #[test]
    fn rejects_invalid_input() {
        assert!(decode("not-a-code").is_err());
        assert!(decode("123").is_err());
        assert!(decode("001001").is_err());
        assert!(decode("B0801001").is_err());
    }

    #[test]
    fn text_export_uses_one_readable_record_per_line() {
        let mut known = decode("A0801001").unwrap();
        known.occurred_at = Some("2025-02-17 04:23:52".into());
        let unknown = decode("A040DEAD").unwrap();
        let report = DiagnosticReport::new(vec![known, unknown]);
        assert_eq!(
            report.to_text(),
            "01 2025-02-17 04:23:52 A0801001 Power CELL\n\
             02 N/A A040DEAD unknown\n"
        );
    }
}
