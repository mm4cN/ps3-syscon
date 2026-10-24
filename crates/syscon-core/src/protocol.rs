//! Read-only PS3 SYSCON protocol operations.
//!
//! The framing and authentication flow mirror the public reference tooling at
//! <https://github.com/db260179/ps3syscon>. This module intentionally exposes
//! authentication and error-log reads only; destructive/write commands are not
//! part of the typed API.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::io::{Read, Write};
use std::time::{Duration, Instant};

const SC2TB_KEY: [u8; 16] = hex_16("71f03f184c01c5ebc3f6a22a42ba9525");
const TB2SC_KEY: [u8; 16] = hex_16("907e730f4d4e0a0b7b75f030eb1d9d36");
const AUTH_VALUE: [u8; 16] = hex_16("3350BD7820345C29056A223BA220B323");
const AUTH1_HEADER: [u8; 16] = hex_16("10100000FFFFFFFF0000000000000000");
const AUTH2_HEADER: [u8; 16] = hex_16("10010000000000000000000000000000");
const ZERO_BLOCK: [u8; 16] = [0; 16];
const AUTH1_ZERO_PAYLOAD: &str = "10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SysconProfile {
    /// Mullion/CXR external command mode.
    Cxr,
    /// Mullion/CXR internal service shell (DIAG asserted where applicable).
    Cxrf,
    /// Sherwood plaintext service protocol.
    Sw,
}

impl SysconProfile {
    pub const ALL: [Self; 3] = [Self::Cxr, Self::Cxrf, Self::Sw];

    pub const fn baud_rate(self) -> u32 {
        match self {
            Self::Cxr | Self::Sw => 57_600,
            Self::Cxrf => 115_200,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Cxr => "CXR — Mullion external (57,600)",
            Self::Cxrf => "CXRF — Mullion internal (115,200)",
            Self::Sw => "SW — Sherwood (57,600)",
        }
    }

    pub const fn menu_label(self) -> &'static str {
        match self {
            Self::Cxr => "CXR — COK / SEM / DIA (recommended first)",
            Self::Cxrf => "CXRF — COK / SEM / DIA + DIAG (advanced)",
            Self::Sw => "SW — VER / DYN / SUR / JTP / JSD / KTE / Super Slim",
        }
    }

    pub const fn suggested_boards(self) -> &'static str {
        match self {
            Self::Cxr | Self::Cxrf => "COK-001/002, SEM-001, DIA-001/002",
            Self::Sw => {
                "VER-001, DYN-001, SUR-001, JTP-001, JSD-001, KTE-001 and Super Slim boards"
            }
        }
    }

    pub const fn short_name(self) -> &'static str {
        match self {
            Self::Cxr => "CXR",
            Self::Cxrf => "CXRF",
            Self::Sw => "SW",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolTrace {
    pub direction: TraceDirection,
    pub text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceDirection {
    Tx,
    Rx,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ErrorLogRecord {
    pub slot: Option<u8>,
    pub code: String,
    pub timestamp: Option<ErrorLogTimestamp>,
    pub raw: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ErrorLogTimestamp {
    pub raw: u32,
    /// Converted SYSCON clock value. `None` means the stored value was
    /// `FFFFFFFF`, which indicates that no valid timestamp was available.
    pub formatted: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolError(pub String);

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for ProtocolError {}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CommandResponse {
    status: u32,
    data: Vec<String>,
    raw: String,
}

pub fn authenticate(
    io: &mut (impl Read + Write + ?Sized),
    profile: SysconProfile,
    trace: &mut dyn FnMut(ProtocolTrace),
) -> Result<(), ProtocolError> {
    let challenge = match profile {
        SysconProfile::Cxr | SysconProfile::Sw => {
            let command = format!("AUTH1 {AUTH1_ZERO_PAYLOAD}");
            let response = transact(io, profile, &command, trace)?;
            if response.status != 0 {
                return Err(ProtocolError(format!(
                    "AUTH1 returned status {:08X}",
                    response.status
                )));
            }
            find_hex_blob(&response.data.join(" "), 128)
                .or_else(|| find_hex_blob(&response.raw, 128))
                .ok_or_else(|| {
                    ProtocolError("AUTH1 response did not contain 128 hex digits".into())
                })?
        }
        SysconProfile::Cxrf => {
            let open = transact(io, profile, "scopen", trace)?;
            if !open.raw.contains("SC_READY") {
                return Err(ProtocolError(
                    "scopen response did not contain SC_READY".into(),
                ));
            }
            let response = transact(io, profile, AUTH1_ZERO_PAYLOAD, trace)?;
            find_hex_blob(&response.raw, 128).ok_or_else(|| {
                ProtocolError("AUTH1 response did not contain 128 hex digits".into())
            })?
        }
    };

    let challenge = decode_hex(&challenge)?;
    if challenge.len() != 64 || challenge[..16] != AUTH1_HEADER {
        return Err(ProtocolError("AUTH1 response header is invalid".into()));
    }

    let decrypted = aes_cbc_decrypt(&SC2TB_KEY, &challenge[16..64])?;
    if decrypted.len() != 48
        || decrypted[8..16] != ZERO_BLOCK[..8]
        || decrypted[16..32] != AUTH_VALUE
        || decrypted[32..48] != ZERO_BLOCK
    {
        return Err(ProtocolError("AUTH1 response body is invalid".into()));
    }

    let mut proof = Vec::with_capacity(48);
    proof.extend_from_slice(&decrypted[8..16]);
    proof.extend_from_slice(&decrypted[0..8]);
    proof.extend_from_slice(&ZERO_BLOCK);
    proof.extend_from_slice(&ZERO_BLOCK);
    let encrypted = aes_cbc_encrypt(&TB2SC_KEY, &proof)?;

    let mut auth2 = Vec::with_capacity(64);
    auth2.extend_from_slice(&AUTH2_HEADER);
    auth2.extend_from_slice(&encrypted);
    let auth2_hex = encode_hex(&auth2);

    let response = match profile {
        SysconProfile::Cxr | SysconProfile::Sw => {
            transact(io, profile, &format!("AUTH2 {auth2_hex}"), trace)?
        }
        SysconProfile::Cxrf => transact(io, profile, &auth2_hex, trace)?,
    };

    match profile {
        SysconProfile::Cxr | SysconProfile::Sw if response.status == 0 => Ok(()),
        SysconProfile::Cxrf if response.raw.contains("SC_SUCCESS") => Ok(()),
        _ => Err(ProtocolError(format!(
            "AUTH2 was rejected (status {:08X})",
            response.status
        ))),
    }
}

pub fn read_error_history(
    io: &mut (impl Read + Write + ?Sized),
    profile: SysconProfile,
    trace: &mut dyn FnMut(ProtocolTrace),
) -> Result<Vec<ErrorLogRecord>, ProtocolError> {
    match profile {
        SysconProfile::Cxr => {
            let mut records = Vec::new();
            for slot in 0_u8..32 {
                let response = transact(io, profile, &format!("ERRLOG GET {slot:02X}"), trace)?;
                if response.status != 0 {
                    return Err(ProtocolError(format!(
                        "ERRLOG slot {slot:02X} returned status {:08X}",
                        response.status
                    )));
                }
                let raw = if response.data.is_empty() {
                    response.raw
                } else {
                    response.data.join(" ")
                };
                if let Some(code) = find_error_code(&raw) {
                    let timestamp = find_timestamp(&raw, &code);
                    records.push(ErrorLogRecord {
                        slot: Some(slot),
                        code,
                        timestamp,
                        raw,
                    });
                }
            }
            Ok(records)
        }
        SysconProfile::Cxrf | SysconProfile::Sw => {
            let response = transact(io, profile, "errlog", trace)?;
            if response.status != 0 {
                return Err(ProtocolError(format!(
                    "errlog returned status {:08X}",
                    response.status
                )));
            }
            Ok(extract_error_records(&response.raw))
        }
    }
}

fn transact(
    io: &mut (impl Read + Write + ?Sized),
    profile: SysconProfile,
    command: &str,
    trace: &mut dyn FnMut(ProtocolTrace),
) -> Result<CommandResponse, ProtocolError> {
    if profile == SysconProfile::Sw && command.len() >= 0x40 && !command.starts_with("SETCMDLONG") {
        let setup = transact(io, profile, "SETCMDLONG FF FF", trace)?;
        if setup.status != 0 {
            return Err(ProtocolError(format!(
                "SETCMDLONG returned status {:08X}",
                setup.status
            )));
        }
    }

    let wire = frame_command(profile, command);
    trace(ProtocolTrace {
        direction: TraceDirection::Tx,
        text: escaped_wire(&wire),
    });
    io.write_all(&wire)
        .and_then(|()| io.flush())
        .map_err(|error| ProtocolError(format!("serial write failed: {error}")))?;

    let raw = read_until_idle(io, Duration::from_millis(1_500), Duration::from_millis(120))?;
    let raw = String::from_utf8_lossy(&raw).into_owned();
    trace(ProtocolTrace {
        direction: TraceDirection::Rx,
        text: escaped_text(&raw),
    });
    if raw.trim().is_empty() {
        return Err(ProtocolError(
            "timed out waiting for a SYSCON response".into(),
        ));
    }

    parse_response(profile, &raw)
}

fn frame_command(profile: SysconProfile, command: &str) -> Vec<u8> {
    let checksum = checksum(command.as_bytes());
    match profile {
        SysconProfile::Cxr => format!("C:{checksum:02X}:{command}\r\n").into_bytes(),
        SysconProfile::Sw => format!("{command}:{checksum:02X}\r\n").into_bytes(),
        SysconProfile::Cxrf => format!("{command}\r\n").into_bytes(),
    }
}

fn parse_response(profile: SysconProfile, raw: &str) -> Result<CommandResponse, ProtocolError> {
    match profile {
        SysconProfile::Cxr => parse_cxr_response(raw),
        SysconProfile::Sw => parse_sw_response(raw),
        SysconProfile::Cxrf => Ok(CommandResponse {
            status: 0,
            data: vec![raw.trim().into()],
            raw: raw.into(),
        }),
    }
}

fn parse_cxr_response(raw: &str) -> Result<CommandResponse, ProtocolError> {
    let line = raw.trim();
    let mut fields = line.splitn(3, ':');
    let magic = fields.next().unwrap_or_default();
    let received_checksum = fields.next().unwrap_or_default();
    let body = fields.next().unwrap_or_default();
    if !matches!(magic, "R" | "E") || body.is_empty() {
        return Err(ProtocolError("invalid CXR response framing".into()));
    }
    verify_checksum(body, received_checksum)?;
    let words: Vec<_> = body.split_whitespace().collect();
    if words.len() < 2 {
        return Err(ProtocolError(
            "CXR response is missing a status word".into(),
        ));
    }
    let status = u32::from_str_radix(words[1], 16)
        .map_err(|_| ProtocolError("CXR status is not hexadecimal".into()))?;
    Ok(CommandResponse {
        status,
        data: words.iter().skip(2).map(|word| (*word).into()).collect(),
        raw: raw.into(),
    })
}

fn parse_sw_response(raw: &str) -> Result<CommandResponse, ProtocolError> {
    let mut payloads = Vec::new();
    for line in raw.lines().map(str::trim).filter(|line| !line.is_empty()) {
        let (payload, received_checksum) = line
            .rsplit_once(':')
            .ok_or_else(|| ProtocolError("invalid SW response framing".into()))?;
        verify_checksum(payload, received_checksum)?;
        payloads.push(payload.to_string());
    }
    let last = payloads
        .last()
        .ok_or_else(|| ProtocolError("empty SW response".into()))?;
    let words: Vec<_> = last.split_whitespace().collect();
    let has_status = words.get(1).is_some_and(|word| {
        word.len() == 8 && word.chars().all(|character| character.is_ascii_hexdigit())
    });
    let (status, data) = if has_status {
        let status = u32::from_str_radix(words[1], 16)
            .map_err(|_| ProtocolError("SW status is not hexadecimal".into()))?;
        if payloads.len() == 1 {
            (
                status,
                words.iter().skip(2).map(|word| (*word).into()).collect(),
            )
        } else {
            (status, payloads[..payloads.len() - 1].to_vec())
        }
    } else {
        (0, payloads.clone())
    };
    Ok(CommandResponse {
        status,
        data,
        raw: raw.into(),
    })
}

fn read_until_idle(
    io: &mut (impl Read + ?Sized),
    overall_timeout: Duration,
    idle_timeout: Duration,
) -> Result<Vec<u8>, ProtocolError> {
    let started = Instant::now();
    let mut last_data = started;
    let mut result = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        match io.read(&mut buffer) {
            Ok(count) if count > 0 => {
                result.extend_from_slice(&buffer[..count]);
                last_data = Instant::now();
            }
            Ok(_) => {
                if !result.is_empty() {
                    break;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut => {}
            Err(error) => {
                return Err(ProtocolError(format!("serial read failed: {error}")));
            }
        }
        if !result.is_empty() && last_data.elapsed() >= idle_timeout {
            break;
        }
        if started.elapsed() >= overall_timeout {
            break;
        }
    }
    Ok(result)
}

fn verify_checksum(payload: &str, received: &str) -> Result<(), ProtocolError> {
    let expected = format!("{:02X}", checksum(payload.as_bytes()));
    if received.trim().eq_ignore_ascii_case(&expected) {
        Ok(())
    } else {
        Err(ProtocolError(format!(
            "checksum mismatch: expected {expected}, got {}",
            received.trim()
        )))
    }
}

fn checksum(bytes: &[u8]) -> u8 {
    bytes.iter().fold(0_u8, |sum, byte| sum.wrapping_add(*byte))
}

fn find_hex_blob(text: &str, length: usize) -> Option<String> {
    let mut current = String::new();
    for character in text.chars() {
        if character.is_ascii_hexdigit() {
            current.push(character);
            if current.len() == length {
                return Some(current.to_ascii_uppercase());
            }
        } else {
            current.clear();
        }
    }
    None
}

fn find_error_code(text: &str) -> Option<String> {
    text.split(|character: char| !character.is_ascii_hexdigit())
        .find(|token| {
            token.len() == 8
                && token.starts_with(['A', 'a'])
                && token.chars().all(|character| character.is_ascii_hexdigit())
        })
        .map(str::to_ascii_uppercase)
}

fn extract_error_records(raw: &str) -> Vec<ErrorLogRecord> {
    raw.lines()
        .filter_map(|line| {
            find_error_code(line).map(|code| {
                let timestamp = find_timestamp(line, &code);
                ErrorLogRecord {
                    slot: parse_slot(line),
                    code,
                    timestamp,
                    raw: line.trim().into(),
                }
            })
        })
        .collect()
}

fn find_timestamp(text: &str, code: &str) -> Option<ErrorLogTimestamp> {
    let mut found_code = false;
    for token in text.split(|character: char| !character.is_ascii_hexdigit()) {
        if !found_code {
            found_code = token.eq_ignore_ascii_case(code);
            continue;
        }
        if token.len() == 8 && token.chars().all(|character| character.is_ascii_hexdigit()) {
            let raw = u32::from_str_radix(token, 16).ok()?;
            return Some(ErrorLogTimestamp {
                raw,
                formatted: (raw != u32::MAX).then(|| format_syscon_timestamp(raw)),
            });
        }
    }
    None
}

fn format_syscon_timestamp(seconds: u32) -> String {
    // The human-readable values produced by the reference tooling use
    // 2000-01-01 00:00:00 as the epoch for this field.
    const UNIX_OFFSET: i64 = 946_684_800;
    let unix_seconds = i64::from(seconds) + UNIX_OFFSET;
    let days = unix_seconds.div_euclid(86_400);
    let seconds_of_day = unix_seconds.rem_euclid(86_400);
    let (year, month, day) = civil_date_from_unix_days(days);
    let hour = seconds_of_day / 3_600;
    let minute = seconds_of_day % 3_600 / 60;
    let second = seconds_of_day % 60;
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}")
}

fn civil_date_from_unix_days(days: i64) -> (i64, i64, i64) {
    // Gregorian calendar conversion adapted from Howard Hinnant's
    // civil_from_days algorithm.
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    (year, month, day)
}

fn parse_slot(line: &str) -> Option<u8> {
    let after_err = line.trim().strip_prefix("ERR ")?;
    let slot = after_err.split(':').next()?.trim();
    u8::from_str_radix(slot, 16).ok()
}

fn aes_cbc_decrypt(key: &[u8; 16], input: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    if !input.len().is_multiple_of(16) {
        return Err(ProtocolError(
            "AES-CBC input is not a whole number of blocks".into(),
        ));
    }
    let round_keys = expand_aes128_key(key);
    let mut previous = ZERO_BLOCK;
    let mut output = Vec::with_capacity(input.len());
    for ciphertext in input.as_chunks::<16>().0 {
        let mut block = *ciphertext;
        aes128_decrypt_block(&mut block, &round_keys);
        for index in 0..16 {
            block[index] ^= previous[index];
        }
        output.extend_from_slice(&block);
        previous.copy_from_slice(ciphertext);
    }
    Ok(output)
}

fn aes_cbc_encrypt(key: &[u8; 16], input: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    if !input.len().is_multiple_of(16) {
        return Err(ProtocolError(
            "AES-CBC input is not a whole number of blocks".into(),
        ));
    }
    let round_keys = expand_aes128_key(key);
    let mut previous = ZERO_BLOCK;
    let mut output = Vec::with_capacity(input.len());
    for plaintext in input.as_chunks::<16>().0 {
        let mut block = *plaintext;
        for index in 0..16 {
            block[index] ^= previous[index];
        }
        aes128_encrypt_block(&mut block, &round_keys);
        output.extend_from_slice(&block);
        previous = block;
    }
    Ok(output)
}

// Small, dependency-free AES-128 implementation used only for the documented
// SYSCON challenge-response. It is covered by NIST known-answer tests below;
// it is not exposed as a general-purpose cryptography API.
fn expand_aes128_key(key: &[u8; 16]) -> [u8; 176] {
    let mut expanded = [0_u8; 176];
    expanded[..16].copy_from_slice(key);
    let mut generated = 16;
    let mut rcon = 1_u8;
    while generated < expanded.len() {
        let mut word = [
            expanded[generated - 4],
            expanded[generated - 3],
            expanded[generated - 2],
            expanded[generated - 1],
        ];
        if generated % 16 == 0 {
            word.rotate_left(1);
            for byte in &mut word {
                *byte = aes_sbox(*byte);
            }
            word[0] ^= rcon;
            rcon = gf_mul(rcon, 2);
        }
        for byte in word {
            expanded[generated] = expanded[generated - 16] ^ byte;
            generated += 1;
        }
    }
    expanded
}

fn aes128_encrypt_block(block: &mut [u8; 16], round_keys: &[u8; 176]) {
    add_round_key(block, &round_keys[..16]);
    for round in 1..10 {
        for byte in block.iter_mut() {
            *byte = aes_sbox(*byte);
        }
        shift_rows(block, false);
        mix_columns(block, false);
        add_round_key(block, &round_keys[round * 16..(round + 1) * 16]);
    }
    for byte in block.iter_mut() {
        *byte = aes_sbox(*byte);
    }
    shift_rows(block, false);
    add_round_key(block, &round_keys[160..176]);
}

fn aes128_decrypt_block(block: &mut [u8; 16], round_keys: &[u8; 176]) {
    add_round_key(block, &round_keys[160..176]);
    for round in (1..10).rev() {
        shift_rows(block, true);
        for byte in block.iter_mut() {
            *byte = aes_inverse_sbox(*byte);
        }
        add_round_key(block, &round_keys[round * 16..(round + 1) * 16]);
        mix_columns(block, true);
    }
    shift_rows(block, true);
    for byte in block.iter_mut() {
        *byte = aes_inverse_sbox(*byte);
    }
    add_round_key(block, &round_keys[..16]);
}

fn add_round_key(block: &mut [u8; 16], round_key: &[u8]) {
    for (byte, key) in block.iter_mut().zip(round_key) {
        *byte ^= key;
    }
}

fn shift_rows(block: &mut [u8; 16], inverse: bool) {
    let original = *block;
    for row in 1..4 {
        for column in 0..4 {
            let source_column = if inverse {
                (column + 4 - row) % 4
            } else {
                (column + row) % 4
            };
            block[column * 4 + row] = original[source_column * 4 + row];
        }
    }
}

fn mix_columns(block: &mut [u8; 16], inverse: bool) {
    for column in 0..4 {
        let index = column * 4;
        let values = [
            block[index],
            block[index + 1],
            block[index + 2],
            block[index + 3],
        ];
        let matrix = if inverse {
            [
                [14, 11, 13, 9],
                [9, 14, 11, 13],
                [13, 9, 14, 11],
                [11, 13, 9, 14],
            ]
        } else {
            [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]]
        };
        for row in 0..4 {
            block[index + row] = gf_mul(values[0], matrix[row][0])
                ^ gf_mul(values[1], matrix[row][1])
                ^ gf_mul(values[2], matrix[row][2])
                ^ gf_mul(values[3], matrix[row][3]);
        }
    }
}

fn aes_sbox(value: u8) -> u8 {
    let inverse = if value == 0 { 0 } else { gf_pow(value, 254) };
    inverse
        ^ inverse.rotate_left(1)
        ^ inverse.rotate_left(2)
        ^ inverse.rotate_left(3)
        ^ inverse.rotate_left(4)
        ^ 0x63
}

fn aes_inverse_sbox(value: u8) -> u8 {
    (0_u16..=255)
        .map(|candidate| candidate as u8)
        .find(|candidate| aes_sbox(*candidate) == value)
        .expect("AES S-box is bijective")
}

fn gf_pow(mut value: u8, mut exponent: u8) -> u8 {
    let mut result = 1_u8;
    while exponent > 0 {
        if exponent & 1 == 1 {
            result = gf_mul(result, value);
        }
        value = gf_mul(value, value);
        exponent >>= 1;
    }
    result
}

fn gf_mul(mut left: u8, mut right: u8) -> u8 {
    let mut result = 0_u8;
    while right != 0 {
        if right & 1 != 0 {
            result ^= left;
        }
        let high_bit = left & 0x80;
        left <<= 1;
        if high_bit != 0 {
            left ^= 0x1B;
        }
        right >>= 1;
    }
    result
}

fn decode_hex(value: &str) -> Result<Vec<u8>, ProtocolError> {
    if !value.len().is_multiple_of(2) {
        return Err(ProtocolError("hex string has an odd length".into()));
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let pair = std::str::from_utf8(pair)
                .map_err(|_| ProtocolError("hex string is not UTF-8".into()))?;
            u8::from_str_radix(pair, 16)
                .map_err(|_| ProtocolError("hex string contains an invalid digit".into()))
        })
        .collect()
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(HEX[(byte >> 4) as usize] as char);
        result.push(HEX[(byte & 0x0F) as usize] as char);
    }
    result
}

fn escaped_wire(bytes: &[u8]) -> String {
    escaped_text(&String::from_utf8_lossy(bytes))
}

fn escaped_text(text: &str) -> String {
    text.replace('\r', "\\r").replace('\n', "\\n")
}

const fn hex_16(value: &str) -> [u8; 16] {
    let bytes = value.as_bytes();
    let mut output = [0_u8; 16];
    let mut index = 0;
    while index < 16 {
        output[index] = (hex_nibble(bytes[index * 2]) << 4) | hex_nibble(bytes[index * 2 + 1]);
        index += 1;
    }
    output
}

const fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        b'A'..=b'F' => value - b'A' + 10,
        _ => panic!("invalid hex digit"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::io;

    struct ScriptedIo {
        responses: VecDeque<Vec<u8>>,
        current: VecDeque<u8>,
        writes: Vec<Vec<u8>>,
    }

    impl ScriptedIo {
        fn new(responses: Vec<Vec<u8>>) -> Self {
            Self {
                responses: responses.into(),
                current: VecDeque::new(),
                writes: Vec::new(),
            }
        }
    }

    impl Write for ScriptedIo {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.writes.push(buffer.to_vec());
            self.current = self.responses.pop_front().unwrap_or_default().into();
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Read for ScriptedIo {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let count = buffer.len().min(self.current.len());
            for output in &mut buffer[..count] {
                *output = self.current.pop_front().expect("length checked");
            }
            Ok(count)
        }
    }

    fn sw_response(payload: &str) -> Vec<u8> {
        format!("{payload}:{:02X}\r\n", checksum(payload.as_bytes())).into_bytes()
    }

    #[test]
    fn frames_each_profile_with_crlf_and_checksum() {
        assert_eq!(
            frame_command(SysconProfile::Cxr, "VERSION"),
            format!("C:{:02X}:VERSION\r\n", checksum(b"VERSION")).into_bytes()
        );
        assert_eq!(
            frame_command(SysconProfile::Sw, "errlog"),
            format!("errlog:{:02X}\r\n", checksum(b"errlog")).into_bytes()
        );
        assert_eq!(frame_command(SysconProfile::Cxrf, "errlog"), b"errlog\r\n");
    }

    #[test]
    fn parses_and_validates_cxr_response() {
        let body = "OK 00000000 A0801001";
        let raw = format!("R:{:02X}:{body}\r\n", checksum(body.as_bytes()));
        let response = parse_response(SysconProfile::Cxr, &raw).unwrap();
        assert_eq!(response.status, 0);
        assert_eq!(response.data, ["A0801001"]);
    }

    #[test]
    fn rejects_bad_response_checksum() {
        assert!(parse_response(SysconProfile::Cxr, "R:00:OK 00000000\r\n").is_err());
    }

    #[test]
    fn extracts_error_records_without_interpreting_them() {
        let records = extract_error_records(
            "ERR 00: 00000000 A0801001 12345678\nERR 01: 00000000 A0403034 ABCDEF00\n",
        );
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].slot, Some(0));
        assert_eq!(records[1].code, "A0403034");
        assert_eq!(
            records[0].timestamp.as_ref().map(|value| value.raw),
            Some(0x1234_5678)
        );
    }

    #[test]
    fn converts_documented_syscon_clock_examples() {
        assert_eq!(format_syscon_timestamp(0x1946_E078), "2013-06-09 06:43:04");
        assert_eq!(format_syscon_timestamp(0x0B48_8680), "2005-12-31 00:00:00");

        let records = extract_error_records(
            "ofst[ 16]:err_code:0xa0404412, clock:0xffffffff\n\
             ofst[ 20]:err_code:0xa0801701, clock:0x194be6c6  2013/06/13 02:11:18\n",
        );
        assert_eq!(
            records[0].timestamp.as_ref().map(|value| value.raw),
            Some(u32::MAX)
        );
        assert_eq!(
            records[0]
                .timestamp
                .as_ref()
                .and_then(|value| value.formatted.as_deref()),
            None
        );
        assert_eq!(
            records[1]
                .timestamp
                .as_ref()
                .and_then(|value| value.formatted.as_deref()),
            Some("2013-06-13 02:11:18")
        );
    }

    #[test]
    fn aes_cbc_matches_nist_vector() {
        let key = hex_16("2b7e151628aed2a6abf7158809cf4f3c");
        let plaintext = decode_hex("6bc1bee22e409f96e93d7e117393172a").unwrap();
        // NIST SP 800-38A with an all-zero IV has this first block.
        let encrypted = aes_cbc_encrypt(&key, &plaintext).unwrap();
        assert_eq!(encode_hex(&encrypted), "3AD77BB40D7A3660A89ECAF32466EF97");
        assert_eq!(aes_cbc_decrypt(&key, &encrypted).unwrap(), plaintext);
    }

    #[test]
    fn completes_scripted_sw_authentication() {
        let mut challenge_body = Vec::new();
        challenge_body.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        challenge_body.extend_from_slice(&[0; 8]);
        challenge_body.extend_from_slice(&AUTH_VALUE);
        challenge_body.extend_from_slice(&[0; 16]);
        let encrypted = aes_cbc_encrypt(&SC2TB_KEY, &challenge_body).unwrap();
        let mut challenge = AUTH1_HEADER.to_vec();
        challenge.extend_from_slice(&encrypted);
        let challenge = encode_hex(&challenge);

        let mut io = ScriptedIo::new(vec![
            sw_response("OK 00000000"),
            sw_response(&format!("OK 00000000 {challenge}")),
            sw_response("OK 00000000"),
            sw_response("OK 00000000"),
        ]);
        let mut traces = Vec::new();
        authenticate(&mut io, SysconProfile::Sw, &mut |trace| traces.push(trace)).unwrap();
        assert_eq!(io.writes.len(), 4);
        assert!(String::from_utf8_lossy(&io.writes[3]).contains("AUTH2 "));
        assert!(
            traces
                .iter()
                .any(|trace| trace.direction == TraceDirection::Tx)
        );
    }
}
