//! Safe-by-default serial and mock transports.
//!
//! Opening a real connection only starts a reader. Typed protocol operations
//! are limited to authentication and read-only error-history retrieval.

pub mod protocol;

use serde::{Deserialize, Serialize};
use serialport::{SerialPortType, UsbPortInfo};
use std::fmt;
use std::io::{Read, Write};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

pub use protocol::{ErrorLogRecord, ErrorLogTimestamp, SysconProfile};

const FTDI_VENDOR_ID: u16 = 0x0403;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PortDescriptor {
    pub name: String,
    pub kind: String,
    pub usb_vid: Option<u16>,
    pub usb_pid: Option<u16>,
    pub manufacturer: Option<String>,
    pub product: Option<String>,
    pub serial_number: Option<String>,
    pub is_ftdi: bool,
}

impl PortDescriptor {
    fn from_serialport(port: serialport::SerialPortInfo) -> Self {
        match port.port_type {
            SerialPortType::UsbPort(info) => Self::from_usb(port.port_name, info),
            SerialPortType::BluetoothPort => Self::plain(port.port_name, "Bluetooth"),
            SerialPortType::PciPort => Self::plain(port.port_name, "PCI"),
            SerialPortType::Unknown => Self::plain(port.port_name, "Unknown"),
        }
    }

    fn from_usb(name: String, info: UsbPortInfo) -> Self {
        let is_ftdi = info.vid == FTDI_VENDOR_ID
            || info
                .manufacturer
                .as_deref()
                .is_some_and(|value| value.to_ascii_lowercase().contains("ftdi"))
            || info
                .product
                .as_deref()
                .is_some_and(|value| value.to_ascii_lowercase().contains("ft232"));
        Self {
            name,
            kind: "USB".into(),
            usb_vid: Some(info.vid),
            usb_pid: Some(info.pid),
            manufacturer: info.manufacturer,
            product: info.product,
            serial_number: info.serial_number,
            is_ftdi,
        }
    }

    fn plain(name: String, kind: &str) -> Self {
        Self {
            name,
            kind: kind.into(),
            usb_vid: None,
            usb_pid: None,
            manufacturer: None,
            product: None,
            serial_number: None,
            is_ftdi: false,
        }
    }

    pub fn display_name(&self) -> String {
        let marker = if self.is_ftdi { " [FTDI/FT232]" } else { "" };
        match (&self.product, self.usb_vid, self.usb_pid) {
            (Some(product), Some(vid), Some(pid)) => {
                format!("{} — {} ({vid:04X}:{pid:04X}){marker}", self.name, product)
            }
            _ => format!("{} — {}{marker}", self.name, self.kind),
        }
    }
}

pub fn enumerate_ports() -> Result<Vec<PortDescriptor>, TransportError> {
    let mut ports: Vec<_> = serialport::available_ports()
        .map_err(|error| TransportError(error.to_string()))?
        .into_iter()
        .map(PortDescriptor::from_serialport)
        .collect();
    ports.sort_by_key(|port| (!port.is_ftdi, port.name.clone()));
    Ok(ports)
}

pub fn ft232_ports() -> Result<Vec<PortDescriptor>, TransportError> {
    Ok(enumerate_ports()?
        .into_iter()
        .filter(|port| port.is_ftdi)
        .collect())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConnectionSettings {
    pub port_name: String,
    pub baud_rate: u32,
    pub timeout_ms: u64,
}

impl Default for ConnectionSettings {
    fn default() -> Self {
        Self {
            port_name: String::new(),
            baud_rate: 57_600,
            timeout_ms: 25,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportEvent {
    Data(Vec<u8>),
    Notice(String),
    AuthAttempt { attempt: u8, total: u8 },
    Authenticated(SysconProfile),
    AuthFailed(String),
    ErrorHistory(Vec<ErrorLogRecord>),
    OperationFinished,
    Error(String),
    Disconnected,
}

enum TransportCommand {
    Write(Vec<u8>),
    Authenticate {
        profile: SysconProfile,
        attempts: u8,
        retry_delay: Duration,
    },
    GetErrors {
        profile: SysconProfile,
    },
    Stop,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportError(pub String);

impl fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for TransportError {}

pub struct TerminalConnection {
    commands: Sender<TransportCommand>,
    events: Receiver<TransportEvent>,
    worker: Option<JoinHandle<()>>,
    pub is_mock: bool,
}

impl TerminalConnection {
    /// Opens an 8-N-1 serial port and starts a reader thread. No bytes are sent.
    pub fn open(settings: &ConnectionSettings) -> Result<Self, TransportError> {
        if settings.port_name.trim().is_empty() {
            return Err(TransportError("no serial port selected".into()));
        }
        if settings.baud_rate == 0 {
            return Err(TransportError("baud rate must be greater than zero".into()));
        }

        let port = serialport::new(&settings.port_name, settings.baud_rate)
            .timeout(Duration::from_millis(settings.timeout_ms.max(1)))
            .data_bits(serialport::DataBits::Eight)
            .parity(serialport::Parity::None)
            .stop_bits(serialport::StopBits::One)
            .flow_control(serialport::FlowControl::None)
            .open()
            .map_err(|error| TransportError(error.to_string()))?;

        let (command_tx, command_rx) = mpsc::channel();
        let (event_tx, event_rx) = mpsc::channel();
        let name = settings.port_name.clone();
        let worker = thread::spawn(move || serial_worker(port, command_rx, event_tx, name));
        Ok(Self {
            commands: command_tx,
            events: event_rx,
            worker: Some(worker),
            is_mock: false,
        })
    }

    #[cfg(feature = "mock")]
    pub fn mock() -> Self {
        let (command_tx, command_rx) = mpsc::channel();
        let (event_tx, event_rx) = mpsc::channel();
        let worker = thread::spawn(move || mock_worker(command_rx, event_tx));
        Self {
            commands: command_tx,
            events: event_rx,
            worker: Some(worker),
            is_mock: true,
        }
    }

    /// Queues raw terminal bytes. Applications should put an explicit safety
    /// gate in front of this method for real hardware.
    pub fn send(&self, bytes: Vec<u8>) -> Result<(), TransportError> {
        self.commands
            .send(TransportCommand::Write(bytes))
            .map_err(|_| TransportError("connection worker has stopped".into()))
    }

    pub fn authenticate(
        &self,
        profile: SysconProfile,
        attempts: u8,
        retry_delay: Duration,
    ) -> Result<(), TransportError> {
        self.commands
            .send(TransportCommand::Authenticate {
                profile,
                attempts: attempts.max(1),
                retry_delay,
            })
            .map_err(|_| TransportError("connection worker has stopped".into()))
    }

    pub fn get_errors(&self, profile: SysconProfile) -> Result<(), TransportError> {
        self.commands
            .send(TransportCommand::GetErrors { profile })
            .map_err(|_| TransportError("connection worker has stopped".into()))
    }

    pub fn try_recv(&self) -> Option<TransportEvent> {
        self.events.try_recv().ok()
    }

    pub fn disconnect(&mut self) {
        let _ = self.commands.send(TransportCommand::Stop);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

impl Drop for TerminalConnection {
    fn drop(&mut self) {
        self.disconnect();
    }
}

fn serial_worker(
    mut port: Box<dyn serialport::SerialPort>,
    commands: Receiver<TransportCommand>,
    events: Sender<TransportEvent>,
    name: String,
) {
    let _ = events.send(TransportEvent::Notice(format!(
        "Connected to {name} in passive read mode; no initialization bytes sent.\n"
    )));
    let mut buffer = [0_u8; 1024];
    let mut authenticated_profile = None;
    loop {
        match commands.try_recv() {
            Ok(TransportCommand::Write(bytes)) => {
                let _ = events.send(TransportEvent::Notice(format!(
                    "[TX raw] {}\n",
                    escape_bytes(&bytes)
                )));
                if let Err(error) = port.write_all(&bytes) {
                    let _ = events.send(TransportEvent::Error(error.to_string()));
                    break;
                }
            }
            Ok(TransportCommand::Authenticate {
                profile,
                attempts,
                retry_delay,
            }) => {
                authenticated_profile = None;
                let mut final_error = String::new();
                for attempt in 1..=attempts {
                    let _ = events.send(TransportEvent::AuthAttempt {
                        attempt,
                        total: attempts,
                    });
                    let mut trace = |entry: protocol::ProtocolTrace| {
                        let direction = match entry.direction {
                            protocol::TraceDirection::Tx => "TX",
                            protocol::TraceDirection::Rx => "RX",
                        };
                        let _ = events.send(TransportEvent::Notice(format!(
                            "[{direction} {}] {}\n",
                            profile.short_name(),
                            entry.text
                        )));
                    };
                    match protocol::authenticate(&mut *port, profile, &mut trace) {
                        Ok(()) => {
                            authenticated_profile = Some(profile);
                            final_error.clear();
                            let _ = events.send(TransportEvent::Authenticated(profile));
                            break;
                        }
                        Err(error) => {
                            final_error = error.to_string();
                            let _ = events.send(TransportEvent::Notice(format!(
                                "[AUTH {attempt}/{attempts}] failed: {error}\n"
                            )));
                            if attempt < attempts {
                                let _ = events.send(TransportEvent::Notice(format!(
                                    "[AUTH] retrying in {:.1}s…\n",
                                    retry_delay.as_secs_f32()
                                )));
                                thread::sleep(retry_delay);
                            }
                        }
                    }
                }
                if authenticated_profile.is_none() {
                    let _ = events.send(TransportEvent::AuthFailed(final_error));
                }
                let _ = events.send(TransportEvent::OperationFinished);
            }
            Ok(TransportCommand::GetErrors { profile }) => {
                if authenticated_profile != Some(profile) {
                    let _ = events.send(TransportEvent::Error(
                        "authenticate successfully before reading the error history".into(),
                    ));
                    let _ = events.send(TransportEvent::OperationFinished);
                    continue;
                }
                let mut trace = |entry: protocol::ProtocolTrace| {
                    let direction = match entry.direction {
                        protocol::TraceDirection::Tx => "TX",
                        protocol::TraceDirection::Rx => "RX",
                    };
                    let _ = events.send(TransportEvent::Notice(format!(
                        "[{direction} {}] {}\n",
                        profile.short_name(),
                        entry.text
                    )));
                };
                match protocol::read_error_history(&mut *port, profile, &mut trace) {
                    Ok(records) => {
                        let _ = events.send(TransportEvent::ErrorHistory(records));
                    }
                    Err(error) => {
                        let _ = events.send(TransportEvent::Error(format!(
                            "error-history read failed: {error}"
                        )));
                    }
                }
                let _ = events.send(TransportEvent::OperationFinished);
            }
            Ok(TransportCommand::Stop) | Err(TryRecvError::Disconnected) => break,
            Err(TryRecvError::Empty) => {}
        }

        match port.read(&mut buffer) {
            Ok(count) if count > 0 => {
                if events
                    .send(TransportEvent::Data(buffer[..count].to_vec()))
                    .is_err()
                {
                    break;
                }
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut => {}
            Err(error) => {
                let _ = events.send(TransportEvent::Error(error.to_string()));
                break;
            }
        }
    }
    let _ = events.send(TransportEvent::Disconnected);
}

#[cfg(feature = "mock")]
fn mock_worker(commands: Receiver<TransportCommand>, events: Sender<TransportEvent>) {
    let _ = events.send(TransportEvent::Notice(
        "[mock] Offline terminal started. No hardware is connected.\n".into(),
    ));
    let mut authenticated_profile = None;
    loop {
        match commands.recv_timeout(Duration::from_millis(50)) {
            Ok(TransportCommand::Write(bytes)) => {
                let _ = events.send(TransportEvent::Notice(format!(
                    "[TX raw/mock] {}\n",
                    escape_bytes(&bytes)
                )));
                let mut response = b"[mock echo] ".to_vec();
                response.extend(bytes);
                let _ = events.send(TransportEvent::Data(response));
            }
            Ok(TransportCommand::Authenticate {
                profile,
                attempts,
                retry_delay,
            }) => {
                let total = attempts.max(1);
                let first_succeeds = total == 1;
                for attempt in 1..=total {
                    let _ = events.send(TransportEvent::AuthAttempt { attempt, total });
                    let _ = events.send(TransportEvent::Notice(format!(
                        "[TX {}/mock] AUTH handshake\n",
                        profile.short_name()
                    )));
                    if first_succeeds || attempt == 2 {
                        let _ = events.send(TransportEvent::Notice(format!(
                            "[RX {}/mock] authentication accepted\n",
                            profile.short_name()
                        )));
                        let _ = events.send(TransportEvent::Authenticated(profile));
                        authenticated_profile = Some(profile);
                        break;
                    }
                    let _ = events.send(TransportEvent::Notice(format!(
                        "[RX {}/mock] simulated transient AUTH failure\n",
                        profile.short_name()
                    )));
                    if attempt < total {
                        thread::sleep(retry_delay.min(Duration::from_millis(250)));
                    } else {
                        let _ = events.send(TransportEvent::AuthFailed(
                            "simulated transient AUTH failure".into(),
                        ));
                    }
                }
                let _ = events.send(TransportEvent::OperationFinished);
            }
            Ok(TransportCommand::GetErrors { profile }) => {
                if authenticated_profile != Some(profile) {
                    let _ = events.send(TransportEvent::Error(
                        "authenticate successfully before reading the error history".into(),
                    ));
                    let _ = events.send(TransportEvent::OperationFinished);
                    continue;
                }
                let _ = events.send(TransportEvent::Notice(format!(
                    "[TX {}/mock] read-only error-history request\n",
                    profile.short_name()
                )));
                let records = vec![
                    ErrorLogRecord {
                        slot: Some(0),
                        code: "A0801001".into(),
                        timestamp: Some(protocol::ErrorLogTimestamp {
                            raw: 0x2F45_7658,
                            formatted: Some("2025-02-17 04:23:52".into()),
                        }),
                        raw: "ERR 00: 00000000 A0801001 2F457658".into(),
                    },
                    ErrorLogRecord {
                        slot: Some(1),
                        code: "A0003001".into(),
                        timestamp: Some(protocol::ErrorLogTimestamp {
                            raw: 0x1946_E078,
                            formatted: Some("2013-06-09 06:43:04".into()),
                        }),
                        raw: "ERR 01: 00000000 A0003001 1946E078".into(),
                    },
                    ErrorLogRecord {
                        slot: Some(2),
                        code: "A040DEAD".into(),
                        timestamp: Some(protocol::ErrorLogTimestamp {
                            raw: u32::MAX,
                            formatted: None,
                        }),
                        raw: "ERR 02: 00000000 A040DEAD FFFFFFFF".into(),
                    },
                ];
                let _ = events.send(TransportEvent::Notice(
                    "[RX mock] returned 3 fixture records\n".into(),
                ));
                let _ = events.send(TransportEvent::ErrorHistory(records));
                let _ = events.send(TransportEvent::OperationFinished);
            }
            Ok(TransportCommand::Stop) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    }
    let _ = events.send(TransportEvent::Disconnected);
}

fn escape_bytes(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .replace('\r', "\\r")
        .replace('\n', "\\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn default_connection_is_configurable_and_passive() {
        let settings = ConnectionSettings::default();
        assert_eq!(settings.baud_rate, 57_600);
        assert!(settings.port_name.is_empty());
    }

    #[test]
    fn ftdi_vendor_is_recognized() {
        let port = PortDescriptor::from_usb(
            "/dev/test".into(),
            UsbPortInfo {
                vid: FTDI_VENDOR_ID,
                pid: 0x6001,
                serial_number: None,
                manufacturer: Some("FTDI".into()),
                product: Some("FT232R USB UART".into()),
            },
        );
        assert!(port.is_ftdi);
        assert!(port.display_name().contains("FTDI/FT232"));
    }

    #[cfg(feature = "mock")]
    #[test]
    fn mock_transport_echoes_without_hardware() {
        let mut connection = TerminalConnection::mock();
        connection.send(b"hello\n".to_vec()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut received = Vec::new();
        while Instant::now() < deadline {
            if let Some(TransportEvent::Data(data)) = connection.try_recv() {
                received.extend(data);
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        connection.disconnect();
        assert!(String::from_utf8_lossy(&received).contains("hello"));
    }

    #[cfg(feature = "mock")]
    #[test]
    fn mock_auth_retries_then_unlocks_error_history() {
        let mut connection = TerminalConnection::mock();
        connection
            .authenticate(SysconProfile::Cxr, 3, Duration::from_millis(1))
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut attempts = 0;
        let mut authenticated = false;
        while Instant::now() < deadline && !authenticated {
            if let Some(event) = connection.try_recv() {
                match event {
                    TransportEvent::AuthAttempt { .. } => attempts += 1,
                    TransportEvent::Authenticated(SysconProfile::Cxr) => authenticated = true,
                    _ => {}
                }
            }
            thread::sleep(Duration::from_millis(1));
        }
        assert!(authenticated);
        assert_eq!(attempts, 2);

        connection.get_errors(SysconProfile::Cxr).unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut record_count = None;
        while Instant::now() < deadline && record_count.is_none() {
            if let Some(TransportEvent::ErrorHistory(records)) = connection.try_recv() {
                record_count = Some(records.len());
            }
            thread::sleep(Duration::from_millis(1));
        }
        connection.disconnect();
        assert_eq!(record_count, Some(3));
    }
}
