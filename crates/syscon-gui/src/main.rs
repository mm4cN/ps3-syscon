use eframe::egui;
use std::path::PathBuf;
use std::time::Duration;
use syscon_core::{
    ConnectionSettings, ErrorLogRecord, PortDescriptor, SysconProfile, TerminalConnection,
    TransportEvent,
};
use syscon_diagnostics::{DecodedError, DiagnosticReport};

struct BoardGuide {
    label: &'static str,
    url: &'static str,
    hint: &'static str,
}

const PANEL_ROW_HEIGHT: f32 = 24.0;

fn panel_row(ui: &mut egui::Ui, add_contents: impl FnOnce(&mut egui::Ui)) {
    ui.allocate_ui_with_layout(
        egui::vec2(ui.available_width(), PANEL_ROW_HEIGHT),
        egui::Layout::left_to_right(egui::Align::Center),
        add_contents,
    );
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TerminalState {
    Disconnected,
    OfflineMock,
    Idle,
    InProgress,
    Manual,
    Authenticated,
}

impl TerminalState {
    fn label(self) -> &'static str {
        match self {
            Self::Disconnected => "Disconnected",
            Self::OfflineMock => "Offline mock",
            Self::Idle => "Idle",
            Self::InProgress => "In progress",
            Self::Manual => "Manual",
            Self::Authenticated => "Authenticated",
        }
    }

    fn color(self) -> egui::Color32 {
        match self {
            Self::Disconnected => egui::Color32::GRAY,
            Self::OfflineMock => egui::Color32::LIGHT_RED,
            Self::Idle => egui::Color32::YELLOW,
            Self::InProgress => egui::Color32::GREEN,
            Self::Manual => egui::Color32::from_rgb(255, 165, 0),
            Self::Authenticated => egui::Color32::LIGHT_BLUE,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ErrorSortOrder {
    NewestFirst,
    SysconOrder,
}

impl ErrorSortOrder {
    const ALL: [Self; 2] = [Self::NewestFirst, Self::SysconOrder];

    fn label(self) -> &'static str {
        match self {
            Self::NewestFirst => "Newest first",
            Self::SysconOrder => "SYSCON order",
        }
    }
}

const BOARD_GUIDES: &[BoardGuide] = &[
    BoardGuide {
        label: "COK-001/002 — CECHA-E",
        url: "https://github.com/db260179/ps3syscon/blob/81cc667de930d489aa6ea9b4e87d0197d119511c/PS3-Serial-Connection-Points/COK-001-002-(A-E-Models)/COK-001_SC_UART_testpads.jpg",
        hint: "Mullion family; verify the exact board and start with CXR external mode.",
    },
    BoardGuide {
        label: "SEM-001 — CECHG",
        url: "https://github.com/db260179/ps3syscon/blob/81cc667de930d489aa6ea9b4e87d0197d119511c/PS3-Serial-Connection-Points/SEM-001-(G-Models)/SEM-001_SC_UART_testpads.jpg",
        hint: "Mullion family; verify the board marking before selecting pads.",
    },
    BoardGuide {
        label: "DIA-001 — CECHH",
        url: "https://github.com/db260179/ps3syscon/blob/81cc667de930d489aa6ea9b4e87d0197d119511c/PS3-Serial-Connection-Points/DIA-001-002-(H-K-Models)/DIA-001_SC_UART_testpads.jpg",
        hint: "Mullion family; DIAG is relevant only for the documented internal-mode procedure.",
    },
    BoardGuide {
        label: "DIA-002 — CECHJ/K",
        url: "https://github.com/db260179/ps3syscon/blob/81cc667de930d489aa6ea9b4e87d0197d119511c/PS3-Serial-Connection-Points/DIA-001-002-(H-K-Models)/DIA-002_SC_UART_testpads.jpg",
        hint: "Mullion family; verify the board marking, not only the case label.",
    },
    BoardGuide {
        label: "VER-001 — CECHL-Q",
        url: "https://github.com/db260179/ps3syscon/blob/81cc667de930d489aa6ea9b4e87d0197d119511c/PS3-Serial-Connection-Points/VER-001-(L-Q-Models)/VER-001_SC_UART_testpads.jpg",
        hint: "Sherwood family; select the SW profile.",
    },
    BoardGuide {
        label: "DYN-001 — CECH-20xx",
        url: "https://github.com/db260179/ps3syscon/blob/81cc667de930d489aa6ea9b4e87d0197d119511c/PS3-Serial-Connection-Points/DYN-001-(20xx-Model)/DYN-001_SC_UART_testpads.jpg",
        hint: "Sherwood family; select the SW profile.",
    },
    BoardGuide {
        label: "SUR/JTP/JSD/KTE — CECH-21xx-40xx",
        url: "https://github.com/db260179/ps3syscon/blob/81cc667de930d489aa6ea9b4e87d0197d119511c/PS3-Serial-Connection-Points/SUR-001-JTP-001-JSD-001-KTE-001-(21xx-40xx-Models)/SUR-001_SC_and_SB_UART_testpads.jpg",
        hint: "Sherwood family; select SW and use only the SC UART pads shown in the collection.",
    },
    BoardGuide {
        label: "SW3 — Super Slim",
        url: "https://github.com/db260179/ps3syscon/blob/81cc667de930d489aa6ea9b4e87d0197d119511c/PS3-Serial-Connection-Points/All-Super-Slim-Models/SW3_SC_UART_testpads.jpg",
        hint: "Sherwood family; select SW. The Mullion DIAG procedure does not apply.",
    },
];

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1180.0, 760.0]),
        ..Default::default()
    };
    eframe::run_native(
        "PS3 SYSCON Diagnostic",
        options,
        Box::new(|_context| Ok(Box::<SysconApp>::default())),
    )
}

struct SysconApp {
    ports: Vec<PortDescriptor>,
    selected_port: usize,
    settings: ConnectionSettings,
    profile: SysconProfile,
    connection: Option<TerminalConnection>,
    authenticated: bool,
    operation_busy: bool,
    auth_attempts: u8,
    retry_delay_seconds: f32,
    selected_board_guide: usize,
    allow_transmit: bool,
    append_crlf: bool,
    terminal: String,
    transmit: String,
    status: String,
    decoder_input: String,
    decoded: Vec<DecodedError>,
    error_sort_order: ErrorSortOrder,
    error_history: Vec<ErrorLogRecord>,
    export_path: String,
}

impl Default for SysconApp {
    fn default() -> Self {
        let mut app = Self {
            ports: Vec::new(),
            selected_port: 0,
            settings: ConnectionSettings::default(),
            profile: SysconProfile::Cxr,
            connection: None,
            authenticated: false,
            operation_busy: false,
            auth_attempts: 3,
            retry_delay_seconds: 2.0,
            selected_board_guide: 0,
            allow_transmit: false,
            append_crlf: true,
            terminal: String::new(),
            transmit: String::new(),
            status: "Disconnected — passive/read-only by default".into(),
            decoder_input: String::new(),
            decoded: Vec::new(),
            error_sort_order: ErrorSortOrder::NewestFirst,
            error_history: Vec::new(),
            export_path: "syscon-diagnostics.txt".into(),
        };
        app.refresh_ports();
        app
    }
}

impl SysconApp {
    fn refresh_ports(&mut self) {
        match syscon_core::enumerate_ports() {
            Ok(ports) => {
                let previous = self.settings.port_name.clone();
                self.ports = ports;
                self.selected_port = self
                    .ports
                    .iter()
                    .position(|port| port.name == previous)
                    .unwrap_or(0);
                if let Some(port) = self.ports.get(self.selected_port) {
                    self.settings.port_name = port.name.clone();
                }
                self.status = format!(
                    "Found {} port(s), including {} FTDI/FT232 candidate(s)",
                    self.ports.len(),
                    self.ports.iter().filter(|port| port.is_ftdi).count()
                );
            }
            Err(error) => self.status = format!("Port scan failed: {error}"),
        }
    }

    fn connect_serial(&mut self) {
        self.disconnect();
        if let Some(port) = self.ports.get(self.selected_port) {
            self.settings.port_name = port.name.clone();
        }
        self.settings.baud_rate = self.profile.baud_rate();
        match TerminalConnection::open(&self.settings) {
            Ok(connection) => {
                self.connection = Some(connection);
                self.allow_transmit = false;
                self.authenticated = false;
                self.status = format!(
                    "Connected as {} in passive mode; press Auth to begin",
                    self.profile.short_name()
                );
            }
            Err(error) => self.status = format!("Connection failed: {error}"),
        }
    }

    #[cfg(feature = "mock")]
    fn connect_mock(&mut self) {
        self.disconnect();
        self.connection = Some(TerminalConnection::mock());
        self.allow_transmit = false;
        self.authenticated = false;
        self.status = "Offline mock active".into();
    }

    fn disconnect(&mut self) {
        if let Some(mut connection) = self.connection.take() {
            connection.disconnect();
        }
        self.allow_transmit = false;
        self.authenticated = false;
        self.operation_busy = false;
    }

    fn authenticate(&mut self) {
        let Some(connection) = &self.connection else {
            return;
        };
        self.authenticated = false;
        self.operation_busy = true;
        self.status = "Authentication started…".into();
        if let Err(error) = connection.authenticate(
            self.profile,
            self.auth_attempts,
            Duration::from_secs_f32(self.retry_delay_seconds),
        ) {
            self.operation_busy = false;
            self.status = format!("Could not start authentication: {error}");
        }
    }

    fn get_errors(&mut self) {
        let Some(connection) = &self.connection else {
            return;
        };
        self.operation_busy = true;
        self.status = "Reading error history…".into();
        if let Err(error) = connection.get_errors(self.profile) {
            self.operation_busy = false;
            self.status = format!("Could not start history read: {error}");
        }
    }

    fn poll_terminal(&mut self) {
        let mut disconnected = false;
        if let Some(connection) = &self.connection {
            while let Some(event) = connection.try_recv() {
                match event {
                    TransportEvent::Data(bytes) => {
                        self.terminal.push_str(&String::from_utf8_lossy(&bytes));
                    }
                    TransportEvent::Notice(message) => self.terminal.push_str(&message),
                    TransportEvent::AuthAttempt { attempt, total } => {
                        self.status = format!("Authentication attempt {attempt}/{total}…");
                        self.terminal
                            .push_str(&format!("[AUTH] attempt {attempt}/{total}\n"));
                    }
                    TransportEvent::Authenticated(profile) => {
                        self.authenticated = true;
                        self.status =
                            format!("Authenticated successfully ({})", profile.short_name());
                        self.terminal.push_str("[AUTH] successful\n");
                    }
                    TransportEvent::AuthFailed(error) => {
                        self.authenticated = false;
                        self.status = format!("Authentication failed: {error}");
                        self.terminal.push_str(&format!("[AUTH] failed: {error}\n"));
                    }
                    TransportEvent::ErrorHistory(records) => {
                        self.error_history = records;
                        self.decoded = self
                            .error_history
                            .iter()
                            .filter_map(|record| {
                                let mut decoded = syscon_diagnostics::decode(&record.code).ok()?;
                                if let Some(timestamp) = &record.timestamp {
                                    decoded.timestamp_raw =
                                        Some(format!("0x{:08X}", timestamp.raw));
                                    decoded.occurred_at = timestamp.formatted.clone();
                                    if timestamp.formatted.is_none() {
                                        decoded.timestamp_warning =
                                            Some("time unavailable (FFFFFFFF)".into());
                                    }
                                }
                                Some(decoded)
                            })
                            .collect();
                        self.status =
                            format!("Read {} error-history record(s)", self.error_history.len());
                    }
                    TransportEvent::OperationFinished => self.operation_busy = false,
                    TransportEvent::Error(error) => {
                        self.operation_busy = false;
                        self.status = format!("Serial error: {error}");
                        self.terminal.push_str(&format!("\n[error] {error}\n"));
                    }
                    TransportEvent::Disconnected => disconnected = true,
                }
            }
        }
        if disconnected {
            self.connection = None;
            self.allow_transmit = false;
            self.authenticated = false;
            self.operation_busy = false;
            self.status = "Disconnected".into();
        }
        const MAX_TERMINAL_CHARS: usize = 250_000;
        if self.terminal.len() > MAX_TERMINAL_CHARS {
            let split = self.terminal.len() - MAX_TERMINAL_CHARS;
            let boundary = self.terminal.ceil_char_boundary(split);
            self.terminal.drain(..boundary);
        }
    }

    fn send_terminal(&mut self) {
        if !self.allow_transmit || self.transmit.is_empty() {
            return;
        }
        let mut bytes = self.transmit.as_bytes().to_vec();
        if self.append_crlf {
            bytes.extend_from_slice(b"\r\n");
        }
        if let Some(connection) = &self.connection {
            match connection.send(bytes) {
                Ok(()) => self.transmit.clear(),
                Err(error) => self.status = format!("Send failed: {error}"),
            }
        }
    }

    fn decode_current(&mut self) {
        match syscon_diagnostics::decode(&self.decoder_input) {
            Ok(decoded) => {
                self.decoded.push(decoded);
                self.decoder_input.clear();
                self.status = "Code added to report".into();
            }
            Err(error) => self.status = format!("Invalid code: {error}"),
        }
    }

    fn export_text(&mut self) {
        let report =
            DiagnosticReport::new(self.ordered_decoded_errors().into_iter().cloned().collect());
        let path = PathBuf::from(self.export_path.trim());
        match std::fs::write(&path, report.to_text()) {
            Ok(()) => self.status = format!("Exported {}", path.display()),
            Err(error) => self.status = format!("Export failed: {error}"),
        }
    }

    fn terminal_state(&self) -> TerminalState {
        let Some(connection) = &self.connection else {
            return TerminalState::Disconnected;
        };
        if self.operation_busy {
            TerminalState::InProgress
        } else if self.manual_mode_active() {
            TerminalState::Manual
        } else if connection.is_mock {
            TerminalState::OfflineMock
        } else if self.authenticated {
            TerminalState::Authenticated
        } else {
            TerminalState::Idle
        }
    }

    fn terminal_state_badge(&self, ui: &mut egui::Ui) {
        let state = self.terminal_state();
        let color = state.color();
        let (rect, _) = ui.allocate_exact_size(egui::vec2(14.0, 14.0), egui::Sense::hover());
        ui.painter().circle_filled(rect.center(), 5.0, color);
        ui.colored_label(color, state.label());
    }

    fn manual_mode_active(&self) -> bool {
        self.connection.is_some() && self.allow_transmit
    }

    fn manual_mode_badge(&self, ui: &mut egui::Ui) {
        let color = if self.manual_mode_active() {
            egui::Color32::from_rgb(255, 165, 0)
        } else {
            egui::Color32::GRAY
        };
        let (rect, _) = ui.allocate_exact_size(egui::vec2(14.0, 14.0), egui::Sense::hover());
        ui.painter().circle_filled(rect.center(), 5.0, color);
        ui.colored_label(color, "Manual mode");
    }

    fn ordered_decoded_errors(&self) -> Vec<&DecodedError> {
        let mut entries: Vec<_> = self.decoded.iter().enumerate().collect();
        if self.error_sort_order == ErrorSortOrder::NewestFirst {
            entries.sort_by(|(left_index, left), (right_index, right)| {
                match (&left.occurred_at, &right.occurred_at) {
                    (Some(left_time), Some(right_time)) => right_time
                        .cmp(left_time)
                        .then_with(|| left_index.cmp(right_index)),
                    (Some(_), None) => std::cmp::Ordering::Less,
                    (None, Some(_)) => std::cmp::Ordering::Greater,
                    (None, None) => left_index.cmp(right_index),
                }
            });
        }
        entries.into_iter().map(|(_, entry)| entry).collect()
    }

    fn can_export(&self) -> bool {
        !self.decoded.is_empty()
    }
}

impl eframe::App for SysconApp {
    fn update(&mut self, context: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_terminal();
        context.request_repaint_after(Duration::from_millis(40));

        egui::TopBottomPanel::top("status").show(context, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.heading(egui::RichText::new("PS3 SYSCON Diagnostic").strong());
                ui.separator();
                ui.label(&self.status);
            });
        });

        egui::CentralPanel::default().show(context, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                let connected = self.connection.is_some();
                ui.columns(2, |columns| {
                    egui::Frame::group(columns[0].style()).show(&mut columns[0], |ui| {
                        ui.set_min_height(220.0);
                        ui.heading(egui::RichText::new("Connection").strong());
                        ui.add_space(2.0);
                        ui.spacing_mut().item_spacing.y = 0.0;
                        panel_row(ui, |ui| {
                            ui.label("SYSCON profile:");
                            let combo_width = (ui.available_width() - 90.0).max(190.0);
                            egui::ComboBox::from_id_salt("syscon_profile")
                                .selected_text(self.profile.label())
                                .width(combo_width)
                                .show_ui(ui, |ui| {
                                    for profile in SysconProfile::ALL {
                                        if ui
                                            .add_enabled(
                                                !connected,
                                                egui::Button::new(profile.menu_label())
                                                    .selected(self.profile == profile),
                                            )
                                            .clicked()
                                        {
                                            self.profile = profile;
                                            self.settings.baud_rate = profile.baud_rate();
                                        }
                                    }
                                });
                            ui.label(format!("{} baud", self.profile.baud_rate()));
                        });
                        panel_row(ui, |ui| {
                            ui.strong("Suggested boards:");
                            ui.add(
                                egui::Label::new(self.profile.suggested_boards()).truncate(),
                            )
                            .on_hover_text(self.profile.suggested_boards());
                        });
                        panel_row(ui, |ui| {
                            ui.label("Serial port:");
                            let selected = self
                                .ports
                                .get(self.selected_port)
                                .map(PortDescriptor::display_name)
                                .unwrap_or_else(|| "No ports found".into());
                            let combo_width = (ui.available_width() - 85.0).max(180.0);
                            egui::ComboBox::from_id_salt("serial_port")
                                .selected_text(selected)
                                .width(combo_width)
                                .show_ui(ui, |ui| {
                                    for (index, port) in self.ports.iter().enumerate() {
                                        if ui
                                            .selectable_value(
                                                &mut self.selected_port,
                                                index,
                                                port.display_name(),
                                            )
                                            .changed()
                                        {
                                            self.settings.port_name = port.name.clone();
                                        }
                                    }
                                });
                            if ui.button("Refresh").clicked() {
                                self.refresh_ports();
                            }
                        });
                        panel_row(ui, |ui| {
                            if ui
                                .add_enabled(!connected, egui::Button::new("Connect serial"))
                                .clicked()
                            {
                                self.connect_serial();
                            }
                            #[cfg(feature = "mock")]
                            if ui
                                .add_enabled(!connected, egui::Button::new("Start offline mock"))
                                .clicked()
                            {
                                self.connect_mock();
                            }
                            if ui
                                .add_enabled(connected, egui::Button::new("Disconnect"))
                                .clicked()
                            {
                                self.disconnect();
                                self.status = "Disconnected".into();
                            }
                        });
                        panel_row(ui, |ui| {
                            const PASSIVE_NOTE: &str = "Connecting remains passive. Auth and Get errors are explicit; write/clear commands are unavailable.";
                            ui.add(egui::Label::new(PASSIVE_NOTE).truncate())
                                .on_hover_text(PASSIVE_NOTE);
                        });
                        panel_row(ui, |ui| {
                            ui.label("Auth attempts");
                            ui.add(egui::DragValue::new(&mut self.auth_attempts).range(1..=10));
                            ui.label("Retry after");
                            ui.add(
                                egui::DragValue::new(&mut self.retry_delay_seconds)
                                    .range(0.2..=15.0)
                                    .speed(0.2)
                                    .suffix(" s"),
                            );
                            let can_auth =
                                connected && !self.operation_busy && !self.allow_transmit;
                            if ui
                                .add_enabled(can_auth, egui::Button::new("Auth"))
                                .clicked()
                            {
                                self.authenticate();
                            }
                            let can_read =
                                self.authenticated && !self.operation_busy && !self.allow_transmit;
                            if ui
                                .add_enabled(can_read, egui::Button::new("Get errors"))
                                .clicked()
                            {
                                self.get_errors();
                            }
                        });
                        panel_row(ui, |ui| {
                            if self.authenticated {
                                ui.colored_label(
                                    egui::Color32::GREEN,
                                    "Authenticated — read-only history access enabled",
                                );
                            } else {
                                ui.label("Get errors stays disabled until Auth succeeds.");
                            }
                        });
                    });

                    egui::Frame::group(columns[1].style()).show(&mut columns[1], |ui| {
                        ui.set_min_height(220.0);
                        ui.heading(egui::RichText::new("Board connection guide").strong());
                        ui.add_space(2.0);
                        ui.spacing_mut().item_spacing.y = 0.0;
                        panel_row(ui, |ui| {
                            ui.label("Motherboard:");
                            let guide = &BOARD_GUIDES[self.selected_board_guide];
                            egui::ComboBox::from_id_salt("motherboard_guide")
                                .selected_text(guide.label)
                                .width(ui.available_width())
                                .show_ui(ui, |ui| {
                                    for (index, guide) in BOARD_GUIDES.iter().enumerate() {
                                        ui.selectable_value(
                                            &mut self.selected_board_guide,
                                            index,
                                            guide.label,
                                        );
                                    }
                                });
                        });
                        let guide = &BOARD_GUIDES[self.selected_board_guide];
                        panel_row(ui, |ui| {
                            ui.add(egui::Label::new(guide.hint).truncate())
                                .on_hover_text(guide.hint);
                        });
                        panel_row(ui, |ui| {
                            ui.hyperlink_to("Open sourced test-pad photograph", guide.url);
                        });
                        panel_row(ui, |ui| {
                            const WIRING_WARNING: &str =
                                "3.3 V TTL only; TX↔RX, GND↔GND; never connect adapter VCC.";
                            ui.add(
                                egui::Label::new(
                                    egui::RichText::new(WIRING_WARNING)
                                        .color(egui::Color32::YELLOW),
                                )
                                .truncate(),
                            )
                            .on_hover_text(WIRING_WARNING);
                        });
                        panel_row(ui, |ui| {
                            const LICENSE_NOTE: &str = "Archived photographs are third-party material, not MIT; provenance is recorded under assets/connection-guides.";
                            ui.add(
                                egui::Label::new(egui::RichText::new(LICENSE_NOTE).small())
                                    .truncate(),
                            )
                            .on_hover_text(LICENSE_NOTE);
                        });
                    });
                });

                ui.separator();
                ui.horizontal(|ui| {
                    ui.heading(egui::RichText::new("Nonblocking terminal").strong());
                    ui.add_space(8.0);
                    self.terminal_state_badge(ui);
                });
                egui::Frame::canvas(ui.style()).show(ui, |ui| {
                    egui::ScrollArea::vertical()
                        .id_salt("terminal_output")
                        .max_height(260.0)
                        .min_scrolled_height(260.0)
                        .auto_shrink([false, false])
                        .stick_to_bottom(true)
                        .show(ui, |ui| {
                            ui.set_min_width(ui.available_width());
                            ui.add(
                                egui::Label::new(
                                    egui::RichText::new(if self.terminal.is_empty() {
                                        " "
                                    } else {
                                        &self.terminal
                                    })
                                    .monospace(),
                                )
                                .selectable(true),
                            );
                        });
                });
                ui.horizontal(|ui| {
                    if ui.button("Clear terminal").clicked() {
                        self.terminal.clear();
                    }
                    let can_toggle_manual =
                        self.connection.is_some() && !self.operation_busy;
                    let manual_toggle = ui.add_enabled(
                        can_toggle_manual,
                        egui::Checkbox::new(
                            &mut self.allow_transmit,
                            "Enable raw transmit (unsafe; off by default)",
                        ),
                    )
                    .on_disabled_hover_text("Connect to serial or start the offline mock first.");
                    if manual_toggle.changed() {
                        self.status = if self.allow_transmit {
                            "Manual transmit enabled — automatic protocol controls are paused".into()
                        } else {
                            "Manual transmit disabled".into()
                        };
                    }
                    ui.add_space(8.0);
                    self.manual_mode_badge(ui);
                });
                ui.horizontal(|ui| {
                    let enabled = self.manual_mode_active();
                    let response = ui.add_enabled(
                        enabled,
                        egui::TextEdit::singleline(&mut self.transmit)
                            .desired_width(500.0)
                            .hint_text("Raw terminal text"),
                    );
                    ui.checkbox(&mut self.append_crlf, "Append CRLF");
                    let enter = response.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter));
                    if ui.add_enabled(enabled, egui::Button::new("Send")).clicked() || enter {
                        self.send_terminal();
                    }
                });

                ui.separator();
                ui.heading(egui::RichText::new("Error-code decoder").strong());
                ui.label("Known meanings are limited to sourced PS3 Developer Wiki entries. Unknown codes receive no guessed interpretation.");
                ui.horizontal(|ui| {
                    let response = ui.add(
                        egui::TextEdit::singleline(&mut self.decoder_input)
                            .desired_width(260.0)
                            .hint_text("A0801001 or 1001"),
                    );
                    let enter = response.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter));
                    if ui.button("Decode and add").clicked() || enter {
                        self.decode_current();
                    }
                    if ui.button("Clear report").clicked() {
                        self.decoded.clear();
                    }
                    ui.label("Order by:");
                    egui::ComboBox::from_id_salt("error_sort_order")
                        .selected_text(self.error_sort_order.label())
                        .show_ui(ui, |ui| {
                            for order in ErrorSortOrder::ALL {
                                ui.selectable_value(
                                    &mut self.error_sort_order,
                                    order,
                                    order.label(),
                                );
                            }
                        });
                    ui.separator();
                    let can_export = self.can_export();
                    if ui
                        .add_enabled(can_export, egui::Button::new("Export"))
                        .on_disabled_hover_text("Add or retrieve at least one error first.")
                        .clicked()
                    {
                        self.export_text();
                    }
                    ui.add_enabled(
                        can_export,
                        egui::TextEdit::singleline(&mut self.export_path)
                            .desired_width(220.0)
                            .hint_text("Output .txt path"),
                    );
                });
                let ordered_entries = self.ordered_decoded_errors();
                egui::Frame::canvas(ui.style()).show(ui, |ui| {
                    egui::ScrollArea::vertical()
                        .id_salt("decoded_error_list")
                        .max_height(260.0)
                        .min_scrolled_height(260.0)
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            if ordered_entries.is_empty() {
                                ui.weak("No decoded errors yet.");
                            }
                            for entry in &ordered_entries {
                                let frame = egui::Frame::group(ui.style());
                                let content_width = (ui.available_width()
                                    - frame.total_margin().sum().x)
                                    .max(240.0);
                                frame.show(ui, |ui| {
                                    ui.set_width(content_width);
                                    ui.horizontal_wrapped(|ui| {
                                        let title = entry.title.as_deref().unwrap_or("unknown");
                                        ui.strong(format!(
                                            "{} — {title}",
                                            entry.normalized_code
                                        ));
                                        if let Some(occurred_at) = &entry.occurred_at {
                                            ui.weak(format!("• {occurred_at}"));
                                        } else if let Some(warning) = &entry.timestamp_warning {
                                            ui.colored_label(
                                                egui::Color32::LIGHT_RED,
                                                format!("• {warning}"),
                                            );
                                        }
                                    });
                                    if entry.known {
                                        if let Some(summary) = &entry.summary {
                                            ui.label(summary);
                                        }
                                        if let Some(source) = &entry.source_url {
                                            ui.hyperlink_to("Source: PS3 Developer Wiki", source);
                                        }
                                    } else {
                                        ui.label("No interpretation is provided.");
                                    }
                                    ui.small(&entry.caution);
                                });
                            }
                        });
                });
                if self
                    .decoded
                    .iter()
                    .any(|entry| entry.timestamp_raw.is_some())
                {
                    ui.small("Times are converted from the SYSCON clock. FFFFFFFF means no valid time; dates around 2005-12-31 can indicate that the console clock was not configured.");
                }
                if !self.error_history.is_empty() {
                    ui.collapsing("Raw error-history records", |ui| {
                        for record in &self.error_history {
                            let slot = record
                                .slot
                                .map(|slot| format!("{slot:02X}"))
                                .unwrap_or_else(|| "--".into());
                            ui.monospace(format!("{slot}: {}", record.raw));
                        }
                    });
                }
                ui.separator();
                ui.small("Protocol scope: authentication and read-only error-history retrieval. EEPROM writes, clearerrlog, power, fan, and voltage commands are intentionally unavailable.");
            });
        });
    }
}

impl Drop for SysconApp {
    fn drop(&mut self) {
        self.disconnect();
    }
}

#[cfg(all(test, feature = "mock"))]
mod tests {
    use super::*;

    #[test]
    fn manual_mode_unlocks_only_with_a_connection_and_changes_state() {
        let mut app = SysconApp::default();
        app.allow_transmit = true;
        assert!(!app.manual_mode_active());
        assert_eq!(app.terminal_state(), TerminalState::Disconnected);

        app.connection = Some(TerminalConnection::mock());
        assert!(app.manual_mode_active());
        assert_eq!(app.terminal_state(), TerminalState::Manual);

        app.operation_busy = true;
        assert_eq!(app.terminal_state(), TerminalState::InProgress);
    }

    #[test]
    fn export_unlocks_only_after_an_error_is_added() {
        let mut app = SysconApp::default();
        assert!(!app.can_export());

        app.decoded
            .push(syscon_diagnostics::decode("1001").unwrap());
        assert!(app.can_export());

        app.decoded.clear();
        assert!(!app.can_export());
    }
}
