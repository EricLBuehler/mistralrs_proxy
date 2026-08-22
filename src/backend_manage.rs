//! Interactive live backend manager.

use std::{
    error::Error,
    io::{self, IsTerminal},
    time::{Duration, Instant},
};

use ratatui::{
    Frame,
    crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    layout::{Constraint, Layout, Margin},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState, Wrap},
};

use crate::{
    backend::BackendMode,
    backend_cli::ControlClient,
    control::{BackendListResponse, BackendView},
};

const REFRESH_INTERVAL: Duration = Duration::from_secs(1);
const INPUT_POLL: Duration = Duration::from_millis(100);

/// Open a terminal UI backed by the running proxy's private control socket.
pub async fn manage(client: ControlClient) -> Result<(), Box<dyn Error>> {
    if !io::stdout().is_terminal() {
        return Err("`backend manage` needs an interactive terminal".into());
    }

    let response = client.list().await?;
    let mut app = App::new(response);
    let mut terminal = ratatui::init();
    let result = app.run(&mut terminal, &client).await;
    ratatui::restore();
    result
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Browse,
    ConfirmDrain,
}

struct App {
    response: BackendListResponse,
    selected: usize,
    mode: Mode,
    status: String,
    last_refresh: Instant,
    quit: bool,
}

impl App {
    fn new(response: BackendListResponse) -> Self {
        Self {
            status: format!(
                "Connected · runtime revision {} · {}",
                response.runtime_revision, response.routing_policy
            ),
            response,
            selected: 0,
            mode: Mode::Browse,
            last_refresh: Instant::now(),
            quit: false,
        }
    }

    async fn run(
        &mut self,
        terminal: &mut ratatui::DefaultTerminal,
        client: &ControlClient,
    ) -> Result<(), Box<dyn Error>> {
        while !self.quit {
            terminal.draw(|frame| self.draw(frame))?;

            if event::poll(INPUT_POLL)?
                && let Event::Key(key) = event::read()?
                && key.kind == KeyEventKind::Press
            {
                if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
                    self.quit = true;
                    continue;
                }
                self.handle(key.code, client).await;
                terminal.draw(|frame| self.draw(frame))?;
            }

            if self.last_refresh.elapsed() >= REFRESH_INTERVAL {
                self.refresh(client, false).await;
            }
        }
        Ok(())
    }

    async fn handle(&mut self, code: KeyCode, client: &ControlClient) {
        if self.mode == Mode::ConfirmDrain {
            if matches!(code, KeyCode::Char('y') | KeyCode::Char('Y')) {
                self.mode = Mode::Browse;
                self.start_drain(client).await;
            } else {
                self.mode = Mode::Browse;
                self.status = "Drain cancelled.".to_owned();
            }
            return;
        }

        match code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.selected = self.selected.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.selected =
                    (self.selected + 1).min(self.response.backends.len().saturating_sub(1));
            }
            KeyCode::Home => self.selected = 0,
            KeyCode::End => self.selected = self.response.backends.len().saturating_sub(1),
            KeyCode::Char('d') => match self
                .selected_backend()
                .map(|backend| (backend.id.clone(), backend.mode))
            {
                Some((id, BackendMode::Active)) => {
                    self.mode = Mode::ConfirmDrain;
                    self.status = format!(
                        "Drain {}? It will stop receiving new requests immediately. y / n",
                        id
                    );
                }
                Some((id, mode)) => {
                    self.status = format!("{id} is already {mode}.");
                }
                None => {}
            },
            KeyCode::Char('a') => self.activate(client).await,
            KeyCode::Char('r') => self.reload(client).await,
            KeyCode::Char('R') => self.refresh(client, true).await,
            KeyCode::Char('q') | KeyCode::Esc => self.quit = true,
            _ => {}
        }
    }

    async fn start_drain(&mut self, client: &ControlClient) {
        let Some(id) = self.selected_backend().map(|backend| backend.id.clone()) else {
            return;
        };
        match client.drain(&id).await {
            Ok(started) => {
                self.status = if started.safe_to_stop {
                    format!("{id} is disabled and safe to stop.")
                } else {
                    format!(
                        "{id} is draining · operation {} · the drain continues if you quit",
                        started.operation_id
                    )
                };
                self.refresh(client, false).await;
            }
            Err(error) => self.status = format!("Could not drain {id}: {error}"),
        }
    }

    async fn activate(&mut self, client: &ControlClient) {
        let Some(id) = self.selected_backend().map(|backend| backend.id.clone()) else {
            return;
        };
        match client.activate(&id).await {
            Ok(response) => {
                self.status = format!("{id}: {}", response.message);
                self.refresh(client, false).await;
            }
            Err(error) => self.status = format!("Could not activate {id}: {error}"),
        }
    }

    async fn reload(&mut self, client: &ControlClient) {
        match client.reload().await {
            Ok(response) => {
                self.status = format!(
                    "Applied runtime revision {} · +{} revived {} updated {} retired {}",
                    response.revision,
                    response.added.len(),
                    response.revived.len(),
                    response.updated.len(),
                    response.retired.len(),
                );
                self.refresh(client, false).await;
            }
            Err(error) => self.status = format!("Runtime reload failed: {error}"),
        }
    }

    async fn refresh(&mut self, client: &ControlClient, announce: bool) {
        let selected_id = self.selected_backend().map(|backend| backend.id.clone());
        match client.list().await {
            Ok(response) => {
                self.response = response;
                self.selected = selected_id
                    .as_deref()
                    .and_then(|id| {
                        self.response
                            .backends
                            .iter()
                            .position(|backend| backend.id == id)
                    })
                    .unwrap_or_else(|| {
                        self.selected
                            .min(self.response.backends.len().saturating_sub(1))
                    });
                if announce {
                    self.status = "Refreshed live backend state.".to_owned();
                }
            }
            Err(error) => self.status = format!("Refresh failed: {error}"),
        }
        self.last_refresh = Instant::now();
    }

    fn selected_backend(&self) -> Option<&BackendView> {
        self.response.backends.get(self.selected)
    }

    fn draw(&self, frame: &mut Frame) {
        let [header, table, detail, help_area, status] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Min(5),
            Constraint::Length(8),
            Constraint::Length(1),
            Constraint::Length(2),
        ])
        .areas(frame.area());

        let title = format!(
            " mistralrs_proxy backends · {} backend{} · rev {} · {} ",
            self.response.backends.len(),
            if self.response.backends.len() == 1 {
                ""
            } else {
                "s"
            },
            self.response.runtime_revision,
            self.response.routing_policy,
        );
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                title,
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ))),
            header,
        );

        let rows = self.response.backends.iter().map(|backend| {
            let style = match backend.mode {
                BackendMode::Disabled => Style::default().fg(Color::DarkGray),
                BackendMode::Draining => Style::default().fg(Color::Yellow),
                BackendMode::Active if backend.eligible => Style::default().fg(Color::Green),
                BackendMode::Active => Style::default().fg(Color::Red),
            };
            Row::new(vec![
                Cell::from(backend.id.clone()),
                Cell::from(backend.mode.to_string()),
                Cell::from(backend.state.to_string()),
                Cell::from(backend.proxy_active.to_string()),
                Cell::from(run_capacity(backend)),
                Cell::from(optional_count(backend.waiting)),
                Cell::from(percent(backend.kv_ratio)),
                Cell::from(decimal(backend.token_rate, 1)),
                Cell::from(decimal(backend.pressure, 2)),
                Cell::from(age(backend.metrics_age_ms)),
            ])
            .style(style)
        });
        let table_widget = Table::new(
            rows,
            [
                Constraint::Length(18),
                Constraint::Length(10),
                Constraint::Length(13),
                Constraint::Length(7),
                Constraint::Length(9),
                Constraint::Length(6),
                Constraint::Length(6),
                Constraint::Length(9),
                Constraint::Length(7),
                Constraint::Min(7),
            ],
        )
        .header(
            Row::new([
                "BACKEND", "MODE", "STATE", "PROXY", "RUN/CAP", "WAIT", "KV%", "TOK/S", "PRESS",
                "AGE",
            ])
            .style(Style::default().add_modifier(Modifier::BOLD | Modifier::UNDERLINED)),
        )
        .row_highlight_style(
            Style::default()
                .bg(Color::Blue)
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");
        let mut table_state = TableState::default()
            .with_selected((!self.response.backends.is_empty()).then_some(self.selected));
        frame.render_stateful_widget(
            table_widget,
            table.inner(Margin::new(1, 0)),
            &mut table_state,
        );

        let details = self.selected_backend().map_or_else(
            || "No configured backends.".to_owned(),
            |backend| {
                format!(
                    "{}\nURL: {}\nreadiness: {} ({})   telemetry: {} ({})   circuit: {}\nproxy active: {}   oldest: {}   engine: {} running / {} waiting / {} capacity\nKV: {}   tokens/s: {}   pressure: {}\n{}{}",
                    backend.id,
                    backend.url,
                    backend.readiness,
                    age(backend.readiness_age_ms),
                    backend.telemetry,
                    age(backend.metrics_age_ms),
                    backend.circuit,
                    backend.proxy_active,
                    age(backend.oldest_proxy_request_ms),
                    optional_count(backend.running),
                    optional_count(backend.waiting),
                    optional_count(backend.effective_capacity),
                    percent(backend.kv_ratio),
                    decimal(backend.token_rate, 1),
                    decimal(backend.pressure, 3),
                    backend
                        .readiness_error
                        .as_deref()
                        .map_or(String::new(), |error| format!("readiness error: {error}\n")),
                    backend
                        .metrics_error
                        .as_deref()
                        .map_or(String::new(), |error| format!("metrics error: {error}")),
                )
            },
        );
        frame.render_widget(
            Paragraph::new(details)
                .block(Block::default().borders(Borders::TOP).title(" selected "))
                .wrap(Wrap { trim: true }),
            detail,
        );

        let help_text = if self.mode == Mode::ConfirmDrain {
            "Drain selected backend? y / n"
        } else {
            "↑/↓ move   d drain   a activate   r reload runtime   R refresh   q quit"
        };
        let help_style = if self.mode == Mode::ConfirmDrain {
            Style::default().fg(Color::Black).bg(Color::Yellow)
        } else {
            Style::default().fg(Color::DarkGray)
        };
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                format!(" {help_text} "),
                help_style,
            ))),
            help_area,
        );
        frame.render_widget(
            Paragraph::new(format!(" {}", self.status))
                .style(Style::default().fg(Color::Yellow))
                .wrap(Wrap { trim: true }),
            status,
        );
    }
}

fn optional_count(value: Option<u64>) -> String {
    value.map_or_else(|| "-".to_owned(), |value| value.to_string())
}

fn run_capacity(backend: &BackendView) -> String {
    match (backend.running, backend.effective_capacity) {
        (Some(running), Some(capacity)) => format!("{running}/{capacity}"),
        _ => "-".to_owned(),
    }
}

fn decimal(value: Option<f64>, precision: usize) -> String {
    value.map_or_else(|| "-".to_owned(), |value| format!("{value:.precision$}"))
}

fn percent(value: Option<f64>) -> String {
    value.map_or_else(|| "-".to_owned(), |value| format!("{:.0}%", value * 100.0))
}

fn age(value: Option<u64>) -> String {
    value.map_or_else(
        || "-".to_owned(),
        |ms| {
            if ms < 1_000 {
                format!("{:.1}s", ms as f64 / 1_000.0)
            } else {
                format!("{:.0}s", ms as f64 / 1_000.0)
            }
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        control::BackendListResponse,
        routing::{BackendDisplayState, CircuitState, ReadinessState, TelemetryState},
    };

    fn backend() -> BackendView {
        BackendView {
            id: "gh200-a".to_owned(),
            url: "http://127.0.0.1:8080".to_owned(),
            mode: BackendMode::Active,
            state: BackendDisplayState::Ready,
            readiness: ReadinessState::Ready,
            telemetry: TelemetryState::Fresh,
            circuit: CircuitState::Closed,
            eligible: true,
            proxy_active: 2,
            oldest_proxy_request_ms: Some(1_500),
            running: Some(3),
            waiting: Some(1),
            reported_capacity: Some(8),
            configured_capacity: None,
            effective_capacity: Some(8),
            capacity_mismatch: false,
            kv_ratio: Some(0.42),
            token_rate: Some(123.4),
            pressure: Some(0.5),
            metrics_age_ms: Some(100),
            readiness_age_ms: Some(200),
            metrics_error: None,
            readiness_error: None,
        }
    }

    fn app() -> App {
        App::new(BackendListResponse {
            runtime_revision: 7,
            routing_policy: "least-pressure-v1".to_owned(),
            backends: vec![backend()],
        })
    }

    #[test]
    fn view_includes_routing_and_capacity_signals() {
        let app = app();
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(120, 18)).unwrap();
        terminal.draw(|frame| app.draw(frame)).unwrap();
        let screen = terminal.backend().to_string();

        assert!(screen.contains("least-pressure-v1"), "{screen}");
        assert!(screen.contains("gh200-a"), "{screen}");
        assert!(screen.contains("RUN/CAP"), "{screen}");
        assert!(screen.contains("3/8"), "{screen}");
        assert!(screen.contains("42%"), "{screen}");
        assert!(screen.contains("closed"), "{screen}");
    }

    #[test]
    fn drain_requires_confirmation() {
        let mut app = app();
        app.mode = Mode::ConfirmDrain;

        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(100, 18)).unwrap();
        terminal.draw(|frame| app.draw(frame)).unwrap();
        let screen = terminal.backend().to_string();

        assert!(screen.contains("Drain selected backend? y / n"), "{screen}");
    }
}
