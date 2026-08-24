//! The `logs` explorer.
//!
//! A read-only view over the JSONL audit log that refreshes while `serve` keeps
//! appending to it.

use std::{
    error::Error,
    io::{self, IsTerminal},
    path::{Path, PathBuf},
    time::Duration,
};

use ratatui::{
    Frame,
    crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    layout::{Constraint, Layout, Margin, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Cell, Paragraph, Row, Table, TableState, Tabs},
};

use super::{
    LogRecord, Summary, Tail, distribution_p95, duration, filter, percentile_rows, summarize,
    thousands, truncate,
};

/// How often to look for newly appended records.
const REFRESH: Duration = Duration::from_millis(400);

/// Run the explorer until the operator quits.
pub fn explore(path: &Path, tail: Tail, records: Vec<LogRecord>) -> Result<(), Box<dyn Error>> {
    if !io::stdout().is_terminal() {
        return Err("`logs` needs an interactive terminal; pass --summary instead".into());
    }

    let mut app = App::new(path.to_path_buf(), tail, records);
    let mut terminal = ratatui::init();
    let result = app.run(&mut terminal);
    ratatui::restore();
    result?;

    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum View {
    Summary,
    Backends,
    Requests,
}

impl View {
    const ALL: [Self; 3] = [Self::Summary, Self::Backends, Self::Requests];

    const fn title(self) -> &'static str {
        match self {
            Self::Summary => "Summary",
            Self::Backends => "Backends",
            Self::Requests => "Requests",
        }
    }

    const fn next(self) -> Self {
        match self {
            Self::Summary => Self::Backends,
            Self::Backends => Self::Requests,
            Self::Requests => Self::Summary,
        }
    }
}

struct App {
    path: PathBuf,
    tail: Tail,
    records: Vec<LogRecord>,
    summary: Summary,
    view: View,
    /// Index into the currently filtered, newest-first list.
    selected: usize,
    /// Request id of the selected row, so a refresh keeps it selected.
    selected_id: Option<String>,
    needle: String,
    editing_filter: bool,
    errors_only: bool,
    /// Horizontal scroll offset for the tables of the current view; clamped
    /// at draw time, a no-op when the table fits.
    table_scroll: u16,
    status: String,
    quit: bool,
}

impl App {
    fn new(path: PathBuf, tail: Tail, records: Vec<LogRecord>) -> Self {
        let summary = summarize(&records);
        let status = format!("Loaded {} records", thousands(records.len() as u64));

        Self {
            path,
            tail,
            records,
            summary,
            view: View::Summary,
            selected: 0,
            selected_id: None,
            needle: String::new(),
            editing_filter: false,
            errors_only: false,
            table_scroll: 0,
            status,
            quit: false,
        }
    }

    fn run(&mut self, terminal: &mut ratatui::DefaultTerminal) -> io::Result<()> {
        while !self.quit {
            terminal.draw(|frame| self.draw(frame))?;
            if event::poll(REFRESH)? {
                if let Event::Key(key) = event::read()? {
                    if key.kind != KeyEventKind::Press {
                        continue;
                    }
                    if key.modifiers.contains(KeyModifiers::CONTROL)
                        && key.code == KeyCode::Char('c')
                    {
                        self.quit = true;
                        continue;
                    }
                    self.handle(key.code);
                }
            } else {
                self.refresh();
            }
        }

        Ok(())
    }

    /// Pull in whatever the proxy has appended since the last look.
    fn refresh(&mut self) {
        match self.tail.poll() {
            Ok(appended) => {
                if appended.restarted {
                    self.records.clear();
                    self.status = "Log file shrank; reread from the start.".to_owned();
                }
                if appended.restarted || !appended.records.is_empty() {
                    self.records.extend(appended.records);
                    self.summary = summarize(&self.records);
                    self.resolve_selection();
                }
            }
            Err(error) => self.status = format!("Could not read the log: {error}"),
        }
    }

    /// Keep the same record highlighted across refreshes, since new records
    /// arrive at the top of a newest-first list.
    fn resolve_selection(&mut self) {
        let Some(id) = self.selected_id.clone() else {
            self.selected = 0;
            return;
        };
        self.selected = self
            .visible()
            .iter()
            .position(|record| record.request_id == id)
            .unwrap_or(0);
    }

    /// The filtered records, newest first.
    fn visible(&self) -> Vec<&LogRecord> {
        let mut visible = filter(&self.records, &self.needle, self.errors_only);
        visible.reverse();

        visible
    }

    fn handle(&mut self, code: KeyCode) {
        if self.editing_filter {
            match code {
                KeyCode::Char(character) => self.needle.push(character),
                KeyCode::Backspace => {
                    self.needle.pop();
                }
                KeyCode::Enter => {
                    self.editing_filter = false;
                    self.status = if self.needle.is_empty() {
                        "Filter cleared.".to_owned()
                    } else {
                        format!("Filtering on {:?}.", self.needle)
                    };
                }
                KeyCode::Esc => {
                    self.editing_filter = false;
                    self.needle.clear();
                    self.status = "Filter cleared.".to_owned();
                }
                _ => return,
            }
            self.select(0);
            return;
        }

        let last = self.visible().len().saturating_sub(1);
        match code {
            KeyCode::Tab => self.view = self.view.next(),
            KeyCode::Left | KeyCode::Char('h') => {
                self.table_scroll =
                    self.table_scroll.saturating_sub(crate::render::SCROLL_STEP);
            }
            KeyCode::Right | KeyCode::Char('l') => {
                self.table_scroll =
                    self.table_scroll.saturating_add(crate::render::SCROLL_STEP);
            }
            KeyCode::Char('1') => self.view = View::Summary,
            KeyCode::Char('2') => self.view = View::Backends,
            KeyCode::Char('3') => self.view = View::Requests,
            KeyCode::Up | KeyCode::Char('k') => self.select(self.selected.saturating_sub(1)),
            KeyCode::Down | KeyCode::Char('j') => self.select((self.selected + 1).min(last)),
            KeyCode::PageUp => self.select(self.selected.saturating_sub(10)),
            KeyCode::PageDown => self.select((self.selected + 10).min(last)),
            KeyCode::Home | KeyCode::Char('g') => self.select(0),
            KeyCode::End | KeyCode::Char('G') => self.select(last),
            KeyCode::Char('/') => {
                self.editing_filter = true;
                self.view = View::Requests;
                self.status = "Type to filter; Enter to keep, Esc to clear.".to_owned();
            }
            KeyCode::Char('e') => {
                self.errors_only = !self.errors_only;
                self.view = View::Requests;
                self.status = if self.errors_only {
                    "Showing errors and incomplete requests only.".to_owned()
                } else {
                    "Showing all requests.".to_owned()
                };
                self.select(0);
            }
            KeyCode::Char('r') => {
                self.refresh();
                self.status = format!("{} records", thousands(self.records.len() as u64));
            }
            KeyCode::Char('q') | KeyCode::Esc => self.quit = true,
            _ => {}
        }
    }

    fn select(&mut self, index: usize) {
        let (selected, id) = {
            let visible = self.visible();
            let selected = index.min(visible.len().saturating_sub(1));
            let id = visible
                .get(selected)
                .map(|record| record.request_id.clone());
            (selected, id)
        };
        self.selected = selected;
        self.selected_id = id;
    }

    fn draw(&self, frame: &mut Frame) {
        let [header, tabs, body, footer, status] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(5),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .areas(frame.area());

        let title = format!(
            " mistralrs_proxy logs · {} request{}{} · {} ",
            thousands(self.records.len() as u64),
            if self.records.len() == 1 { "" } else { "s" },
            if self.tail.malformed > 0 {
                format!(" · {} unreadable", self.tail.malformed)
            } else {
                String::new()
            },
            self.path.display(),
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

        frame.render_widget(
            Tabs::new(View::ALL.map(View::title).to_vec())
                .select(View::ALL.iter().position(|view| *view == self.view))
                .highlight_style(
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )
                .divider(" "),
            tabs,
        );

        match self.view {
            View::Summary => self.draw_summary(frame, body),
            View::Backends => self.draw_backends(frame, body),
            View::Requests => self.draw_requests(frame, body),
        }

        let help = if self.editing_filter {
            format!("filter: {}_", self.needle)
        } else {
            let scope = match (self.needle.is_empty(), self.errors_only) {
                (true, false) => String::new(),
                (true, true) => "  [errors only]".to_owned(),
                (false, false) => format!("  [/{}]", self.needle),
                (false, true) => format!("  [/{} + errors]", self.needle),
            };
            format!("tab views   ↑/↓ move   ←/→ scroll   / filter   e errors   r refresh   q quit{scope}")
        };
        let help_style = if self.editing_filter {
            Style::default().fg(Color::Black).bg(Color::Yellow)
        } else {
            Style::default().fg(Color::DarkGray)
        };
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(format!(" {help} "), help_style))),
            footer,
        );

        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                format!(" {}", self.status),
                Style::default().fg(Color::Yellow),
            ))),
            status,
        );
    }

    fn draw_summary(&self, frame: &mut Frame, area: Rect) {
        let summary = &self.summary;
        let window = match (&summary.first_at, &summary.last_at) {
            (Some(first), Some(last)) => format!("{first}  to  {last}"),
            _ => "no requests recorded yet".to_owned(),
        };
        let overview = vec![
            Line::from(vec![label("window   "), Span::raw(window)]),
            Line::from(vec![
                label("requests "),
                Span::raw(format!(
                    "{}   authorized {}   rejected {}   incomplete {}",
                    thousands(summary.requests as u64),
                    summary.authorized,
                    summary.rejected,
                    summary.incomplete,
                )),
            ]),
            Line::from(vec![
                label("statuses "),
                Span::raw(format!(
                    "2xx {}   3xx {}   4xx {}   5xx {}   none {}",
                    summary.successful,
                    summary.redirected,
                    summary.client_errors,
                    summary.server_errors,
                    summary.no_status,
                )),
            ]),
            Line::from(vec![
                label("tokens   "),
                Span::raw(format!(
                    "{} in   {} out   {} total",
                    thousands(summary.input_tokens),
                    thousands(summary.output_tokens),
                    thousands(summary.input_tokens + summary.output_tokens),
                )),
            ]),
            Line::from(vec![
                label("cache    "),
                Span::raw(format!(
                    "{} cached   {} of input   {} prefilled",
                    thousands(summary.cached_tokens),
                    summary
                        .cache_hit_pct()
                        .map_or_else(|| "-".to_owned(), |pct| format!("{pct:.1}%")),
                    thousands(summary.prefilled_tokens),
                )),
            ]),
            Line::from(vec![
                label("shape    "),
                Span::raw(format!(
                    "{} streaming   {} non-streaming",
                    thousands(summary.streaming as u64),
                    thousands(summary.non_streaming as u64),
                )),
            ]),
        ];

        let rows = percentile_rows(summary);
        let [overview_area, percentiles_area, keys_area, paths_area] = Layout::vertical([
            Constraint::Length(overview.len() as u16 + 1),
            Constraint::Length(rows.len() as u16 + 2),
            Constraint::Fill(1),
            Constraint::Fill(1),
        ])
        .areas(area);

        frame.render_widget(
            Paragraph::new(overview),
            overview_area.inner(Margin::new(1, 0)),
        );

        let percentiles = Table::new(
            rows.into_iter().map(|(name, row)| {
                Row::new(vec![
                    Cell::from(name).style(Style::default().fg(Color::DarkGray)),
                    Cell::from(row.p50),
                    Cell::from(row.p95),
                    Cell::from(row.max),
                    Cell::from(row.samples).style(Style::default().fg(Color::DarkGray)),
                ])
            }),
            [
                Constraint::Length(20),
                Constraint::Length(12),
                Constraint::Length(12),
                Constraint::Length(12),
                Constraint::Min(9),
            ],
        )
        .header(
            Row::new(vec!["", "P50", "P95", "MAX", "SAMPLES"])
                .style(Style::default().add_modifier(Modifier::BOLD | Modifier::UNDERLINED)),
        );
        frame.render_widget(percentiles, percentiles_area.inner(Margin::new(1, 0)));

        let key_rows = summary.by_key.iter().map(|(name, totals)| {
            Row::new(vec![
                Cell::from(truncate(name, 22)),
                Cell::from(thousands(totals.requests as u64)),
                Cell::from(thousands(totals.input_tokens)),
                Cell::from(thousands(totals.cached_tokens)),
                Cell::from(thousands(totals.prefilled_tokens)),
                Cell::from(thousands(totals.output_tokens)),
                Cell::from(totals.errors.to_string()),
            ])
        });
        {
            let mut state = TableState::default();
            crate::render::render_scrolled_table(
                frame,
                totals_table(key_rows, "KEY"),
                keys_area.inner(Margin::new(1, 0)),
                TOTALS_TABLE_WIDTH,
                self.table_scroll,
                &mut state,
            );
        }

        let path_rows = summary.by_path.iter().map(|(path, totals)| {
            Row::new(vec![
                Cell::from(truncate(path, 22)),
                Cell::from(thousands(totals.requests as u64)),
                Cell::from(thousands(totals.input_tokens)),
                Cell::from(thousands(totals.cached_tokens)),
                Cell::from(thousands(totals.prefilled_tokens)),
                Cell::from(thousands(totals.output_tokens)),
                Cell::from(totals.errors.to_string()),
            ])
        });
        {
            let mut state = TableState::default();
            crate::render::render_scrolled_table(
                frame,
                totals_table(path_rows, "ENDPOINT"),
                paths_area.inner(Margin::new(1, 0)),
                TOTALS_TABLE_WIDTH,
                self.table_scroll,
                &mut state,
            );
        }
    }

    fn draw_backends(&self, frame: &mut Frame, area: Rect) {
        let routed: usize = self
            .summary
            .by_backend
            .iter()
            .map(|(_, totals)| totals.requests)
            .sum();
        let [overview_area, table_area] =
            Layout::vertical([Constraint::Length(3), Constraint::Min(4)]).areas(area);
        frame.render_widget(
            Paragraph::new(vec![
                Line::from(vec![
                    label("routed   "),
                    Span::raw(format!(
                        "{} request{} across {} backend{}",
                        thousands(routed as u64),
                        if routed == 1 { "" } else { "s" },
                        self.summary.by_backend.len(),
                        if self.summary.by_backend.len() == 1 {
                            ""
                        } else {
                            "s"
                        },
                    )),
                ]),
                Line::from(Span::styled(
                    "Historical request share and latency from proxy.jsonl",
                    Style::default().fg(Color::DarkGray),
                )),
            ]),
            overview_area.inner(Margin::new(1, 0)),
        );

        let rows = self.summary.by_backend.iter().map(|(backend, totals)| {
            let share = if routed == 0 {
                0.0
            } else {
                totals.requests as f64 * 100.0 / routed as f64
            };
            Row::new(vec![
                Cell::from(truncate(backend, 23)),
                Cell::from(thousands(totals.requests as u64)),
                Cell::from(format!("{share:.1}%")),
                Cell::from(thousands(totals.input_tokens)),
                Cell::from(thousands(totals.cached_tokens)),
                Cell::from(thousands(totals.prefilled_tokens)),
                Cell::from(thousands(totals.output_tokens)),
                Cell::from(totals.errors.to_string()),
                Cell::from(distribution_p95(totals.queue_ms)),
                Cell::from(distribution_p95(totals.first_byte_ms)),
                Cell::from(distribution_p95(totals.latency_ms)),
            ])
        });
        let table = Table::new(
            rows,
            [
                Constraint::Length(24),
                Constraint::Length(10),
                Constraint::Length(9),
                Constraint::Length(12),
                Constraint::Length(12),
                Constraint::Length(12),
                Constraint::Length(12),
                Constraint::Length(9),
                Constraint::Length(11),
                Constraint::Length(11),
                Constraint::Min(11),
            ],
        )
        .header(
            Row::new([
                "BACKEND", "REQUESTS", "SHARE", "IN", "CACHED", "PREFILLED", "OUT", "ERRORS",
                "QUEUE95", "TTFB95", "LATENCY95",
            ])
            .style(Style::default().add_modifier(Modifier::BOLD | Modifier::UNDERLINED)),
        );
        let mut state = TableState::default();
        crate::render::render_scrolled_table(
            frame,
            table,
            table_area.inner(Margin::new(1, 0)),
            BACKENDS_TABLE_WIDTH,
            self.table_scroll,
            &mut state,
        );
    }

    fn draw_requests(&self, frame: &mut Frame, area: Rect) {
        let visible = self.visible();
        let [table_area, detail_area] =
            Layout::vertical([Constraint::Min(4), Constraint::Length(9)]).areas(area);

        let rows = visible.iter().map(|record| {
            Row::new(vec![
                Cell::from(clock(&record.started_at)),
                Cell::from(record.method.clone()),
                Cell::from(truncate(record.path(), 27)),
                Cell::from(truncate(&record.principal(), 21)),
                Cell::from(truncate(record.backend_id.as_deref().unwrap_or("-"), 15)),
                Cell::from(
                    record
                        .status
                        .map_or_else(|| "---".to_owned(), |status| status.to_string()),
                ),
                Cell::from(duration(record.duration_ms)),
                Cell::from(tokens(record.input_tokens)),
                Cell::from(tokens(record.cached_tokens)),
                Cell::from(tokens(record.output_tokens)),
            ])
            .style(status_style(record))
        });
        let table = Table::new(
            rows,
            [
                Constraint::Length(12),
                Constraint::Length(6),
                Constraint::Length(24),
                Constraint::Length(19),
                Constraint::Length(16),
                Constraint::Length(6),
                Constraint::Length(8),
                Constraint::Length(8),
                Constraint::Length(8),
                Constraint::Min(8),
            ],
        )
        .header(
            Row::new(vec![
                "TIME", "METHOD", "ENDPOINT", "KEY", "BACKEND", "STATUS", "TOOK", "IN", "CACHED",
                "OUT",
            ])
            .style(Style::default().add_modifier(Modifier::BOLD | Modifier::UNDERLINED)),
        )
        .row_highlight_style(
            Style::default()
                .bg(Color::Blue)
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ")
        .block(Block::new());

        // `then` rather than `then_some`: the index must not be computed when
        // the list is empty.
        let mut state = TableState::default()
            .with_selected((!visible.is_empty()).then(|| self.selected.min(visible.len() - 1)));
        crate::render::render_scrolled_table(
            frame,
            table,
            table_area.inner(Margin::new(1, 0)),
            REQUESTS_TABLE_WIDTH,
            self.table_scroll,
            &mut state,
        );

        let detail = match visible.get(self.selected.min(visible.len().saturating_sub(1))) {
            Some(record) => detail_lines(record),
            None => vec![Line::from(Span::styled(
                "no records match",
                Style::default().fg(Color::DarkGray),
            ))],
        };
        frame.render_widget(
            Paragraph::new(detail).block(
                Block::new()
                    .title(" selected request ")
                    .borders(ratatui::widgets::Borders::TOP)
                    .border_style(Style::default().fg(Color::DarkGray)),
            ),
            detail_area.inner(Margin::new(1, 0)),
        );
    }
}

fn totals_table<'a>(rows: impl IntoIterator<Item = Row<'a>>, first: &'a str) -> Table<'a> {
    Table::new(
        rows,
        [
            Constraint::Length(22),
            Constraint::Length(10),
            Constraint::Length(12),
            Constraint::Length(12),
            Constraint::Length(12),
            Constraint::Length(12),
            Constraint::Min(8),
        ],
    )
    .header(
        Row::new(vec![
            first, "REQUESTS", "IN", "CACHED", "PREFILLED", "OUT", "ERRORS",
        ])
        .style(Style::default().add_modifier(Modifier::BOLD | Modifier::UNDERLINED)),
    )
}

/// Natural widths of the TUI tables (columns + 1px spacing + the 2px
/// highlight-symbol slot). They are rendered off-screen and blitted as a
/// scrollable window, so they stay intact below their natural width.
const TOTALS_TABLE_WIDTH: u16 = 96;
const BACKENDS_TABLE_WIDTH: u16 = 145;
const REQUESTS_TABLE_WIDTH: u16 = 126;

fn detail_lines(record: &LogRecord) -> Vec<Line<'static>> {
    let unknown = |value: &Option<String>| value.clone().unwrap_or_else(|| "-".to_owned());

    vec![
        Line::from(vec![
            label("id      "),
            Span::raw(record.request_id.clone()),
            label("   started "),
            Span::raw(record.started_at.clone()),
        ]),
        Line::from(vec![
            label("request "),
            Span::raw(format!(
                "{} {}  {}  from {}:{}",
                record.method,
                record.uri,
                record.http_version,
                record.client_ip,
                record.client_port
            )),
        ]),
        Line::from(vec![
            label("key     "),
            Span::raw(format!(
                "{}  digest {}  admin {}",
                record.principal(),
                record
                    .key_sha256
                    .as_deref()
                    .map_or("-", |digest| &digest[..16.min(digest.len())]),
                record
                    .key_admin
                    .map_or_else(|| "-".to_owned(), |admin| admin.to_string()),
            )),
        ]),
        Line::from(vec![
            label("outcome "),
            Span::styled(
                format!(
                    "{}  {}  {}",
                    record
                        .status
                        .map_or_else(|| "no status".to_owned(), |status| status.to_string()),
                    record.termination,
                    unknown(&record.auth_error),
                ),
                status_style(record),
            ),
        ]),
        Line::from(vec![
            label("tokens  "),
            Span::raw(format!(
                "{} in   {} out   {} total   {}",
                tokens(record.input_tokens),
                tokens(record.output_tokens),
                tokens(record.total_tokens),
                match (record.cached_tokens, record.input_tokens) {
                    (Some(cached), Some(input)) if input > 0 => format!(
                        "{cached} cached ({}% of input)",
                        100 * cached / input
                    ),
                    (Some(cached), _) => format!("{cached} cached"),
                    (None, _) => "no cache data".to_owned(),
                },
            )),
        ]),
        Line::from(vec![
            label("timing  "),
            Span::raw(format!(
                "{} total   first byte {}   {}   {} bytes out   {} bytes in",
                duration(record.duration_ms),
                record
                    .time_to_first_byte_ms
                    .map_or_else(|| "-".to_owned(), duration),
                if record.streaming {
                    "streaming"
                } else {
                    "non-streaming"
                },
                thousands(record.response_bytes),
                record
                    .request_content_length
                    .map_or_else(|| "-".to_owned(), thousands),
            )),
        ]),
        Line::from(vec![
            label("routing "),
            Span::raw(format!(
                "{} via {} ({})   eligible {}   pressure {}   queue {}",
                record.backend_id.as_deref().unwrap_or("-"),
                record.routing_policy.as_deref().unwrap_or("-"),
                record.routing_reason.as_deref().unwrap_or("-"),
                record
                    .eligible_backend_count
                    .map_or_else(|| "-".to_owned(), |count| count.to_string()),
                record
                    .backend_pressure_at_dispatch
                    .map_or_else(|| "-".to_owned(), |value| format!("{value:.3}")),
                record
                    .proxy_queue_ms
                    .map_or_else(|| "-".to_owned(), duration),
            )),
        ]),
        Line::from(vec![
            label("client  "),
            Span::raw(truncate(record.user_agent.as_deref().unwrap_or("-"), 96)),
        ]),
    ]
}

fn label(text: &'static str) -> Span<'static> {
    Span::styled(text, Style::default().fg(Color::DarkGray))
}

/// Just the `HH:MM:SS.mmm` of an ISO-8601 timestamp.
fn clock(started_at: &str) -> String {
    match started_at.split_once('T') {
        Some((_, time)) => time.trim_end_matches('Z').to_owned(),
        None => started_at.to_owned(),
    }
}

fn tokens(count: Option<u64>) -> String {
    count.map_or_else(|| "-".to_owned(), thousands)
}

fn status_style(record: &LogRecord) -> Style {
    if !record.complete {
        return Style::default().fg(Color::Magenta);
    }
    match record.status.map(|status| status / 100) {
        Some(2) => Style::default(),
        Some(3) => Style::default().fg(Color::Cyan),
        Some(4) => Style::default().fg(Color::Yellow),
        Some(_) => Style::default().fg(Color::Red),
        None => Style::default().fg(Color::Magenta),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app_with(lines: &str) -> App {
        let path =
            std::env::temp_dir().join(format!("proxy-explore-{}.jsonl", uuid::Uuid::new_v4()));
        std::fs::write(&path, lines).unwrap();
        let mut tail = Tail::new(&path);
        let records = tail.poll().unwrap().records;
        std::fs::remove_file(&path).unwrap();

        App::new(path, tail, records)
    }

    fn sample_app() -> App {
        app_with(concat!(
            r#"{"request_id":"aaaaaaaa-0000-0000-0000-000000000001","started_at":"2026-08-20T10:00:00.000Z","started_at_unix_ms":1,"duration_ms":120,"method":"POST","uri":"/v1/chat/completions","key_name":"alice","key_identifier":"AAAAAAAA","key_sha256":"aa11bb22cc33dd44ee55ff66aa77bb88cc99dd00ee11ff22aa33bb44cc55dd66","key_admin":true,"backend_id":"gh200-a","routing_policy":"least-pressure-v1","routing_reason":"fresh_metrics_lowest_pressure","eligible_backend_count":2,"backend_pressure_at_dispatch":0.25,"proxy_queue_ms":1,"status":200,"authorized":true,"streaming":true,"input_tokens":1234,"output_tokens":56,"cached_tokens":500,"response_bytes":900,"complete":true,"termination":"complete","client_ip":"127.0.0.1","client_port":5000,"http_version":"HTTP/1.1","user_agent":"openai-python/1.2.3","time_to_first_byte_ms":40}"#,
            "\n",
            r#"{"request_id":"bbbbbbbb-0000-0000-0000-000000000002","started_at":"2026-08-20T10:00:05.000Z","started_at_unix_ms":2,"duration_ms":3000,"method":"GET","uri":"/v1/models","status":401,"authorized":false,"auth_error":"invalid_api_key","complete":true,"termination":"complete","client_ip":"127.0.0.1","client_port":5001}"#,
            "\n",
        ))
    }

    fn rendered(app: &App) -> String {
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(120, 26)).unwrap();
        terminal.draw(|frame| app.draw(frame)).unwrap();

        terminal.backend().to_string()
    }

    #[test]
    fn the_summary_view_shows_totals_and_breakdowns() {
        let screen = rendered(&sample_app());

        assert!(screen.contains("Summary"), "{screen}");
        assert!(screen.contains("requests"), "{screen}");
        assert!(screen.contains("1,234 in"), "{screen}");
        assert!(screen.contains("alice"), "{screen}");
        assert!(screen.contains("(unauthenticated)"), "{screen}");
        assert!(screen.contains("/v1/chat/completions"), "{screen}");
        assert!(screen.contains("2 requests"), "{screen}");
        assert!(screen.contains("P50"), "{screen}");
        assert!(screen.contains("first token"), "{screen}");
        assert!(screen.contains("per output token"), "{screen}");
        assert!(screen.contains("1 streaming"), "{screen}");
        assert!(screen.contains("500 cached"), "{screen}");
        assert!(screen.contains("40.5% of input"), "{screen}");
        assert!(screen.contains("734 prefilled"), "{screen}");
        assert!(screen.contains("cache hit %"), "{screen}");
    }

    #[test]
    fn the_backends_view_shows_routing_share_and_latency() {
        let mut app = sample_app();
        app.handle(KeyCode::Char('2'));

        // At the default scroll the left and middle columns are in view...
        let screen = rendered(&app);

        assert!(screen.contains("Backends"), "{screen}");
        assert!(screen.contains("gh200-a"), "{screen}");
        assert!(screen.contains("100.0%"), "{screen}");
        assert!(screen.contains("CACHED"), "{screen}");
        assert!(screen.contains("PREFILLED"), "{screen}");
        assert!(!screen.contains("LATENCY95"), "{screen}");

        // ...and the latency columns on the right need a scroll.
        app.table_scroll = u16::MAX;

        let screen = rendered(&app);

        assert!(screen.contains("QUEUE95"), "{screen}");
        assert!(screen.contains("TTFB95"), "{screen}");
        assert!(screen.contains("LATENCY95"), "{screen}");
        assert!(!screen.contains("gh200-a"), "{screen}");
    }

    #[test]
    fn the_requests_view_lists_rows_and_details_the_selection() {
        let mut app = sample_app();
        app.handle(KeyCode::Char('3'));

        let screen = rendered(&app);

        assert!(screen.contains("ENDPOINT"), "{screen}");
        assert!(screen.contains("10:00:05.000"), "{screen}");
        assert!(screen.contains("alice[AAAAAAAA]"), "{screen}");
        assert!(screen.contains("selected request"), "{screen}");
        // Newest first, so the 401 is selected and detailed.
        assert!(
            screen.contains("bbbbbbbb-0000-0000-0000-000000000002"),
            "{screen}"
        );
        assert!(screen.contains("invalid_api_key"), "{screen}");
    }

    #[test]
    fn moving_down_selects_the_older_record() {
        let mut app = sample_app();
        app.handle(KeyCode::Char('3'));
        app.handle(KeyCode::Down);

        let screen = rendered(&app);

        assert_eq!(app.selected, 1);
        assert!(screen.contains("openai-python/1.2.3"), "{screen}");
        assert!(screen.contains("streaming"), "{screen}");
        assert!(screen.contains("1,234 in"), "{screen}");
    }

    #[test]
    fn a_filter_narrows_the_list_and_survives_editing() {
        let mut app = sample_app();
        app.handle(KeyCode::Char('/'));
        for character in "alice".chars() {
            app.handle(KeyCode::Char(character));
        }

        assert!(app.editing_filter);
        assert_eq!(app.visible().len(), 1);

        app.handle(KeyCode::Enter);
        assert!(!app.editing_filter);
        assert_eq!(app.visible().len(), 1);

        app.handle(KeyCode::Char('/'));
        app.handle(KeyCode::Esc);
        assert!(app.needle.is_empty());
        assert_eq!(app.visible().len(), 2);
    }

    #[test]
    fn the_errors_toggle_keeps_only_failures() {
        let mut app = sample_app();

        app.handle(KeyCode::Char('e'));
        assert!(app.errors_only);
        let visible = app.visible();
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].status, Some(401));

        app.handle(KeyCode::Char('e'));
        assert_eq!(app.visible().len(), 2);
    }

    #[test]
    fn an_empty_log_renders_without_panicking() {
        let mut app = app_with("");
        app.handle(KeyCode::Char('3'));

        let screen = rendered(&app);

        assert!(screen.contains("no records match"), "{screen}");
        assert!(screen.contains("0 requests"), "{screen}");
    }

    #[test]
    fn tab_cycles_the_views_and_q_quits() {
        let mut app = sample_app();
        assert_eq!(app.view, View::Summary);

        app.handle(KeyCode::Tab);
        assert_eq!(app.view, View::Backends);
        app.handle(KeyCode::Tab);
        assert_eq!(app.view, View::Requests);
        app.handle(KeyCode::Tab);
        assert_eq!(app.view, View::Summary);

        app.handle(KeyCode::Char('q'));
        assert!(app.quit);
    }

    #[test]
    fn a_refresh_keeps_the_selected_record_highlighted() {
        let path =
            std::env::temp_dir().join(format!("proxy-explore-{}.jsonl", uuid::Uuid::new_v4()));
        std::fs::write(
            &path,
            "{\"request_id\":\"old\",\"status\":200,\"complete\":true}\n",
        )
        .unwrap();
        let mut tail = Tail::new(&path);
        let records = tail.poll().unwrap().records;
        let mut app = App::new(path.clone(), tail, records);
        app.handle(KeyCode::Char('3'));
        app.select(0);
        assert_eq!(app.selected_id.as_deref(), Some("old"));

        // The proxy appends a newer record, which lands above the selection.
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        std::io::Write::write_all(
            &mut file,
            b"{\"request_id\":\"new\",\"status\":200,\"complete\":true}\n",
        )
        .unwrap();
        drop(file);
        app.refresh();
        std::fs::remove_file(&path).unwrap();

        assert_eq!(app.records.len(), 2);
        assert_eq!(app.selected, 1, "the selection should follow its record");
        assert_eq!(app.visible()[app.selected].request_id, "old");
    }
}

