//! The `key create` and `key manage` subcommands.

use std::{
    error::Error,
    io::{self, IsTerminal},
    path::Path,
};

use ratatui::{
    Frame,
    crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    layout::{Constraint, Layout, Margin},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Cell, Paragraph, Row, Table, TableState},
};

use crate::{
    keys::{KeyFile, KeyRecord},
    logging::format_timestamp,
};

/// Issue a key, append it to the database, and print it once.
///
/// The first key written to a new database is always an admin key so the file
/// is never left without one.
pub fn create(path: &Path, name: &str, admin: bool) -> Result<(), Box<dyn Error>> {
    let name = name.trim();
    if name.is_empty() {
        return Err("a key name cannot be empty".into());
    }

    let mut file = KeyFile::load_or_default(path)?;
    if file.keys.iter().any(|key| key.name == name) {
        return Err(format!("a key named {name:?} already exists in {}", path.display()).into());
    }

    let admin = admin || file.keys.is_empty();
    let (record, key) = KeyRecord::generate(name, admin)?;
    let identifier = record.identifier.clone();
    file.keys.push(record);
    file.save(path)?;

    crate::logs::write_lines(&[
        key,
        String::new(),
        format!("  name        {name}"),
        format!("  identifier  {identifier}"),
        format!("  admin       {admin}"),
        format!("  stored in   {}", path.display()),
        String::new(),
        "This is the only time the key is shown; only its digest is stored.".to_owned(),
        "Key created. Restart mistralrs_proxy to apply changes.".to_owned(),
    ])?;

    Ok(())
}

/// Open the interactive key manager.
pub fn manage(path: &Path) -> Result<(), Box<dyn Error>> {
    let file = KeyFile::load_or_default(path)?;
    if file.keys.is_empty() {
        return Err(format!(
            "no keys in {}; run `mistralrs_proxy key create <name>` first",
            path.display()
        )
        .into());
    }
    if !io::stdout().is_terminal() {
        return Err("`key manage` needs an interactive terminal".into());
    }

    let mut app = App::new(file, path);
    let mut terminal = ratatui::init();
    let result = app.run(&mut terminal);
    ratatui::restore();
    result?;

    if app.saved {
        println!("Changes saved. Restart mistralrs_proxy to apply changes.");
    }

    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Browse,
    ConfirmDelete,
    ConfirmDiscard,
}

struct App<'a> {
    path: &'a Path,
    file: KeyFile,
    selected: usize,
    dirty: bool,
    saved: bool,
    status: String,
    mode: Mode,
    quit: bool,
}

impl<'a> App<'a> {
    fn new(file: KeyFile, path: &'a Path) -> Self {
        Self {
            path,
            file,
            selected: 0,
            dirty: false,
            saved: false,
            status: format!("Loaded {}", path.display()),
            mode: Mode::Browse,
            quit: false,
        }
    }

    fn run(&mut self, terminal: &mut ratatui::DefaultTerminal) -> io::Result<()> {
        while !self.quit {
            terminal.draw(|frame| self.draw(frame))?;
            let Event::Key(key) = event::read()? else {
                continue;
            };
            if key.kind != KeyEventKind::Press {
                continue;
            }
            if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
                self.quit = true;
                continue;
            }
            self.handle(key.code);
        }

        Ok(())
    }

    fn handle(&mut self, code: KeyCode) {
        match self.mode {
            Mode::ConfirmDelete => match code {
                KeyCode::Char('y') | KeyCode::Char('Y') => self.delete(),
                _ => {
                    self.mode = Mode::Browse;
                    self.status = "Delete cancelled.".to_owned();
                }
            },
            Mode::ConfirmDiscard => match code {
                KeyCode::Char('y') | KeyCode::Char('Y') => self.quit = true,
                _ => {
                    self.mode = Mode::Browse;
                    self.status = "Still editing.".to_owned();
                }
            },
            Mode::Browse => self.handle_browse(code),
        }
    }

    fn handle_browse(&mut self, code: KeyCode) {
        match code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.selected = self.selected.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.selected = (self.selected + 1).min(self.file.keys.len().saturating_sub(1));
            }
            KeyCode::Home => self.selected = 0,
            KeyCode::End => self.selected = self.file.keys.len().saturating_sub(1),
            KeyCode::Char('a') => self.toggle_admin(),
            KeyCode::Char('d') => self.toggle_disabled(),
            KeyCode::Char('x') | KeyCode::Delete => {
                if self.would_orphan_admin() {
                    self.status = "Refusing to delete the last enabled admin key.".to_owned();
                } else if self.file.keys.len() == 1 {
                    self.status = "Refusing to delete the last key.".to_owned();
                } else {
                    self.mode = Mode::ConfirmDelete;
                }
            }
            KeyCode::Char('s') => self.save(),
            KeyCode::Char('r') => self.reload(),
            KeyCode::Char('q') | KeyCode::Esc => {
                if self.dirty {
                    self.mode = Mode::ConfirmDiscard;
                } else {
                    self.quit = true;
                }
            }
            _ => {}
        }
    }

    /// True when the selected key is the only enabled admin key left.
    fn would_orphan_admin(&self) -> bool {
        let Some(selected) = self.file.keys.get(self.selected) else {
            return false;
        };
        selected.admin
            && !selected.disabled
            && self
                .file
                .keys
                .iter()
                .filter(|key| key.admin && !key.disabled)
                .count()
                == 1
    }

    fn toggle_admin(&mut self) {
        if self.would_orphan_admin() {
            self.status = "Refusing to clear the last enabled admin key.".to_owned();
            return;
        }
        if let Some(key) = self.file.keys.get_mut(self.selected) {
            key.admin = !key.admin;
            self.dirty = true;
            self.status = format!("{}: admin = {}. Press s to save.", key.name, key.admin);
        }
    }

    fn toggle_disabled(&mut self) {
        if self.would_orphan_admin() {
            self.status = "Refusing to disable the last enabled admin key.".to_owned();
            return;
        }
        if let Some(key) = self.file.keys.get_mut(self.selected) {
            key.disabled = !key.disabled;
            self.dirty = true;
            self.status = format!(
                "{}: disabled = {}. Press s to save.",
                key.name, key.disabled
            );
        }
    }

    fn delete(&mut self) {
        self.mode = Mode::Browse;
        if self.selected >= self.file.keys.len() {
            return;
        }
        let removed = self.file.keys.remove(self.selected);
        self.selected = self.selected.min(self.file.keys.len().saturating_sub(1));
        self.dirty = true;
        self.status = format!("Deleted {}. Press s to save.", removed.name);
    }

    fn save(&mut self) {
        if !self.dirty {
            self.status = "Nothing to save.".to_owned();
            return;
        }
        match self.file.save(self.path) {
            Ok(()) => {
                self.dirty = false;
                self.saved = true;
                self.status = format!(
                    "Saved {}. Restart mistralrs_proxy to apply changes.",
                    self.path.display()
                );
            }
            Err(error) => self.status = format!("Could not save: {error}"),
        }
    }

    fn reload(&mut self) {
        match KeyFile::load(self.path) {
            Ok(file) => {
                self.file = file;
                self.selected = self.selected.min(self.file.keys.len().saturating_sub(1));
                self.dirty = false;
                self.status = "Reloaded from disk; unsaved edits discarded.".to_owned();
            }
            Err(error) => self.status = format!("Could not reload: {error}"),
        }
    }

    fn draw(&self, frame: &mut Frame) {
        let [header, body, footer, status] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Min(3),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .areas(frame.area());

        // The count and the unsaved marker come first: a long path would
        // otherwise push them past the right edge.
        let title = format!(
            " mistralrs_proxy keys · {} key{}{} · {} ",
            self.file.keys.len(),
            if self.file.keys.len() == 1 { "" } else { "s" },
            if self.dirty { " · UNSAVED" } else { "" },
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

        let rows = self.file.keys.iter().map(|key| {
            let style = if key.disabled {
                Style::default().fg(Color::DarkGray)
            } else {
                Style::default()
            };
            Row::new(vec![
                Cell::from(key.name.clone()),
                Cell::from(key.identifier.clone()),
                Cell::from(if key.admin { "yes" } else { "no" }),
                Cell::from(if key.disabled { "DISABLED" } else { "active" }),
                Cell::from(if key.created_at_unix_ms == 0 {
                    "unknown".to_owned()
                } else {
                    format_timestamp(key.created_at_unix_ms)
                }),
                Cell::from(key.key_sha256.chars().take(16).collect::<String>()),
            ])
            .style(style)
        });
        let table = Table::new(
            rows,
            [
                Constraint::Length(24),
                Constraint::Length(10),
                Constraint::Length(5),
                Constraint::Length(8),
                Constraint::Length(24),
                Constraint::Min(16),
            ],
        )
        .header(
            Row::new(vec![
                "NAME",
                "IDENTIFIER",
                "ADMIN",
                "STATE",
                "CREATED",
                "SHA-256",
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

        let mut state = TableState::default().with_selected(Some(self.selected));
        frame.render_stateful_widget(table, body.inner(Margin::new(1, 0)), &mut state);

        let help = match self.mode {
            Mode::Browse => {
                "↑/↓ move   a admin   d disable   x delete   s save   r reload   q quit"
            }
            Mode::ConfirmDelete => "Delete this key permanently? y / n",
            Mode::ConfirmDiscard => "Quit and discard unsaved changes? y / n",
        };
        let help_style = if self.mode == Mode::Browse {
            Style::default().fg(Color::DarkGray)
        } else {
            Style::default().fg(Color::Black).bg(Color::Yellow)
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
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn scratch() -> PathBuf {
        std::env::temp_dir().join(format!("proxy-manage-{}.json", uuid::Uuid::new_v4()))
    }

    fn app_with(names: &[(&str, bool)]) -> (KeyFile, PathBuf) {
        let mut file = KeyFile::default();
        for (name, admin) in names {
            let (record, _) = KeyRecord::generate(*name, *admin).unwrap();
            file.keys.push(record);
        }
        (file, scratch())
    }

    fn rendered(app: &App) -> String {
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(110, 10)).unwrap();
        terminal.draw(|frame| app.draw(frame)).unwrap();

        terminal.backend().to_string()
    }

    #[test]
    fn the_view_shows_every_key_with_its_flags() {
        let (mut file, path) = app_with(&[("admin", true), ("bot", false)]);
        file.keys[1].disabled = true;
        let app = App::new(file, &path);
        let identifier = app.file.keys[0].identifier.clone();

        let screen = rendered(&app);

        assert!(screen.contains("NAME"), "{screen}");
        assert!(screen.contains("IDENTIFIER"), "{screen}");
        assert!(screen.contains("admin"), "{screen}");
        assert!(screen.contains("bot"), "{screen}");
        assert!(screen.contains(&identifier), "{screen}");
        assert!(screen.contains("DISABLED"), "{screen}");
        assert!(screen.contains("2 keys"), "{screen}");
        assert!(screen.contains("d disable"), "{screen}");
        // The secret never reaches the screen, only a digest prefix.
        assert!(
            screen.contains(&app.file.keys[0].key_sha256[..16]),
            "{screen}"
        );
    }

    #[test]
    fn a_pending_confirmation_replaces_the_help_line() {
        let (file, path) = app_with(&[("admin", true), ("bot", false)]);
        let mut app = App::new(file, &path);
        app.handle(KeyCode::Down);
        app.handle(KeyCode::Char('x'));

        let screen = rendered(&app);

        assert!(screen.contains("Delete this key permanently?"), "{screen}");
    }

    #[test]
    fn the_first_key_is_an_admin_key_even_without_the_flag() {
        let path = scratch();
        create(&path, "bootstrap", false).unwrap();

        let file = KeyFile::load(&path).unwrap();
        std::fs::remove_file(&path).unwrap();

        assert_eq!(file.keys.len(), 1);
        assert!(file.keys[0].admin);
    }

    #[test]
    fn later_keys_follow_the_flag_and_names_stay_unique() {
        let path = scratch();
        create(&path, "first", false).unwrap();
        create(&path, "second", false).unwrap();
        assert!(create(&path, "second", false).is_err());
        assert!(create(&path, "  ", false).is_err());

        let file = KeyFile::load(&path).unwrap();
        std::fs::remove_file(&path).unwrap();

        assert_eq!(file.keys.len(), 2);
        assert!(file.keys[0].admin);
        assert!(!file.keys[1].admin);
    }

    #[test]
    fn the_last_enabled_admin_key_cannot_be_removed_or_demoted() {
        let (file, path) = app_with(&[("admin", true), ("bot", false)]);
        let mut app = App::new(file, &path);

        app.handle_browse(KeyCode::Char('a'));
        assert!(app.file.keys[0].admin);
        app.handle_browse(KeyCode::Char('d'));
        assert!(!app.file.keys[0].disabled);
        app.handle_browse(KeyCode::Char('x'));
        assert_eq!(app.mode, Mode::Browse);
        assert_eq!(app.file.keys.len(), 2);
        assert!(!app.dirty);
    }

    #[test]
    fn a_second_admin_key_frees_the_first_one() {
        let (file, path) = app_with(&[("admin", true), ("other-admin", true)]);
        let mut app = App::new(file, &path);

        app.handle_browse(KeyCode::Char('d'));

        assert!(app.file.keys[0].disabled);
        assert!(app.dirty);
    }

    #[test]
    fn deleting_takes_a_confirmation_and_shifts_the_selection() {
        let (file, path) = app_with(&[("admin", true), ("bot", false)]);
        let mut app = App::new(file, &path);

        app.handle(KeyCode::Down);
        app.handle(KeyCode::Char('x'));
        assert_eq!(app.mode, Mode::ConfirmDelete);
        app.handle(KeyCode::Char('n'));
        assert_eq!(app.file.keys.len(), 2);

        app.handle(KeyCode::Char('x'));
        app.handle(KeyCode::Char('y'));

        assert_eq!(app.mode, Mode::Browse);
        assert_eq!(app.file.keys.len(), 1);
        assert_eq!(app.selected, 0);
        assert!(app.dirty);
    }

    #[test]
    fn quitting_with_unsaved_edits_asks_first() {
        let (file, path) = app_with(&[("admin", true), ("bot", false)]);
        let mut app = App::new(file, &path);

        app.handle(KeyCode::Down);
        app.handle(KeyCode::Char('d'));
        app.handle(KeyCode::Char('q'));
        assert_eq!(app.mode, Mode::ConfirmDiscard);
        assert!(!app.quit);

        app.handle(KeyCode::Char('y'));
        assert!(app.quit);
    }

    #[test]
    fn saving_writes_the_edits_and_leaves_no_unsaved_state() {
        let (file, path) = app_with(&[("admin", true), ("bot", false)]);
        let mut app = App::new(file, &path);

        app.handle(KeyCode::Down);
        app.handle(KeyCode::Char('d'));
        app.handle(KeyCode::Char('s'));

        assert!(!app.dirty);
        assert!(app.saved);
        let reloaded = KeyFile::load(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert!(reloaded.keys[1].disabled);
    }
}
