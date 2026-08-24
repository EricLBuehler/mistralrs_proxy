//! Off-screen table rendering with horizontal scrolling, shared by the TUIs.
//!
//! A table keeps a fixed natural width. When the viewport is narrower, only
//! the window beginning at `scroll` is blitted into it, clamped so the scroll
//! never runs past the right edge. When the viewport is wider, the table is
//! stretched across it, so the trailing column absorbs the slack. Scrolling is
//! always available and is simply a no-op when the table already fits.

use ratatui::{
    buffer::Buffer,
    layout::Rect,
    prelude::Frame,
    widgets::{StatefulWidget, Table, TableState},
};

/// ←/→ (or h/l) scroll step, in cells.
pub const SCROLL_STEP: u16 = 8;

/// Render a stateful table into `area` with the scrolling window above.
pub fn render_scrolled_table(
    frame: &mut Frame,
    table: Table<'_>,
    area: Rect,
    natural_width: u16,
    scroll: u16,
    state: &mut TableState,
) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let width = natural_width.max(area.width);
    let scroll = scroll.min(width.saturating_sub(area.width));

    let mut offscreen = Buffer::empty(Rect::new(0, 0, width, area.height));
    StatefulWidget::render(table, Rect::new(0, 0, width, area.height), &mut offscreen, state);

    let buffer = frame.buffer_mut();
    for y in 0..area.height {
        for x in 0..area.width {
            let source = scroll + x;
            if source >= width {
                break;
            }
            buffer[(area.x + x, area.y + y)] = offscreen[(source, y)].clone();
        }
    }
}
