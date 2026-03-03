//! Terminal UI dashboard for the batch pipeline.
//!
//! Uses ratatui + crossterm to render a full-screen dashboard showing
//! progress, throughput, ISA breakdown, and recent activity.
//!
//! See `docs/batch-store/04-batch-ingestion.md` Section 4 for the layout spec.

use super::stats::PipelineStats;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Gauge, Paragraph},
    Frame, Terminal,
};
use std::io::stdout;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Run the TUI dashboard in the current thread.
///
/// Renders at ~10 Hz until the pipeline finishes (stats show completion)
/// or the user presses `q` / Ctrl-C.
///
/// Returns `Ok(true)` if the user requested shutdown via `q`.
pub fn run_tui(
    stats: Arc<PipelineStats>,
    shutdown: Arc<AtomicBool>,
    run_id: &str,
    jobs: usize,
    input_dir: &str,
    staging_dir: &str,
) -> std::io::Result<bool> {
    // Enter TUI mode
    enable_raw_mode()?;
    stdout().execute(EnterAlternateScreen)?;
    let backend = ratatui::backend::CrosstermBackend::new(stdout());
    let mut terminal = Terminal::new(backend)?;

    let start_time = Instant::now();
    let mut user_quit = false;

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        let snap = stats.snapshot();
        let elapsed = start_time.elapsed();

        // Draw
        terminal.draw(|frame| {
            draw_dashboard(frame, &snap, run_id, jobs, input_dir, staging_dir, elapsed);
        })?;

        // Poll for key events (100ms timeout = ~10 Hz)
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') => {
                            user_quit = true;
                            shutdown.store(true, Ordering::Relaxed);
                            break;
                        }
                        KeyCode::Char('c')
                            if key
                                .modifiers
                                .contains(crossterm::event::KeyModifiers::CONTROL) =>
                        {
                            user_quit = true;
                            shutdown.store(true, Ordering::Relaxed);
                            break;
                        }
                        _ => {}
                    }
                }
            }
        }

        // Check if pipeline is done (all discovered files written)
        if snap.discovered_files > 0 && snap.total_processed() >= snap.discovered_files {
            // Wait a moment for the user to see final stats
            std::thread::sleep(Duration::from_secs(1));
            // Redraw with final stats
            let final_snap = stats.snapshot();
            terminal.draw(|frame| {
                draw_dashboard(
                    frame,
                    &final_snap,
                    run_id,
                    jobs,
                    input_dir,
                    staging_dir,
                    start_time.elapsed(),
                );
            })?;
            std::thread::sleep(Duration::from_secs(2));
            break;
        }
    }

    // Leave TUI mode
    disable_raw_mode()?;
    stdout().execute(LeaveAlternateScreen)?;

    Ok(user_quit)
}

/// Simple non-TUI progress output.
///
/// Prints a progress line to stderr every `interval` seconds.
pub fn run_simple_progress(
    stats: Arc<PipelineStats>,
    shutdown: Arc<AtomicBool>,
    interval: Duration,
) {
    let start = Instant::now();
    loop {
        std::thread::sleep(interval);
        if shutdown.load(Ordering::Relaxed) {
            break;
        }
        let snap = stats.snapshot();
        let elapsed = start.elapsed();
        let rate = if elapsed.as_secs() > 0 {
            snap.written_files as f64 / elapsed.as_secs_f64()
        } else {
            0.0
        };

        let pct = if snap.discovered_files > 0 {
            snap.total_processed() as f64 / snap.discovered_files as f64 * 100.0
        } else {
            0.0
        };

        let eta = if rate > 0.0 && snap.discovered_files > snap.total_processed() {
            let remaining = snap.discovered_files - snap.total_processed();
            let secs = remaining as f64 / rate;
            format_duration(Duration::from_secs_f64(secs))
        } else {
            "??:??:??".to_string()
        };

        eprintln!(
            "[{}] Processed {}/{} files ({:.1}%) | {:.0} files/sec | ETA {}",
            format_duration(elapsed),
            snap.total_processed(),
            snap.discovered_files,
            pct,
            rate,
            eta,
        );

        if snap.discovered_files > 0 && snap.total_processed() >= snap.discovered_files {
            eprintln!(
                "Completed: {} classified, {} ambiguous, {} errors",
                snap.classified_files,
                snap.written_files.saturating_sub(snap.classified_files),
                snap.errors,
            );
            break;
        }
    }
}

fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    format!("{:02}:{:02}:{:02}", h, m, s)
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_000_000_000_000 {
        format!("{:.1} TB", bytes as f64 / 1e12)
    } else if bytes >= 1_000_000_000 {
        format!("{:.1} GB", bytes as f64 / 1e9)
    } else if bytes >= 1_000_000 {
        format!("{:.1} MB", bytes as f64 / 1e6)
    } else if bytes >= 1_000 {
        format!("{:.1} KB", bytes as f64 / 1e3)
    } else {
        format!("{} B", bytes)
    }
}

fn draw_dashboard(
    frame: &mut Frame,
    snap: &super::stats::StatsSnapshot,
    run_id: &str,
    jobs: usize,
    input_dir: &str,
    staging_dir: &str,
    elapsed: Duration,
) {
    let area = frame.area();

    // Top-level layout: header, progress, stats
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5), // Header
            Constraint::Length(5), // Progress
            Constraint::Length(7), // Classification results
            Constraint::Min(3),    // Pipeline status
        ])
        .split(area);

    // Header
    let elapsed_str = format_duration(elapsed);
    let header_text = vec![
        Line::from(vec![
            Span::styled("  Run: ", Style::default().fg(Color::DarkGray)),
            Span::styled(run_id, Style::default().fg(Color::Cyan)),
            Span::raw("    "),
            Span::styled("Workers: ", Style::default().fg(Color::DarkGray)),
            Span::styled(format!("{}", jobs), Style::default().fg(Color::Yellow)),
            Span::raw("    "),
            Span::styled("Elapsed: ", Style::default().fg(Color::DarkGray)),
            Span::styled(&elapsed_str, Style::default().fg(Color::Green)),
        ]),
        Line::from(vec![
            Span::styled("  Input: ", Style::default().fg(Color::DarkGray)),
            Span::raw(input_dir),
        ]),
        Line::from(vec![
            Span::styled("  Output: ", Style::default().fg(Color::DarkGray)),
            Span::raw(staging_dir),
        ]),
    ];
    let header = Paragraph::new(header_text).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" ISA Harvester Batch Classifier ")
            .title_style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
    );
    frame.render_widget(header, chunks[0]);

    // Progress bar
    let pct = snap.progress_fraction();
    let rate = if elapsed.as_secs() > 0 {
        snap.total_processed() as f64 / elapsed.as_secs_f64()
    } else {
        0.0
    };
    let byte_rate = if elapsed.as_secs() > 0 {
        snap.hashed_bytes as f64 / elapsed.as_secs_f64()
    } else {
        0.0
    };
    let eta = if rate > 0.0 && snap.discovered_files > snap.total_processed() {
        let remaining = snap.discovered_files - snap.total_processed();
        format_duration(Duration::from_secs_f64(remaining as f64 / rate))
    } else {
        "??:??:??".to_string()
    };

    let progress_label = format!(
        "  Files: {}/{} ({:.1}%)   {:.0} files/sec   {} /sec   ETA: {}",
        snap.total_processed(),
        snap.discovered_files,
        pct * 100.0,
        rate,
        format_bytes(byte_rate as u64),
        eta,
    );
    let gauge = Gauge::default()
        .block(Block::default().borders(Borders::ALL).title(" Progress "))
        .gauge_style(Style::default().fg(Color::Green))
        .ratio(pct.min(1.0))
        .label(progress_label);
    frame.render_widget(gauge, chunks[1]);

    // Classification results
    let classified = snap.classified_files;
    let ambiguous = snap.written_files.saturating_sub(classified);
    let errors = snap.errors;
    let total = snap.total_processed();

    let results_text = vec![
        Line::from(vec![
            Span::styled("  Classified: ", Style::default().fg(Color::Green)),
            Span::raw(format!("{}", classified)),
            if total > 0 {
                Span::styled(
                    format!("  ({:.1}%)", classified as f64 / total as f64 * 100.0),
                    Style::default().fg(Color::DarkGray),
                )
            } else {
                Span::raw("")
            },
        ]),
        Line::from(vec![
            Span::styled("  Ambiguous:  ", Style::default().fg(Color::Yellow)),
            Span::raw(format!("{}", ambiguous)),
        ]),
        Line::from(vec![
            Span::styled("  Errors:     ", Style::default().fg(Color::Red)),
            Span::raw(format!("{}", errors)),
        ]),
        Line::from(vec![
            Span::styled("  Skipped:    ", Style::default().fg(Color::DarkGray)),
            Span::raw(format!("{}", snap.skipped)),
        ]),
    ];
    let results = Paragraph::new(results_text).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Classification Results "),
    );
    frame.render_widget(results, chunks[2]);

    // Pipeline status
    let pipeline_text = vec![
        Line::from(vec![
            Span::styled("  Discovered: ", Style::default().fg(Color::DarkGray)),
            Span::raw(format!("{} files", snap.discovered_files)),
            Span::raw("  "),
            Span::styled(
                format!("({})", format_bytes(snap.discovered_bytes)),
                Style::default().fg(Color::DarkGray),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Hashed:     ", Style::default().fg(Color::DarkGray)),
            Span::raw(format!("{} files", snap.hashed_files)),
        ]),
        Line::from(vec![
            Span::styled("  Classified: ", Style::default().fg(Color::DarkGray)),
            Span::raw(format!("{} files", snap.classified_files)),
        ]),
        Line::from(vec![
            Span::styled("  Written:    ", Style::default().fg(Color::DarkGray)),
            Span::raw(format!("{} files", snap.written_files)),
        ]),
    ];
    let pipeline = Paragraph::new(pipeline_text).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Pipeline Status "),
    );
    frame.render_widget(pipeline, chunks[3]);
}
