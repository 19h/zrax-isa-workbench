//! The entropy tab: the file drawn as a map in one of eight modes, with an
//! inspector for the byte under the cursor.
//!
//! Seven modes are apeiron's (`crates/apeiron-core`); the eighth is the
//! browser workbench's entropy map. The view works the way apeiron's does:
//! whenever the camera, the mode or the underlying data changes, the
//! visible region is drawn again off the main thread at about one texel per
//! device pixel (`crate::entropy::frame`). Until the new frame arrives the
//! previous one stays on screen, moved and scaled with the camera.

use std::cell::Cell;
use std::fmt::Write as _;
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use apeiron::analysis::{
    calculate_jsd, calculate_kolmogorov_complexity, calculate_rcmse_quick, identify_file_type,
};
use apeiron::types::ByteLayout;
use gpui::{
    canvas, div, fill, outline, point, prelude::*, px, rems, size, App, BorderStyle, Bounds,
    ContentMask, Context, Corners, Div, Entity, FocusHandle, Focusable, MouseButton,
    MouseDownEvent, MouseMoveEvent, MouseUpEvent, Pixels, Point, RenderImage, Rgba, ScrollEvent,
    SharedString, Subscription, Window,
};
use zrax::workbench::{Curve, Engine, Inspection, Patch};

use super::strip::profile_strip;
use super::widgets::{self, badge, key_cap, meter, small, spacer, text_button};
use crate::entropy::frame::{self, Frame, FrameSpec, Gpu, MapSpace, MAX_TEXTURE_SIDE};
use crate::entropy::raster;
use crate::entropy::scene::{MapMode, Scene};
use crate::entropy::viewport::{self, Grid, Viewport};
use crate::model::entry::EntryId;
use crate::model::session::{Session, SessionEvent};
use crate::{format, palette, theme};

/// Padding around the map frame.
const STAGE_PADDING_REMS: f32 = 0.375;

/// Frame side assumed before the stage has been measured, in device pixels.
const DEFAULT_FRAME_PIXELS: usize = 1024;

/// How far a corner of the view may drift from the frame on screen, as a
/// fraction of the visible span, before the region is drawn again.
const REDRAW_TOLERANCE: f32 = 0.02;

/// How often the map is drawn again while background analysis feeds it.
const PROGRESS_INTERVAL: Duration = Duration::from_millis(250);

/// Bytes the probe's statistics window covers.
const PROBE_WINDOW_BYTES: u64 = 4096;

/// Windows of apeiron's per-offset readouts, as its samplers use them.
const COMPLEXITY_WINDOW_BYTES: usize = 128;
const MULTI_SCALE_WINDOW_BYTES: usize = 256;
const DIVERGENCE_WINDOW_BYTES: usize = 256;

/// Rows and bytes per row of the inspector's hex excerpt.
const MINI_HEX_ROWS: usize = 12;
const MINI_HEX_COLUMNS: usize = 8;

/// Zoom factor of the toolbar's in and out buttons.
const ZOOM_STEP: f64 = 2.0;

/// Wheel pixels that double or halve the zoom.
const WHEEL_PIXELS_PER_OCTAVE: f32 = 240.0;

/// Pointer travel beyond which a press is a pan, not a click.
const DRAG_THRESHOLD: f32 = 3.0;

/// Size of the histogram, in `rem` and bars.
const HISTOGRAM_HEIGHT_REMS: f32 = 3.0;
const HISTOGRAM_BARS: usize = 256;

/// The frame on screen.
struct Shown {
    entry: EntryId,
    spec: FrameSpec,
    /// The world region the image covers.
    world_min: (f32, f32),
    world_max: (f32, f32),
    image: Arc<RenderImage>,
    used_gpu: bool,
}

/// Statistics of the probe's window, cached while the probe stays in it.
struct Probe {
    entry: EntryId,
    start: u64,
    stats: Inspection,
}

/// Apeiron's measures of the bytes at the cursor.
#[derive(Clone, Copy)]
struct Readouts {
    entry: EntryId,
    cursor: u64,
    /// Compression complexity of the next 128 B, 0.0 to 1.0.
    complexity: f64,
    /// Divergence of the next 256 B from the file's distribution.
    divergence: f64,
    /// Quick multi-scale entropy of the next 256 B.
    multi_scale: f32,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Framing {
    Fill,
    Fit,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Inspector {
    Visible,
    Hidden,
}

/// The entropy tab of the selected file.
pub struct EntropyView {
    session: Entity<Session>,
    focus: FocusHandle,
    mode: MapMode,
    layout: ByteLayout,
    camera: Viewport,
    framing: Framing,
    inspector: Inspector,
    /// The selected file as apeiron sees it.
    scene: Option<(EntryId, Arc<Scene>)>,
    gpu: Arc<Gpu>,
    shown: Option<Shown>,
    /// Images no longer shown, released from the GPU on the next frame.
    retired: Vec<Arc<RenderImage>>,
    /// Whether a frame is being drawn; one at a time, the newest wish next.
    is_drawing: bool,
    /// Whether a redraw for background progress is already scheduled.
    is_progress_scheduled: bool,
    /// Clock for apeiron's animated placeholders.
    started: Instant,
    probe: Option<Probe>,
    readouts: Option<Readouts>,
    /// Where the map frame and the overview strip were last painted.
    frame_bounds: Rc<Cell<Bounds<Pixels>>>,
    strip_bounds: Rc<Cell<Bounds<Pixels>>>,
    /// Where a press on the map started, and whether it became a pan.
    press: Option<Point<Pixels>>,
    is_panning: bool,
    /// The cursor the camera was last checked against.
    followed_cursor: Option<(EntryId, u64)>,
    _subscriptions: Vec<Subscription>,
}

impl Focusable for EntropyView {
    fn focus_handle(&self, _cx: &App) -> FocusHandle {
        self.focus.clone()
    }
}

fn rgba(color: palette::Rgb) -> Rgba {
    Rgba {
        r: f32::from(color[0]) / 255.0,
        g: f32::from(color[1]) / 255.0,
        b: f32::from(color[2]) / 255.0,
        a: 1.0,
    }
}

/// Fraction of the square world visible at 1× along each axis.
fn frame_span(bounds: Bounds<Pixels>) -> (f64, f64) {
    let side = bounds.size.width.max(bounds.size.height);
    if side <= px(0.0) {
        return (1.0, 1.0);
    }
    (
        f64::from(bounds.size.width / side),
        f64::from(bounds.size.height / side),
    )
}

/// Turn a rendered frame into an image for the window. A texture smaller
/// than the frame on screen (the fixed-resolution modes) is enlarged by a
/// whole factor first, so its texels stay sharp.
fn frame_image(frame: &Frame, frame_pixels: usize) -> Option<Arc<RenderImage>> {
    let largest = frame.width.max(frame.height).max(1);
    let factor = (frame_pixels / largest).clamp(1, (MAX_TEXTURE_SIDE / largest).max(1));
    let pixels = raster::upscale_nearest(&frame.pixels, frame.width, frame.height, factor);
    let buffer = image::RgbaImage::from_raw(
        u32::try_from(frame.width * factor).ok()?,
        u32::try_from(frame.height * factor).ok()?,
        pixels,
    )?;
    Some(Arc::new(RenderImage::new(vec![image::Frame::new(buffer)])))
}

impl EntropyView {
    /// An entropy view over the selected entry of `session`.
    pub fn new(session: Entity<Session>, cx: &mut Context<Self>) -> Self {
        let subscriptions = vec![
            cx.observe(&session, |_, _, cx| cx.notify()),
            cx.subscribe(&session, |this, _, event: &SessionEvent, cx| {
                if *event == SessionEvent::SelectionChanged {
                    this.camera = Viewport::default();
                    this.probe = None;
                    this.readouts = None;
                    cx.notify();
                }
            }),
        ];
        Self {
            session,
            focus: cx.focus_handle(),
            mode: MapMode::Entropy,
            layout: ByteLayout::Hilbert,
            camera: Viewport::default(),
            framing: Framing::Fill,
            inspector: Inspector::Visible,
            scene: None,
            gpu: Arc::default(),
            shown: None,
            retired: Vec::new(),
            is_drawing: false,
            is_progress_scheduled: false,
            started: Instant::now(),
            probe: None,
            readouts: None,
            frame_bounds: Rc::new(Cell::new(Bounds::default())),
            strip_bounds: Rc::new(Cell::new(Bounds::default())),
            press: None,
            is_panning: false,
            followed_cursor: None,
            _subscriptions: subscriptions,
        }
    }

    /// Show `mode` at `zoom`, centered: what a screenshot is taken of.
    #[cfg(feature = "screenshots")]
    pub fn show(&mut self, mode: MapMode, zoom: f64, cx: &mut Context<Self>) {
        self.mode = mode;
        self.camera = Viewport::default();
        self.camera.zoom_at(zoom, 0.25, 0.25, zoom.max(1.0), (1.0, 1.0));
        cx.notify();
    }

    /// Id, size and cursor of the selected entry.
    fn target(&self, cx: &App) -> Option<(EntryId, u64, u64)> {
        let entry = self.session.read(cx).selected()?;
        Some((entry.id, entry.size, entry.cursor))
    }

    fn set_cursor(&mut self, offset: u64, cx: &mut Context<Self>) {
        if let Some((id, _, _)) = self.target(cx) {
            self.session
                .update(cx, |session, cx| session.set_cursor(id, offset, cx));
        }
    }

    /// The scene of `entry`, built when another file is selected.
    fn scene_for(&mut self, entry: EntryId, engine: &Engine) -> Arc<Scene> {
        match &self.scene {
            Some((held, scene)) if *held == entry => scene.clone(),
            _ => {
                let scene = Arc::new(Scene::new(engine.shared_data()));
                self.scene = Some((entry, scene.clone()));
                scene
            }
        }
    }

    /// Side of the current mode's world, in world units.
    fn dimension(&self) -> Option<u64> {
        let (_, scene) = self.scene.as_ref()?;
        Some(scene.dimension(self.mode, self.layout))
    }

    /// The frame the current view calls for.
    fn wanted_spec(&self, scene: &Scene, window: &Window) -> FrameSpec {
        let dimension = scene.dimension(self.mode, self.layout);
        // World sides are at most 2^15 and camera values fractions of
        // them: f32 holds both.
        #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
        let (world_side, camera_x, camera_y, zoom) = (
            dimension as f32,
            self.camera.x as f32,
            self.camera.y as f32,
            self.camera.zoom as f32,
        );
        let bounds = self.frame_bounds.get();
        let frame_points = f32::from(bounds.size.width.max(bounds.size.height));
        // A frame is at most a few thousand device pixels.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let frame_pixels = match (frame_points * window.scale_factor()) as usize {
            0 => DEFAULT_FRAME_PIXELS,
            pixels => pixels,
        };
        let (world_min, world_max, texture_side) = if self.mode.renders_full_world() {
            (
                (0.0, 0.0),
                (world_side, world_side),
                self.mode.min_texture_size().min(MAX_TEXTURE_SIDE),
            )
        } else {
            let span = frame_span(bounds);
            #[allow(clippy::cast_possible_truncation)]
            let (width, height) = (span.0 as f32 * world_side / zoom, span.1 as f32 * world_side / zoom);
            let (left, top) = (camera_x * world_side, camera_y * world_side);
            (
                (left, top),
                ((left + width).min(world_side), (top + height).min(world_side)),
                frame_pixels.clamp(self.mode.min_texture_size(), MAX_TEXTURE_SIDE),
            )
        };
        FrameSpec {
            mode: self.mode,
            layout: self.layout,
            world_min,
            world_max,
            texture_side,
            revision: scene.revision(self.mode),
        }
    }

    /// Draw `spec` off the main thread unless a frame is already under way;
    /// the view asks again when that one arrives.
    fn request_frame(
        &mut self,
        entry: EntryId,
        scene: Arc<Scene>,
        engine: Engine,
        spec: FrameSpec,
        window: &Window,
        cx: &mut Context<Self>,
    ) {
        if self.is_drawing {
            return;
        }
        self.is_drawing = true;
        let gpu = self.gpu.clone();
        let time_seconds = self.started.elapsed().as_secs_f64();
        let bounds = self.frame_bounds.get();
        let frame_points = f32::from(bounds.size.width.max(bounds.size.height));
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let frame_pixels = ((frame_points * window.scale_factor()) as usize).max(1);
        cx.spawn(async move |view, cx| {
            let drawn = cx
                .background_executor()
                .spawn(async move {
                    let frame = frame::render(&scene, &engine, &gpu, spec, time_seconds);
                    let (world_min, world_max, used_gpu) =
                        (frame.world_min, frame.world_max, frame.used_gpu);
                    frame_image(&frame, frame_pixels)
                        .map(|image| (image, world_min, world_max, used_gpu))
                })
                .await;
            let _ = view.update(cx, |view, cx| {
                view.is_drawing = false;
                if let Some((image, world_min, world_max, used_gpu)) = drawn {
                    if let Some(previous) = view.shown.take() {
                        view.retired.push(previous.image);
                    }
                    view.shown = Some(Shown {
                        entry,
                        spec,
                        world_min,
                        world_max,
                        image,
                        used_gpu,
                    });
                }
                cx.notify();
            });
        })
        .detach();
    }

    /// While background analysis feeds the current mode, look again soon.
    fn schedule_progress(&mut self, cx: &mut Context<Self>) {
        if self.is_progress_scheduled {
            return;
        }
        self.is_progress_scheduled = true;
        cx.spawn(async move |view, cx| {
            cx.background_executor().timer(PROGRESS_INTERVAL).await;
            let _ = view.update(cx, |view, cx| {
                view.is_progress_scheduled = false;
                cx.notify();
            });
        })
        .detach();
    }

    /// A window position in projected square-world units at 1×, inside the
    /// frame. Both axes use the same scale even when the frame clips the map.
    fn frame_fraction(&self, position: Point<Pixels>) -> Option<(f64, f64)> {
        let frame = self.frame_bounds.get();
        let side = frame.size.width.max(frame.size.height);
        if side <= px(0.0) || !frame.contains(&position) {
            return None;
        }
        let x = (position.x - frame.origin.x) / side;
        let y = (position.y - frame.origin.y) / side;
        Some((f64::from(x), f64::from(y)))
    }

    fn zoom(&mut self, factor: f64, anchor: (f64, f64), cx: &mut Context<Self>) {
        if let Some(dimension) = self.dimension() {
            let max_zoom = viewport::max_zoom(dimension);
            let span = frame_span(self.frame_bounds.get());
            self.camera.zoom_at(factor, anchor.0, anchor.1, max_zoom, span);
            cx.notify();
        }
    }

    fn on_mouse_down(
        &mut self,
        event: &MouseDownEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        window.focus(&self.focus, cx);
        if self.frame_fraction(event.position).is_some() {
            self.press = Some(event.position);
            self.is_panning = false;
        }
    }

    fn on_mouse_move(
        &mut self,
        event: &MouseMoveEvent,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(press) = self.press else {
            return;
        };
        if event.pressed_button != Some(MouseButton::Left) {
            self.press = None;
            return;
        }
        let delta = event.position - press;
        let travelled = f32::from(delta.x).abs().max(f32::from(delta.y).abs());
        if !self.is_panning && travelled < DRAG_THRESHOLD {
            return;
        }
        self.is_panning = true;
        let frame = self.frame_bounds.get();
        let side = frame.size.width.max(frame.size.height);
        if side <= px(0.0) {
            return;
        }
        self.camera.pan(
            f64::from(delta.x / side),
            f64::from(delta.y / side),
            frame_span(frame),
        );
        self.press = Some(event.position);
        cx.notify();
    }

    /// A click on the map moves the cursor to the byte under it, in the
    /// modes whose points are file offsets.
    fn on_mouse_up(&mut self, event: &MouseUpEvent, _window: &mut Window, cx: &mut Context<Self>) {
        let was_click = self.press.take().is_some() && !self.is_panning;
        self.is_panning = false;
        if !was_click || !self.mode.maps_file_offsets() {
            return;
        }
        let (Some(fraction), Some(dimension), Some((_, size_bytes, _))) = (
            self.frame_fraction(event.position),
            self.dimension(),
            self.target(cx),
        ) else {
            return;
        };
        let (world_x, world_y) = self.camera.world_at(fraction.0, fraction.1);
        // Fractions of a world of at most 2^15 units.
        #[allow(
            clippy::cast_precision_loss,
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss
        )]
        let (x, y) = (
            (world_x * dimension as f64) as u64,
            (world_y * dimension as f64) as u64,
        );
        let space = MapSpace {
            dimension,
            layout: self.layout,
        };
        if let Some(offset) = space.offset_at(x, y).filter(|offset| *offset < size_bytes) {
            self.set_cursor(offset, cx);
        }
    }

    fn on_scroll(&mut self, event: &ScrollEvent, window: &mut Window, cx: &mut Context<Self>) {
        let Some(anchor) = self.frame_fraction(event.position) else {
            return;
        };
        let line_height = window.rem_size() * theme::LINE_HEIGHT;
        let travel = f32::from(event.delta.pixel_delta(line_height).y);
        let factor = f64::from((travel / WHEEL_PIXELS_PER_OCTAVE).exp2());
        self.zoom(factor, anchor, cx);
    }

    /// Statistics of the 4 KiB window the probe is in.
    fn probe_stats(&mut self, entry: EntryId, engine: &Engine, cursor: u64) -> &Inspection {
        let size_bytes = engine.data().len() as u64;
        let length = size_bytes.min(PROBE_WINDOW_BYTES);
        let start = (cursor / length.max(1) * length).min(size_bytes - length);
        let is_current = self
            .probe
            .as_ref()
            .is_some_and(|probe| probe.entry == entry && probe.start == start);
        if !is_current {
            // Both fit usize: the file is resident.
            #[allow(clippy::cast_possible_truncation)]
            let stats = engine.inspect(start as usize, length as usize);
            self.probe = Some(Probe {
                entry,
                start,
                stats,
            });
        }
        &self.probe.as_ref().expect("set above").stats
    }

    /// Apeiron's measures at the cursor, cached until it moves.
    fn readouts(&mut self, entry: EntryId, scene: &Scene, cursor: u64) -> Readouts {
        if let Some(readouts) = self
            .readouts
            .filter(|r| r.entry == entry && r.cursor == cursor)
        {
            return readouts;
        }
        let data: &[u8] = scene.data();
        // Inside the resident file.
        #[allow(clippy::cast_possible_truncation)]
        let start = (cursor as usize).min(data.len());
        let window = |length: usize| &data[start..data.len().min(start + length)];
        let readouts = Readouts {
            entry,
            cursor,
            complexity: calculate_kolmogorov_complexity(window(COMPLEXITY_WINDOW_BYTES)),
            divergence: calculate_jsd(
                window(DIVERGENCE_WINDOW_BYTES),
                scene.reference_distribution(),
            ),
            multi_scale: calculate_rcmse_quick(window(MULTI_SCALE_WINDOW_BYTES)),
        };
        self.readouts = Some(readouts);
        readouts
    }

    fn render_toolbar(&self, status: String, cx: &mut Context<Self>) -> Div {
        let segment = |name: &'static str, is_active: bool| {
            small()
                .id(name)
                .px(rems(0.5))
                .py(rems(0.125))
                .cursor_pointer()
                .map(|segment| {
                    if is_active {
                        segment.bg(theme::ACCENT_WASH).text_color(theme::ACCENT)
                    } else {
                        segment
                            .text_color(theme::TEXT_MUTED)
                            .hover(|style| style.bg(theme::SURFACE_HOVER))
                    }
                })
                .child(name)
        };
        let segments = || {
            div()
                .flex()
                .flex_none()
                .border_1()
                .border_color(theme::LINE_DEFAULT)
        };
        let modes =
            segments().children(MapMode::ALL.into_iter().enumerate().map(|(index, mode)| {
                segment(mode.short_name(), mode == self.mode)
                    .when(index > 0, |segment| {
                        segment.border_l_1().border_color(theme::LINE_DEFAULT)
                    })
                    .tooltip(widgets::text_tooltip(mode.description()))
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.mode = mode;
                        this.camera = Viewport::default();
                        cx.notify();
                    }))
            }));
        let set_layout = |layout: ByteLayout| {
            cx.listener(move |this: &mut Self, _, _, cx| {
                this.layout = layout;
                this.camera = Viewport::default();
                cx.notify();
            })
        };
        // The layout only applies to modes whose points are file offsets.
        let layouts = self.mode.maps_file_offsets().then(|| {
            segments()
                .child(
                    segment("hilbert", self.layout == ByteLayout::Hilbert)
                        .on_click(set_layout(ByteLayout::Hilbert)),
                )
                .child(
                    segment("linear", self.layout == ByteLayout::Linear)
                        .border_l_1()
                        .border_color(theme::LINE_DEFAULT)
                        .on_click(set_layout(ByteLayout::Linear)),
                )
        });
        let zoom_button = |name: &'static str, factor: f64| {
            small()
                .id(name)
                .px(rems(0.5))
                .py(rems(0.125))
                .cursor_pointer()
                .hover(|style| style.bg(theme::SURFACE_HOVER))
                .on_click(cx.listener(move |this, _, _, cx| {
                    let (width, height) = frame_span(this.frame_bounds.get());
                    this.zoom(factor, (width * 0.5, height * 0.5), cx);
                }))
                .child(name)
        };
        let framing = segments()
            .child(segment("fill", self.framing == Framing::Fill)
                .tooltip(widgets::text_tooltip("Fill the pane. Drag to see the rest of the map."))
                .on_click(cx.listener(|this, _, _, cx| {
                    this.framing = Framing::Fill;
                    this.camera = Viewport::default();
                    this.followed_cursor = None;
                    cx.notify();
                })))
            .child(segment("fit", self.framing == Framing::Fit)
                .border_l_1()
                .border_color(theme::LINE_DEFAULT)
                .tooltip(widgets::text_tooltip("Fit the whole map in the pane"))
                .on_click(cx.listener(|this, _, _, cx| {
                    this.framing = Framing::Fit;
                    this.camera = Viewport::default();
                    cx.notify();
                })));
        div()
            .flex()
            .flex_none()
            .flex_wrap()
            .items_center()
            .gap_x(rems(0.5))
            .gap_y(rems(0.375))
            .min_h(rems(2.25))
            .px(rems(0.75))
            .py(rems(0.375))
            .border_b_1()
            .border_color(theme::LINE_DEFAULT)
            .child(modes)
            .children(layouts)
            .child(
                small()
                    .flex_none()
                    .text_color(theme::TEXT_MUTED)
                    .child(status),
            )
            .child(zoom_button("− out", 1.0 / ZOOM_STEP))
            .child(zoom_button("+ in", ZOOM_STEP))
            .child(framing)
            .child(text_button("map-inspector", "inspector")
                .text_size(rems(theme::TEXT_SMALL_REMS))
                .when(self.inspector == Inspector::Visible, |button| {
                    button.text_color(theme::ACCENT)
                })
                .on_click(cx.listener(|this, _, _, cx| {
                    this.inspector = match this.inspector {
                        Inspector::Visible => Inspector::Hidden,
                        Inspector::Hidden => Inspector::Visible,
                    };
                    cx.notify();
                })))
    }

    /// The map frame: the frame on screen placed by the camera, with the
    /// cursor's byte outlined. `marker` is the cursor's world cell.
    fn render_map(
        &self,
        entry: EntryId,
        dimension: u64,
        marker: Option<(u64, u64)>,
        cx: &Context<Self>,
    ) -> impl IntoElement {
        let frame_bounds = self.frame_bounds.clone();
        let mut camera = self.camera;
        let framing = self.framing;
        let entity = cx.entity_id();
        let shown = self
            .shown
            .as_ref()
            .filter(|shown| shown.entry == entry && shown.spec.mode == self.mode
                && shown.spec.layout == self.layout)
            .map(|shown| (shown.image.clone(), shown.world_min, shown.world_max));
        canvas(
            move |bounds, window, _| {
                let padding = window.rem_size() * STAGE_PADDING_REMS;
                let inner = Bounds::new(
                    point(bounds.origin.x + padding, bounds.origin.y + padding),
                    size(
                        (bounds.size.width - padding * 2.0).max(px(0.0)),
                        (bounds.size.height - padding * 2.0).max(px(0.0)),
                    ),
                );
                let frame = match framing {
                    Framing::Fill => inner,
                    Framing::Fit => {
                        let side = inner.size.width.min(inner.size.height);
                        Bounds::centered_at(inner.center(), size(side, side))
                    }
                };
                if frame_bounds.replace(frame).size != frame.size {
                    window.on_next_frame(move |_, cx| cx.notify(entity));
                }
                frame
            },
            move |_, frame, window, _| {
                let span = frame_span(frame);
                camera.clamp(span);
                window.paint_quad(fill(frame, theme::SURFACE_INSET));
                // World units to window positions. Sides are at most 2^15
                // and camera values fractions: f32 suffices on screen.
                #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
                let (world_side, camera_x, camera_y, zoom) = (
                    dimension as f32,
                    camera.x as f32,
                    camera.y as f32,
                    camera.zoom as f32,
                );
                let side = frame.size.width.max(frame.size.height);
                let place = |world: (f32, f32)| {
                    point(
                        frame.origin.x
                            + side * ((world.0 / world_side - camera_x) * zoom),
                        frame.origin.y
                            + side * ((world.1 / world_side - camera_y) * zoom),
                    )
                };
                window.with_content_mask(Some(ContentMask { bounds: frame }), |window| {
                    if let Some((image, world_min, world_max)) = shown {
                        let (top_left, bottom_right) = (place(world_min), place(world_max));
                        let target = Bounds::new(
                            top_left,
                            size(bottom_right.x - top_left.x, bottom_right.y - top_left.y),
                        );
                        // A failure leaves the frame empty for one frame.
                        let _ =
                            window.paint_image(frame, target, Corners::default(), image, 0, false);
                    }
                    if let Some((x, y)) = marker {
                        // A world cell below 2^15.
                        #[allow(clippy::cast_precision_loss)]
                        let (x, y) = (x as f32, y as f32);
                        let (top_left, bottom_right) = (place((x, y)), place((x + 1.0, y + 1.0)));
                        let side = (bottom_right.x - top_left.x).max(px(6.0));
                        let cell = Bounds::new(top_left, size(side, side));
                        window.paint_quad(outline(cell, theme::ACCENT, BorderStyle::Solid));
                    }
                });
                window.paint_quad(outline(frame, theme::LINE_DEFAULT, BorderStyle::Solid));
            },
        )
        .size_full()
    }

    /// The overview strip: the profile of the whole file, the cursor as a
    /// tick; a click moves the cursor.
    fn render_overview(
        &self,
        profile: Arc<[f32]>,
        size_bytes: u64,
        cursor: u64,
        cx: &mut Context<Self>,
    ) -> Div {
        let strip_bounds = self.strip_bounds.clone();
        let last = size_bytes.saturating_sub(1);
        // Five labels from the start to the size; sizes are at most 2^30.
        let ticks = (0..5u64).map(|tick| {
            small()
                .text_color(theme::TEXT_MUTED)
                .child(format::offset(size_bytes * tick / 4))
        });
        let marker = canvas(
            move |bounds, _, _| strip_bounds.set(bounds),
            move |bounds, (), window, _| {
                // A fraction of the file, for a pixel position.
                #[allow(clippy::cast_precision_loss)]
                let fraction = cursor as f32 / size_bytes.max(1) as f32;
                let tick = Bounds::new(
                    point(
                        bounds.origin.x + bounds.size.width * fraction,
                        bounds.origin.y,
                    ),
                    size(px(2.0), bounds.size.height),
                );
                window.paint_quad(fill(tick, theme::ACCENT));
            },
        )
        .absolute()
        .size_full();
        div()
            .flex()
            .flex_col()
            .flex_none()
            .gap(rems(0.25))
            .px(rems(1.0))
            .py(rems(0.5))
            .border_t_1()
            .border_color(theme::LINE_DEFAULT)
            .child(div().flex().justify_between().children(ticks))
            .child(
                div()
                    .id("entropy-overview")
                    .relative()
                    .w_full()
                    .h(rems(1.5))
                    .bg(theme::SURFACE_INSET)
                    .cursor_crosshair()
                    .on_mouse_down(
                        MouseButton::Left,
                        cx.listener(move |this, event: &MouseDownEvent, _, cx| {
                            let bounds = this.strip_bounds.get();
                            if bounds.size.width <= px(0.0) {
                                return;
                            }
                            let fraction = ((event.position.x - bounds.origin.x)
                                / bounds.size.width)
                                .clamp(0.0, 1.0);
                            // A position within the file, for navigation.
                            #[allow(
                                clippy::cast_precision_loss,
                                clippy::cast_possible_truncation,
                                clippy::cast_sign_loss
                            )]
                            let offset = (f64::from(fraction) * last as f64) as u64;
                            this.set_cursor(offset, cx);
                        }),
                    )
                    .child(profile_strip(profile).absolute().size_full())
                    .child(marker),
            )
    }
}

/// A titled block of the inspector.
fn inspector_section(title: &str) -> Div {
    div()
        .flex()
        .flex_col()
        .gap(rems(0.5))
        .p(rems(0.75))
        .border_b_1()
        .border_color(theme::LINE_DEFAULT)
        .child(
            small()
                .text_color(theme::TEXT_SECONDARY)
                .child(format!("[ {} ]", title.to_uppercase())),
        )
}

/// A `label … value` line of the inspector.
fn fact(label: &'static str, value: impl Into<SharedString>) -> Div {
    div()
        .flex()
        .justify_between()
        .gap(rems(0.5))
        .child(div().text_color(theme::TEXT_MUTED).child(label))
        .child(div().child(value.into()))
}

/// A large measured value with its unit note.
fn measure(label: String, value: String, note: &'static str) -> Div {
    div()
        .flex()
        .items_baseline()
        .justify_between()
        .child(div().text_color(theme::TEXT_MUTED).child(label))
        .child(
            div()
                .flex()
                .items_baseline()
                .gap(rems(0.375))
                .child(
                    div()
                        .font_family(theme::FONT_DISPLAY)
                        .font_weight(gpui::FontWeight::MEDIUM)
                        .text_size(rems(1.25))
                        .child(value),
                )
                .child(small().text_color(theme::TEXT_MUTED).child(note)),
        )
}

/// The hex excerpt around the probe: offset, bytes, ASCII.
fn mini_hex(engine: &Engine, cursor: u64) -> Div {
    let data = engine.data();
    let size_bytes = data.len() as u64;
    let (columns, rows_shown) = (MINI_HEX_COLUMNS as u64, MINI_HEX_ROWS as u64);
    let cursor_row = cursor / columns;
    let last_row = size_bytes.saturating_sub(1) / columns;
    let first_row = cursor_row
        .saturating_sub(rows_shown / 2)
        .min(last_row.saturating_sub(rows_shown - 1));
    let rows = (first_row..=last_row.min(first_row + rows_shown - 1)).map(|row| {
        let row_offset = row * columns;
        // Inside the resident file.
        #[allow(clippy::cast_possible_truncation)]
        let start = row_offset as usize;
        let bytes = &data[start.min(data.len())..data.len().min(start + MINI_HEX_COLUMNS)];
        let cell = |text: String, offset: u64, color: Rgba| {
            let is_cursor = offset == cursor;
            div()
                .w(rems(1.375))
                .text_center()
                .text_color(if is_cursor {
                    theme::TEXT_INVERSE
                } else {
                    color
                })
                .when(is_cursor, |cell| cell.bg(theme::ACCENT))
                .child(text)
        };
        let hex_cells = bytes.iter().enumerate().map(|(column, byte)| {
            let color = match byte {
                0x00 => theme::byte::ZERO,
                0xFF => theme::byte::FULL,
                0x01..=0x1F | 0x7F => theme::byte::CONTROL,
                0x20..=0x7E => theme::byte::ASCII,
                _ => theme::byte::HIGH,
            };
            cell(format!("{byte:02X}"), row_offset + column as u64, color)
        });
        let text_cells = bytes.iter().enumerate().map(|(column, byte)| {
            let glyph = if (0x20..0x7F).contains(byte) {
                char::from(*byte)
            } else {
                '.'
            };
            cell(
                glyph.to_string(),
                row_offset + column as u64,
                theme::TEXT_SECONDARY,
            )
            .w(rems(0.5625))
        });
        div()
            .flex()
            .text_size(rems(0.75))
            .line_height(rems(1.25))
            .child(
                div()
                    .w(rems(5.0))
                    .flex_none()
                    .text_color(if row == cursor_row {
                        theme::ACCENT
                    } else {
                        theme::TEXT_MUTED
                    })
                    .child(format::hex(row_offset, 8)),
            )
            .children(hex_cells)
            .child(div().w(rems(0.5)))
            .children(text_cells)
    });
    div().flex().flex_col().p(rems(0.75)).children(rows)
}

/// The byte histogram of the probe window: square-root bar heights, the
/// byte under the cursor in the accent color.
fn histogram(counts: &[u32; HISTOGRAM_BARS], probe_byte: Option<u8>) -> impl IntoElement {
    let counts = *counts;
    canvas(
        |_, _, _| (),
        move |bounds, (), window, _| {
            window.paint_quad(fill(bounds, theme::SURFACE_INSET));
            let largest = counts.iter().copied().max().unwrap_or(0).max(1);
            // 256 bars; counts are at most 4096.
            #[allow(clippy::cast_precision_loss)]
            let bar_width = bounds.size.width / HISTOGRAM_BARS as f32;
            for (value, count) in counts.iter().enumerate() {
                if *count == 0 {
                    continue;
                }
                #[allow(clippy::cast_precision_loss)]
                let share = (*count as f32 / largest as f32).sqrt();
                let height = (bounds.size.height * share).max(px(1.0));
                let is_probe = probe_byte.is_some_and(|byte| usize::from(byte) == value);
                let color = if is_probe {
                    palette::HISTOGRAM_PROBE
                } else {
                    palette::HISTOGRAM_BAR
                };
                #[allow(clippy::cast_precision_loss)]
                let left = bounds.origin.x + bar_width * value as f32;
                let bar = Bounds::new(
                    point(left, bounds.origin.y + bounds.size.height - height),
                    size(bar_width.max(px(1.0)), height),
                );
                window.paint_quad(fill(bar, rgba(color)));
            }
            window.paint_quad(outline(bounds, theme::LINE_HAIRLINE, BorderStyle::Solid));
        },
    )
    .w_full()
    .h(rems(HISTOGRAM_HEIGHT_REMS))
}

impl Render for EntropyView {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        for image in self.retired.drain(..) {
            // Releasing an image that was never uploaded is not an error.
            let _ = window.drop_image(image);
        }

        let session = self.session.read(cx);
        let Some(entry) = session.selected() else {
            return div().into_any_element();
        };
        let Some(analysis) = &entry.analysis else {
            let message = entry
                .error_message()
                .unwrap_or("The map is drawn once the file has been read.")
                .to_string();
            return div()
                .p(rems(1.5))
                .text_color(theme::TEXT_MUTED)
                .child(message)
                .into_any_element();
        };
        let (entry_id, size_bytes, cursor) = (entry.id, entry.size, entry.cursor);
        let engine = analysis.engine.clone();
        let profile = analysis.profile.clone();

        // The scene, and the frame this view calls for.
        let scene = self.scene_for(entry_id, &engine);
        scene.prepare(self.mode);
        let dimension = scene.dimension(self.mode, self.layout);
        let space = MapSpace {
            dimension,
            layout: self.layout,
        };
        let maps_offsets = self.mode.maps_file_offsets();
        let marker = (maps_offsets && size_bytes > 0).then(|| space.position_of(cursor));
        let span = frame_span(self.frame_bounds.get());
        self.camera.clamp(span);

        // When the cursor moved (from the hex tab, the overview, a click)
        // to a place the camera does not show, center the camera on it.
        if self.followed_cursor.replace((entry_id, cursor)) != Some((entry_id, cursor)) {
            if let Some((x, y)) = marker {
                // World cells below 2^15: exact in f64.
                #[allow(clippy::cast_precision_loss)]
                let (world_x, world_y) = (
                    (x as f64 + 0.5) / dimension as f64,
                    (y as f64 + 0.5) / dimension as f64,
                );
                if !self.camera.contains(world_x, world_y, span) {
                    self.camera.center(world_x, world_y, span);
                }
            }
        }

        let wanted = self.wanted_spec(&scene, window);
        let is_current = self.shown.as_ref().is_some_and(|shown| {
            shown.entry == entry_id && wanted.is_satisfied_by(&shown.spec, REDRAW_TOLERANCE)
        });
        if !is_current {
            self.request_frame(entry_id, scene.clone(), engine.clone(), wanted, window, cx);
        }
        let background = scene.background_progress(self.mode);
        if background.is_some() {
            self.schedule_progress(cx);
        }

        // Toolbar status: what is on screen and how it was drawn.
        // A world side of at most 2^15.
        #[allow(clippy::cast_precision_loss)]
        let visible_span = span.0 * dimension as f64 / self.camera.zoom;
        let renderer = match self.shown.as_ref().filter(|shown| shown.entry == entry_id) {
            Some(shown) if shown.used_gpu => "gpu",
            Some(_) => "cpu",
            None => "drawing",
        };
        let unit = if maps_offsets { "B" } else { "values" };
        let mut status = format!(
            "{visible_span:.0} {unit} across · {:.2}× · {renderer}",
            self.camera.zoom
        );
        if let Some(fraction) = background {
            // Writing to a String cannot fail.
            let _ = write!(status, " · computing {:.0}%", fraction * 100.0);
        }

        // The inspector's numbers for the cursor, on the engine's own grid.
        let grid = Grid::base(
            size_bytes,
            match self.layout {
                ByteLayout::Hilbert => Curve::Hilbert,
                ByteLayout::Linear => Curve::Linear,
            },
        );
        let (cell_column, cell_row) = grid.cell_of(cursor);
        let cell_origin = grid.origin_of(cell_column, cell_row);
        let bytes_per_cell = grid.bytes_per_cell();
        let cell_entropy = (size_bytes > 0).then(|| {
            // The map side is at most 2^15.
            #[allow(clippy::cast_possible_truncation)]
            let patch = Patch {
                side: grid.side as u32,
                scale: grid.scale as u32,
                x: cell_column as u32,
                y: cell_row as u32,
                width: 1,
                height: 1,
                curve: grid.curve,
            };
            engine.spatial_cells(&patch, 0, 1).first().copied()
        });
        let cell_entropy = cell_entropy.flatten().filter(|bits| *bits >= 0.0);
        let stats = (size_bytes > 0).then(|| self.probe_stats(entry_id, &engine, cursor).clone());
        let readouts = (size_bytes > 0).then(|| self.readouts(entry_id, &scene, cursor));
        // Inside the resident file.
        #[allow(clippy::cast_possible_truncation)]
        let probe_byte = engine.data().get(cursor as usize).copied();

        let cell_last = size_bytes
            .min(cell_origin + bytes_per_cell)
            .saturating_sub(1);
        let range = if size_bytes == 0 {
            "—".to_string()
        } else if grid.curve == Curve::Linear && grid.scale > 1 {
            format!(
                "{} × {} B @ {} · row stride {}",
                grid.scale,
                grid.scale,
                format::offset(cell_origin),
                format::size(grid.side)
            )
        } else {
            format!(
                "{}–{}",
                format::offset(cell_origin),
                format::offset(cell_last)
            )
        };
        let location = inspector_section("location")
            .child(fact("offset hex", format::offset(cursor)))
            .child(fact("offset dec", format::grouped(cursor)))
            .child(fact(
                "cell",
                format!(
                    "#{} · {}",
                    cell_origin / bytes_per_cell,
                    format::size(bytes_per_cell)
                ),
            ))
            .child(fact("range", range));

        let entropy_label = if bytes_per_cell < 256 {
            format!("shannon, {} context", format::size(size_bytes.min(256)))
        } else {
            "shannon, cell".to_string()
        };
        let entropy = inspector_section("entropy")
            .child(measure(
                entropy_label,
                cell_entropy.map_or_else(|| "—".to_string(), |bits| format!("{bits:.4}")),
                "/ 8",
            ))
            .child(meter(
                cell_entropy.unwrap_or(0.0) / palette::MAX_ENTROPY_BITS,
            ))
            .child(small().child(match cell_entropy {
                Some(bits) => format!("class {}", palette::entropy_class(f64::from(bits))),
                None => "waiting for cell analysis".to_string(),
            }));

        let ratio = stats.as_ref().and_then(|stats| stats.deflate_ratio);
        // A ratio near 1.0, for the meter only.
        #[allow(clippy::cast_possible_truncation)]
        let ratio_meter = ratio.unwrap_or(0.0).min(1.0) as f32;
        let complexity = inspector_section("complexity")
            .child(measure(
                "deflate ratio".to_string(),
                ratio.map_or_else(|| "—".to_string(), |ratio| format!("{:.2}%", ratio * 100.0)),
                "",
            ))
            .child(meter(ratio_meter))
            .child(small().child(match ratio {
                Some(ratio) => format!("class {}", palette::complexity_class(ratio)),
                None => "waiting for window analysis".to_string(),
            }))
            .when_some(stats.as_ref(), |section, stats| {
                section.child(small().text_color(theme::TEXT_MUTED).child(format!(
                    "{} window @ {} · raw DEFLATE level 6",
                    format::size(stats.length as u64),
                    format::offset(stats.start as u64)
                )))
            });

        // Apeiron's measures of the bytes at the cursor.
        let apeiron_section =
            inspector_section("apeiron").when_some(readouts, |section, readouts| {
                section
                    .child(fact(
                        "kolmogorov, 128 B",
                        format!("{:.4}", readouts.complexity),
                    ))
                    .child(fact(
                        "jsd vs file, 256 B",
                        format!("{:.4}", readouts.divergence),
                    ))
                    .child(fact(
                        "multi-scale entropy, 256 B",
                        format!("{:.4}", readouts.multi_scale),
                    ))
                    .child(fact("content", identify_file_type(scene.data())))
            });

        let histogram_section =
            inspector_section("byte histogram").when_some(stats.as_ref(), |section, stats| {
                let counts = stats.histogram;
                let distinct = counts.iter().filter(|count| **count > 0).count();
                let (top_byte, top_count) = counts
                    .iter()
                    .enumerate()
                    .max_by_key(|(value, count)| (**count, std::cmp::Reverse(*value)))
                    .map_or((0, 0), |(value, count)| (value, *count));
                // Counts within a 4 KiB window.
                #[allow(clippy::cast_precision_loss)]
                let top_share = f64::from(top_count) / stats.length.max(1) as f64;
                section
                    .child(histogram(&counts, probe_byte))
                    .child(
                        small()
                            .flex()
                            .justify_between()
                            .text_color(theme::TEXT_MUTED)
                            .child("0x00")
                            .child("0x80")
                            .child("0xff"),
                    )
                    .child(small().child(format!(
                        "{distinct} distinct · top 0x{top_byte:02X} {} · {} window",
                        format::percent(top_share),
                        format::size(stats.length as u64)
                    )))
            });

        let inspector = div()
            .id("entropy-inspector")
            .flex()
            .flex_col()
            .flex_none()
            .w(rems(22.5))
            .h_full()
            .border_l_1()
            .border_color(theme::LINE_DEFAULT)
            .overflow_y_scroll()
            .child(
                div()
                    .flex()
                    .flex_none()
                    .items_center()
                    .gap(rems(0.625))
                    .min_h(rems(2.25))
                    .px(rems(0.75))
                    .border_b_1()
                    .border_color(theme::LINE_DEFAULT)
                    .child(small().child("[ HEX ]"))
                    .child(spacer())
                    .child(badge("cursor", theme::ACCENT)),
            )
            .child(
                mini_hex(&engine, cursor)
                    .border_b_1()
                    .border_color(theme::LINE_DEFAULT),
            )
            .child(location)
            .child(entropy)
            .child(complexity)
            .child(apeiron_section)
            .child(histogram_section);

        let legend = small()
            .flex()
            .flex_none()
            .flex_wrap()
            .items_center()
            .gap(rems(0.5))
            .px(rems(1.0))
            .py(rems(0.5))
            .border_t_1()
            .border_color(theme::LINE_DEFAULT)
            .when(self.mode == MapMode::Entropy, |legend| {
                let ramp: Arc<[f32]> = (0..=160u8).map(|step| f32::from(step) / 20.0).collect();
                legend
                    .child("0")
                    .child(profile_strip(ramp).w(rems(8.0)).h(rems(0.5)))
                    .child("8 bits/byte")
            })
            .child(
                div()
                    .text_color(theme::TEXT_MUTED)
                    .child(self.mode.description()),
            )
            .child(spacer())
            .child(key_cap("drag"))
            .child(div().text_color(theme::TEXT_MUTED).child("pan"))
            .child(key_cap("wheel"))
            .child(div().text_color(theme::TEXT_MUTED).child("zoom at pointer"));

        let toolbar = self.render_toolbar(status, cx);
        let overview = self.render_overview(profile, size_bytes, cursor, cx);
        let stage = div()
            .id("entropy-stage")
            .flex_1()
            .min_h(rems(4.0))
            .min_w_0()
            .overflow_hidden()
            .on_mouse_down(MouseButton::Left, cx.listener(Self::on_mouse_down))
            .on_mouse_up(MouseButton::Left, cx.listener(Self::on_mouse_up))
            .on_scroll(cx.listener(Self::on_scroll))
            .child(self.render_map(entry_id, dimension, marker, cx));

        div()
            .id("entropy-view")
            .track_focus(&self.focus)
            .flex()
            .size_full()
            .on_mouse_move(cx.listener(Self::on_mouse_move))
            .child(
                div()
                    .flex()
                    .flex_col()
                    .flex_1()
                    .min_w_0()
                    .min_h_0()
                    .child(toolbar)
                    .child(stage)
                    .child(legend)
                    .child(overview),
            )
            .when(self.inspector == Inspector::Visible, |view| {
                view.child(inspector)
            })
            .into_any_element()
    }
}
