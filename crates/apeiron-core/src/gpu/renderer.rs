//! GPU-accelerated visualization renderer using wgpu compute shaders.

use bytemuck::{Pod, Zeroable};
use std::sync::Arc;

use wgpu::util::DeviceExt;

/// Visualization mode for GPU rendering.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GpuVizMode {
    Hilbert,
    Digraph,
    BytePhaseSpace,
    SimilarityMatrix,
}

/// Uniform parameters passed to compute shaders.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
struct Uniforms {
    /// Output texture width.
    tex_width: u32,
    /// Output texture height.
    tex_height: u32,
    /// File size in bytes.
    file_size: u32,
    /// Hilbert curve dimension (power of 2).
    dimension: u32,
    /// Viewport world min X.
    world_min_x: f32,
    /// Viewport world min Y.
    world_min_y: f32,
    /// Viewport world max X.
    world_max_x: f32,
    /// Viewport world max Y.
    world_max_y: f32,
}

/// GPU renderer for entropy visualizations.
pub struct GpuRenderer {
    device: wgpu::Device,
    queue: wgpu::Queue,
    /// Pipeline for Hilbert visualization.
    hilbert_pipeline: wgpu::ComputePipeline,
    /// Pipeline for Digraph visualization.
    digraph_pipeline: wgpu::ComputePipeline,
    /// Pipeline for BytePhaseSpace visualization.
    phase_space_pipeline: wgpu::ComputePipeline,
    /// Pipeline for SimilarityMatrix visualization.
    similarity_pipeline: wgpu::ComputePipeline,
    /// Bind group layout shared by all pipelines.
    bind_group_layout: wgpu::BindGroupLayout,
    /// Currently loaded file data buffer.
    file_buffer: Option<wgpu::Buffer>,
    /// Current file size.
    file_size: u32,
    /// Current Hilbert dimension.
    dimension: u32,
    /// Precomputed digraph buffer (256x256 u32 counts).
    digraph_buffer: Option<wgpu::Buffer>,
    /// Precomputed phase space buffer (256x256 x2 u32: last_pos, count).
    phase_space_buffer: Option<wgpu::Buffer>,
    /// Texture and readback storage reused until output dimensions change.
    render_targets: Option<RenderTargets>,
    /// Source for preparing small axis histograms without duplicating a mapping.
    host_file: HostFile,
}

enum HostFile {
    Owned(Vec<u8>),
    Mapped(Arc<[u8]>),
}

impl AsRef<[u8]> for HostFile {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Owned(bytes) => bytes,
            Self::Mapped(mapping) => mapping,
        }
    }
}

struct RenderTargets {
    width: u32,
    height: u32,
    uniform_buffer: wgpu::Buffer,
    texture: wgpu::Texture,
    view: wgpu::TextureView,
    readback: wgpu::Buffer,
    similarity: wgpu::Buffer,
    padded_bytes_per_row: u32,
}

impl GpuRenderer {
    /// Create a new GPU renderer.
    pub fn new() -> Option<Self> {
        let instance = wgpu::Instance::new(wgpu::InstanceDescriptor {
            backends: wgpu::Backends::all(),
            ..Default::default()
        });

        let adapter = pollster::block_on(instance.request_adapter(&wgpu::RequestAdapterOptions {
            power_preference: wgpu::PowerPreference::HighPerformance,
            compatible_surface: None,
            force_fallback_adapter: false,
        }))?;

        let (device, queue) = pollster::block_on(adapter.request_device(
            &wgpu::DeviceDescriptor {
                label: Some("Apeiron GPU"),
                required_features: wgpu::Features::empty(),
                required_limits: wgpu::Limits::default(),
                memory_hints: wgpu::MemoryHints::Performance,
            },
            None,
        ))
        .ok()?;

        // Create bind group layout shared by all compute shaders
        let bind_group_layout = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
            label: Some("Compute Bind Group Layout"),
            entries: &[
                // Uniform buffer
                wgpu::BindGroupLayoutEntry {
                    binding: 0,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Uniform,
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
                // File data buffer (read-only)
                wgpu::BindGroupLayoutEntry {
                    binding: 1,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Storage { read_only: true },
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
                // Output texture (write)
                wgpu::BindGroupLayoutEntry {
                    binding: 2,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::StorageTexture {
                        access: wgpu::StorageTextureAccess::WriteOnly,
                        format: wgpu::TextureFormat::Rgba8Unorm,
                        view_dimension: wgpu::TextureViewDimension::D2,
                    },
                    count: None,
                },
                // Precomputed data buffer (for digraph/phase space)
                wgpu::BindGroupLayoutEntry {
                    binding: 3,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Storage { read_only: true },
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
            ],
        });

        let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
            label: Some("Compute Pipeline Layout"),
            bind_group_layouts: &[&bind_group_layout],
            push_constant_ranges: &[],
        });

        // Create compute pipelines for each visualization
        let hilbert_pipeline = Self::create_pipeline(
            &device,
            &pipeline_layout,
            include_str!("shaders/hilbert.wgsl"),
        );
        let digraph_pipeline = Self::create_pipeline(
            &device,
            &pipeline_layout,
            include_str!("shaders/digraph.wgsl"),
        );
        let phase_space_pipeline = Self::create_pipeline(
            &device,
            &pipeline_layout,
            include_str!("shaders/phase_space.wgsl"),
        );
        let similarity_pipeline = Self::create_pipeline(
            &device,
            &pipeline_layout,
            include_str!("shaders/similarity.wgsl"),
        );

        Some(Self {
            device,
            queue,
            hilbert_pipeline,
            digraph_pipeline,
            phase_space_pipeline,
            similarity_pipeline,
            bind_group_layout,
            file_buffer: None,
            file_size: 0,
            dimension: 0,
            digraph_buffer: None,
            phase_space_buffer: None,
            render_targets: None,
            host_file: HostFile::Owned(Vec::new()),
        })
    }

    fn create_pipeline(
        device: &wgpu::Device,
        layout: &wgpu::PipelineLayout,
        shader_source: &str,
    ) -> wgpu::ComputePipeline {
        let shader_module = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("Compute Shader"),
            source: wgpu::ShaderSource::Wgsl(shader_source.into()),
        });

        device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
            label: Some("Compute Pipeline"),
            layout: Some(layout),
            module: &shader_module,
            entry_point: Some("main"),
            compilation_options: Default::default(),
            cache: None,
        })
    }

    /// Maximum file size for GPU upload (128MB is wgpu's max_storage_buffer_binding_size)
    const MAX_GPU_FILE_SIZE: usize = 120 * 1024 * 1024;

    /// Upload file data to GPU and precompute derived data.
    /// Returns false if file is too large for GPU.
    pub fn upload_file(&mut self, data: &[u8], dimension: u64) -> bool {
        let uploaded = self.upload_bytes(data, dimension);
        if uploaded {
            self.host_file = HostFile::Owned(data.to_vec());
        }
        uploaded
    }

    /// Upload a mapped file while retaining its shared source for axis sampling.
    pub fn upload_mapped_file(&mut self, data: Arc<[u8]>, dimension: u64) -> bool {
        let uploaded = self.upload_bytes(&data, dimension);
        if uploaded {
            self.host_file = HostFile::Mapped(data);
        }
        uploaded
    }

    fn upload_bytes(&mut self, data: &[u8], dimension: u64) -> bool {
        self.host_file = HostFile::Owned(Vec::new());
        self.file_size = data.len() as u32;
        self.dimension = dimension as u32;

        // Check if file is too large for GPU buffer
        if data.len() > Self::MAX_GPU_FILE_SIZE {
            println!(
                "File too large for GPU ({} MB > {} MB limit), using CPU fallback",
                data.len() / (1024 * 1024),
                Self::MAX_GPU_FILE_SIZE / (1024 * 1024)
            );
            self.file_buffer = None;
            self.digraph_buffer = None;
            self.phase_space_buffer = None;
            return false;
        }

        // WGSL reads array<u32>; the final word must exist for 1-3 trailing bytes.
        if data.is_empty() {
            self.file_buffer = None;
            self.digraph_buffer = None;
            self.phase_space_buffer = None;
            return false;
        }
        let padded;
        let bytes = if data.len() % 4 == 0 {
            data
        } else {
            let mut bytes = Vec::with_capacity(data.len().div_ceil(4) * 4);
            bytes.extend_from_slice(data);
            bytes.resize(data.len().div_ceil(4) * 4, 0);
            padded = bytes;
            &padded
        };
        // Upload raw file data
        self.file_buffer = Some(self.device.create_buffer_init(
            &wgpu::util::BufferInitDescriptor {
                label: Some("File Data Buffer"),
                contents: bytes,
                usage: wgpu::BufferUsages::STORAGE,
            },
        ));

        // Transition statistics are deferred until their mode is first rendered.
        self.digraph_buffer = None;
        self.phase_space_buffer = None;
        true
    }

    fn ensure_transitions(&mut self, mode: GpuVizMode) {
        let data = self.host_file.as_ref();
        if mode == GpuVizMode::Digraph && self.digraph_buffer.is_none() {
            let mut counts = vec![0u32; 256 * 256];
            for pair in data.windows(2) {
                counts[pair[0] as usize * 256 + pair[1] as usize] += 1;
            }
            self.digraph_buffer = Some(self.device.create_buffer_init(
                &wgpu::util::BufferInitDescriptor {
                    label: Some("Digraph Buffer"),
                    contents: bytemuck::cast_slice(&counts),
                    usage: wgpu::BufferUsages::STORAGE,
                },
            ));
        }
        if mode == GpuVizMode::BytePhaseSpace && self.phase_space_buffer.is_none() {
            let mut space = vec![0u32; 256 * 256 * 2];
            for (position, pair) in data.windows(2).enumerate() {
                let index = (pair[1] as usize * 256 + pair[0] as usize) * 2;
                space[index] = position as u32;
                space[index + 1] += 1;
            }
            self.phase_space_buffer = Some(self.device.create_buffer_init(
                &wgpu::util::BufferInitDescriptor {
                    label: Some("Phase Space Buffer"),
                    contents: bytemuck::cast_slice(&space),
                    usage: wgpu::BufferUsages::STORAGE,
                },
            ));
        }
    }

    /// Render visualization to RGBA pixel data.
    pub fn render(
        &mut self,
        mode: GpuVizMode,
        tex_width: u32,
        tex_height: u32,
        world_min_x: f32,
        world_min_y: f32,
        world_max_x: f32,
        world_max_y: f32,
    ) -> Vec<u8> {
        if tex_width == 0 || tex_height == 0 {
            return Vec::new();
        }
        if self.file_buffer.is_some() {
            self.ensure_transitions(mode);
        }
        let Some(file_buffer) = &self.file_buffer else {
            return vec![0u8; (tex_width * tex_height * 4) as usize];
        };

        // Create uniform buffer
        let uniforms = Uniforms {
            tex_width,
            tex_height,
            file_size: self.file_size,
            dimension: self.dimension,
            world_min_x,
            world_min_y,
            world_max_x,
            world_max_y,
        };

        if self
            .render_targets
            .as_ref()
            .map(|targets| targets.width != tex_width || targets.height != tex_height)
            .unwrap_or(true)
        {
            let uniform_buffer =
                self.device
                    .create_buffer_init(&wgpu::util::BufferInitDescriptor {
                        label: Some("Uniform Buffer"),
                        contents: bytemuck::bytes_of(&uniforms),
                        usage: wgpu::BufferUsages::UNIFORM | wgpu::BufferUsages::COPY_DST,
                    });

            // Create output texture
            let output_texture = self.device.create_texture(&wgpu::TextureDescriptor {
                label: Some("Output Texture"),
                size: wgpu::Extent3d {
                    width: tex_width,
                    height: tex_height,
                    depth_or_array_layers: 1,
                },
                mip_level_count: 1,
                sample_count: 1,
                dimension: wgpu::TextureDimension::D2,
                format: wgpu::TextureFormat::Rgba8Unorm,
                usage: wgpu::TextureUsages::STORAGE_BINDING | wgpu::TextureUsages::COPY_SRC,
                view_formats: &[],
            });
            let output_view = output_texture.create_view(&Default::default());

            // Create output buffer for reading back
            // bytes_per_row must be aligned to COPY_BYTES_PER_ROW_ALIGNMENT (256)
            let unpadded_bytes_per_row = tex_width * 4;
            let align = wgpu::COPY_BYTES_PER_ROW_ALIGNMENT;
            let padded_bytes_per_row = (unpadded_bytes_per_row + align - 1) / align * align;
            let output_buffer_size = (padded_bytes_per_row * tex_height) as u64;
            let output_buffer = self.device.create_buffer(&wgpu::BufferDescriptor {
                label: Some("Output Buffer"),
                size: output_buffer_size,
                usage: wgpu::BufferUsages::COPY_DST | wgpu::BufferUsages::MAP_READ,
                mapped_at_creation: false,
            });
            let similarity = self.device.create_buffer(&wgpu::BufferDescriptor {
                label: Some("Similarity Axis Histograms"),
                size: u64::from(tex_width + tex_height) * 16 * 4,
                usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST,
                mapped_at_creation: false,
            });

            self.render_targets = Some(RenderTargets {
                width: tex_width,
                height: tex_height,
                uniform_buffer,
                texture: output_texture,
                view: output_view,
                readback: output_buffer,
                similarity,
                padded_bytes_per_row,
            });
        }
        let targets = self.render_targets.as_ref().unwrap();
        self.queue
            .write_buffer(&targets.uniform_buffer, 0, bytemuck::bytes_of(&uniforms));
        let uniform_buffer = &targets.uniform_buffer;
        let output_texture = &targets.texture;
        let output_view = &targets.view;
        let output_buffer = &targets.readback;
        let padded_bytes_per_row = targets.padded_bytes_per_row;
        let unpadded_bytes_per_row = tex_width * 4;

        if mode == GpuVizMode::SimilarityMatrix {
            let host_file = self.host_file.as_ref();
            let mut histograms = Vec::with_capacity((tex_width + tex_height) as usize * 16);
            for (count, min, max) in [
                (tex_width, world_min_x, world_max_x),
                (tex_height, world_min_y, world_max_y),
            ] {
                let scale = (max - min) * (1.0 / count as f32);
                let file_scale = self.file_size as f32 * (1.0 / self.dimension as f32);
                for index in 0..count {
                    let world = (index as f32).mul_add(scale, min);
                    let start = (world * file_scale) as usize;
                    let end = start.saturating_add(32).min(host_file.len());
                    let mut counts = [0u32; 16];
                    if start < end {
                        for &byte in &host_file[start..end] {
                            counts[(byte >> 4) as usize] += 1;
                        }
                    }
                    let inverse = if start < end {
                        1.0 / (end - start) as f32
                    } else {
                        0.0
                    };
                    histograms.extend(counts.map(|c| c as f32 * inverse));
                }
            }
            self.queue
                .write_buffer(&targets.similarity, 0, bytemuck::cast_slice(&histograms));
        }

        // Select pipeline and precomputed buffer based on mode
        let (pipeline, precomputed_buffer) = match mode {
            GpuVizMode::Hilbert => (&self.hilbert_pipeline, file_buffer),
            GpuVizMode::Digraph => (
                &self.digraph_pipeline,
                self.digraph_buffer.as_ref().unwrap_or(file_buffer),
            ),
            GpuVizMode::BytePhaseSpace => (
                &self.phase_space_pipeline,
                self.phase_space_buffer.as_ref().unwrap_or(file_buffer),
            ),
            GpuVizMode::SimilarityMatrix => (&self.similarity_pipeline, &targets.similarity),
        };

        // Create bind group
        let bind_group = self.device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("Compute Bind Group"),
            layout: &self.bind_group_layout,
            entries: &[
                wgpu::BindGroupEntry {
                    binding: 0,
                    resource: uniform_buffer.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 1,
                    resource: file_buffer.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 2,
                    resource: wgpu::BindingResource::TextureView(output_view),
                },
                wgpu::BindGroupEntry {
                    binding: 3,
                    resource: precomputed_buffer.as_entire_binding(),
                },
            ],
        });

        // Encode and submit compute pass
        let mut encoder = self
            .device
            .create_command_encoder(&wgpu::CommandEncoderDescriptor {
                label: Some("Compute Encoder"),
            });

        {
            let mut compute_pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
                label: Some("Compute Pass"),
                timestamp_writes: None,
            });
            compute_pass.set_pipeline(pipeline);
            compute_pass.set_bind_group(0, &bind_group, &[]);
            // Dispatch workgroups (8x8 threads per group)
            let workgroups_x = (tex_width + 7) / 8;
            let workgroups_y = (tex_height + 7) / 8;
            compute_pass.dispatch_workgroups(workgroups_x, workgroups_y, 1);
        }

        // Copy texture to buffer
        encoder.copy_texture_to_buffer(
            wgpu::ImageCopyTexture {
                texture: output_texture,
                mip_level: 0,
                origin: wgpu::Origin3d::ZERO,
                aspect: wgpu::TextureAspect::All,
            },
            wgpu::ImageCopyBuffer {
                buffer: output_buffer,
                layout: wgpu::ImageDataLayout {
                    offset: 0,
                    bytes_per_row: Some(padded_bytes_per_row),
                    rows_per_image: Some(tex_height),
                },
            },
            wgpu::Extent3d {
                width: tex_width,
                height: tex_height,
                depth_or_array_layers: 1,
            },
        );

        self.queue.submit(std::iter::once(encoder.finish()));

        // Read back the result with timeout to avoid deadlock
        let buffer_slice = output_buffer.slice(..);
        let (tx, rx) = std::sync::mpsc::channel();
        buffer_slice.map_async(wgpu::MapMode::Read, move |result| {
            let _ = tx.send(result); // Ignore send error if receiver dropped
        });

        // Poll with timeout - try multiple times with short polls
        let timeout = std::time::Duration::from_secs(5);
        let start = std::time::Instant::now();
        loop {
            self.device.poll(wgpu::Maintain::Poll);
            match rx.try_recv() {
                Ok(Ok(())) => break,
                Ok(Err(e)) => {
                    eprintln!("GPU buffer mapping error: {:?}", e);
                    self.render_targets = None;
                    return vec![0u8; (tex_width * tex_height * 4) as usize];
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    if start.elapsed() > timeout {
                        eprintln!("GPU readback timeout - falling back to empty texture");
                        output_buffer.unmap();
                        self.render_targets = None;
                        return vec![0u8; (tex_width * tex_height * 4) as usize];
                    }
                    if start.elapsed() < std::time::Duration::from_micros(250) {
                        std::thread::yield_now();
                    } else {
                        std::thread::sleep(std::time::Duration::from_micros(250));
                    }
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    eprintln!("GPU channel disconnected");
                    output_buffer.unmap();
                    self.render_targets = None;
                    return vec![0u8; (tex_width * tex_height * 4) as usize];
                }
            }
        }

        let data = buffer_slice.get_mapped_range();

        // Remove row padding if present
        let result = if padded_bytes_per_row != unpadded_bytes_per_row {
            let mut unpacked = Vec::with_capacity((tex_width * tex_height * 4) as usize);
            for row in 0..tex_height {
                let start = (row * padded_bytes_per_row) as usize;
                let end = start + unpadded_bytes_per_row as usize;
                unpacked.extend_from_slice(&data[start..end]);
            }
            unpacked
        } else {
            data.to_vec()
        };

        drop(data);
        output_buffer.unmap();

        result
    }

    /// Check if GPU renderer is available and has file loaded.
    pub fn is_ready(&self) -> bool {
        self.file_buffer.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires a native GPU adapter"]
    fn native_gpu_reuses_targets_and_handles_trailing_bytes() {
        let mut gpu = GpuRenderer::new().expect("native GPU adapter required");
        for len in [1, 2, 3, 5, 63, 129] {
            let data = vec![0; len];
            assert!(gpu.upload_file(&data, 64));
            for size in [1, 7, 64, 257] {
                for mode in [
                    GpuVizMode::Hilbert,
                    GpuVizMode::SimilarityMatrix,
                    GpuVizMode::Digraph,
                    GpuVizMode::BytePhaseSpace,
                ] {
                    let first = gpu.render(mode, size, size, 0.0, 0.0, 64.0, 64.0);
                    let second = gpu.render(mode, size, size, 0.0, 0.0, 64.0, 64.0);
                    assert_eq!(first.len(), size as usize * size as usize * 4);
                    assert_eq!(first, second);
                    assert!(first.chunks_exact(4).all(|p| p[3] == 255));
                }
            }
            // Force the last byte through the shader's packed-u32 read.
            let (x, y) = crate::hilbert::d2xy(64, len as u64 - 1);
            let pixel = gpu.render(
                GpuVizMode::Hilbert,
                1,
                1,
                x as f32,
                y as f32,
                x as f32 + 1.0,
                y as f32 + 1.0,
            );
            assert_eq!(pixel, [0, 0, 128, 255]);
        }
        assert!(gpu
            .render(GpuVizMode::Hilbert, 0, 0, 0.0, 0.0, 1.0, 1.0)
            .is_empty());
        assert!(!gpu.upload_file(&[], 64));
        assert!(!gpu.is_ready());
    }

    #[test]
    #[ignore = "requires a native GPU adapter"]
    fn native_similarity_precomputed_axes_match_scalar_colors() {
        let mut gpu = GpuRenderer::new().expect("native GPU adapter required");
        let data: Vec<u8> = (0..513).map(|i| (i * 137 + i / 5) as u8).collect();
        assert!(gpu.upload_file(&data, 64));
        let size = 17u32;
        let pixels = gpu.render(
            GpuVizMode::SimilarityMatrix,
            size,
            size,
            0.0,
            0.0,
            64.0,
            64.0,
        );
        let hist = |index: u32| {
            let scale = 64.0 * (1.0 / size as f32);
            let world = (index as f32).mul_add(scale, 0.0);
            let pos = (world * (513.0 / 64.0)) as usize;
            let end = (pos + 32).min(data.len());
            let mut bins = [0.0; 16];
            for &byte in &data[pos..end] {
                bins[(byte >> 4) as usize] += 1.0 / (end - pos) as f64;
            }
            (pos, bins)
        };
        for y in 0..size {
            for x in 0..size {
                let (px, hx) = hist(x);
                let (py, hy) = hist(y);
                let distance: f64 = hx
                    .iter()
                    .zip(hy)
                    .map(|(&p, q)| {
                        if p + q == 0.0 {
                            0.0
                        } else {
                            (p - q).powi(2) / (p + q)
                        }
                    })
                    .sum();
                let expected = crate::viz::similarity_to_color(
                    1.0 - (distance / 2.0).sqrt(),
                    px.abs_diff(py) < 32,
                );
                let actual = &pixels[((y * size + x) * 4) as usize..][..3];
                // WGSL's existing diagonal palette starts at 0.7 rather than
                // the CPU's 180/255. Away from the diagonal, allow quantization.
                if px.abs_diff(py) >= 32 {
                    for (&a, e) in actual.iter().zip(expected.to_array()) {
                        assert!(a.abs_diff(e) <= 2);
                    }
                }
            }
        }
    }
}
