// Hilbert curve visualization compute shader
// Maps file bytes to a Hilbert curve with forensic color scheme
//
// Optimizations:
// - Loop unrolling for byte analysis
// - Precomputed color thresholds
// - Reduced divergence with select()

struct Uniforms {
    tex_width: u32,
    tex_height: u32,
    file_size: u32,
    dimension: u32,
    world_min_x: f32,
    world_min_y: f32,
    world_max_x: f32,
    world_max_y: f32,
}

@group(0) @binding(0) var<uniform> uniforms: Uniforms;
@group(0) @binding(1) var<storage, read> file_data: array<u32>;
@group(0) @binding(2) var output_texture: texture_storage_2d<rgba8unorm, write>;
@group(0) @binding(3) var<storage, read> precomputed: array<u32>;

const ANALYSIS_WINDOW: u32 = 64u;

// Precomputed color constants
const COLOR_PADDING: vec3<f32> = vec3<f32>(0.0, 0.0, 0.5);
const COLOR_ENCRYPTED: vec3<f32> = vec3<f32>(1.0, 0.2, 0.0);
const COLOR_TEXT: vec3<f32> = vec3<f32>(0.0, 0.8, 0.8);
const COLOR_CODE: vec3<f32> = vec3<f32>(0.0, 0.7, 0.0);
const COLOR_BACKGROUND: vec4<f32> = vec4<f32>(0.05, 0.05, 0.05, 1.0);

// Rotate/flip quadrant for Hilbert curve
fn rot(n: u32, x: ptr<function, u32>, y: ptr<function, u32>, rx: u32, ry: u32) {
    if ry == 0u {
        if rx == 1u {
            *x = n - 1u - *x;
            *y = n - 1u - *y;
        }
        let t = *x;
        *x = *y;
        *y = t;
    }
}

// Convert (x, y) to Hilbert curve index
fn xy2d(n: u32, x_in: u32, y_in: u32) -> u32 {
    var x = x_in;
    var y = y_in;
    var d = 0u;
    var s = n / 2u;
    
    while s > 0u {
        let rx = select(0u, 1u, (x & s) > 0u);
        let ry = select(0u, 1u, (y & s) > 0u);
        d = d + s * s * ((3u * rx) ^ ry);
        rot(s, &x, &y, rx, ry);
        s = s / 2u;
    }
    
    return d;
}

// Get byte at offset (file_data is packed as u32)
fn get_byte(offset: u32) -> u32 {
    if offset >= uniforms.file_size {
        return 0u;
    }
    let word_idx = offset / 4u;
    let byte_idx = offset % 4u;
    let word = file_data[word_idx];
    return (word >> (byte_idx * 8u)) & 0xFFu;
}

// Analyze bytes for forensic color mapping
struct ByteAnalysis {
    text_ratio: f32,
    high_ratio: f32,
    null_ratio: f32,
    variation: f32,
}

// Optimized byte analysis with loop unrolling
fn analyze_bytes(start: u32) -> ByteAnalysis {
    var text_chars = 0u;
    var high_bits = 0u;
    var nulls = 0u;
    var variation = 0u;
    var prev_byte = 0u;
    
    let end = min(start + ANALYSIS_WINDOW, uniforms.file_size);
    let count = end - start;
    
    if count == 0u {
        return ByteAnalysis(0.0, 0.0, 0.0, 0.0);
    }
    
    // Process first byte separately to avoid branch in loop
    var i = start;
    if i < end {
        prev_byte = get_byte(i);
        // Branchless counting using select
        text_chars = select(0u, 1u, prev_byte >= 32u && prev_byte <= 126u);
        high_bits = select(0u, 1u, prev_byte > 127u);
        nulls = select(0u, 1u, prev_byte == 0u);
        i = i + 1u;
    }
    
    // Process remaining bytes - unroll by 4 where possible
    while i + 4u <= end {
        let b0 = get_byte(i);
        let b1 = get_byte(i + 1u);
        let b2 = get_byte(i + 2u);
        let b3 = get_byte(i + 3u);
        
        // Branchless text character counting
        text_chars += select(0u, 1u, b0 >= 32u && b0 <= 126u);
        text_chars += select(0u, 1u, b1 >= 32u && b1 <= 126u);
        text_chars += select(0u, 1u, b2 >= 32u && b2 <= 126u);
        text_chars += select(0u, 1u, b3 >= 32u && b3 <= 126u);
        
        // Branchless high-bit counting
        high_bits += select(0u, 1u, b0 > 127u);
        high_bits += select(0u, 1u, b1 > 127u);
        high_bits += select(0u, 1u, b2 > 127u);
        high_bits += select(0u, 1u, b3 > 127u);
        
        // Branchless null counting
        nulls += select(0u, 1u, b0 == 0u);
        nulls += select(0u, 1u, b1 == 0u);
        nulls += select(0u, 1u, b2 == 0u);
        nulls += select(0u, 1u, b3 == 0u);
        
        // Variation (absolute differences)
        variation += select(b0 - prev_byte, prev_byte - b0, prev_byte > b0);
        variation += select(b1 - b0, b0 - b1, b0 > b1);
        variation += select(b2 - b1, b1 - b2, b1 > b2);
        variation += select(b3 - b2, b2 - b3, b2 > b3);
        
        prev_byte = b3;
        i = i + 4u;
    }
    
    // Handle remainder
    while i < end {
        let byte = get_byte(i);
        text_chars += select(0u, 1u, byte >= 32u && byte <= 126u);
        high_bits += select(0u, 1u, byte > 127u);
        nulls += select(0u, 1u, byte == 0u);
        variation += select(byte - prev_byte, prev_byte - byte, prev_byte > byte);
        prev_byte = byte;
        i = i + 1u;
    }
    
    let inv_count = 1.0 / f32(count);
    return ByteAnalysis(
        f32(text_chars) * inv_count,
        f32(high_bits) * inv_count,
        f32(nulls) * inv_count,
        f32(variation) * inv_count * 0.0078125 // 1/128
    );
}

// Map analysis to RGB color using forensic color scheme
// Optimized with reduced branching
fn analysis_to_color(a: ByteAnalysis) -> vec3<f32> {
    // Priority-based color selection with early returns
    
    // Padding / Zeroes -> Deep Blue (highest priority)
    if a.null_ratio > 0.9 {
        return vec3<f32>(0.0, 0.0, min(0.2 + 0.3 * a.null_ratio, 1.0));
    }
    
    // High Entropy / Encryption -> Red/Orange
    let is_encrypted = a.variation > 0.5 && a.high_ratio > 0.25;
    if is_encrypted {
        return COLOR_ENCRYPTED;
    }
    
    // ASCII Text -> Cyan
    if a.text_ratio > 0.85 {
        let intensity = min(fma(0.8, a.variation, 0.2), 1.0);
        return vec3<f32>(0.0, intensity, intensity);
    }
    
    // Mixed/Moderate text -> Yellow/Green gradient
    if a.text_ratio > 0.5 {
        let t = (a.text_ratio - 0.5) * 2.857143; // 1/0.35
        let intensity = min(fma(0.5, a.variation, 0.5), 1.0);
        return vec3<f32>(intensity * (1.0 - t), intensity, intensity * t);
    }
    
    // Code / Machine Instructions -> Green (default)
    let intensity = min(fma(0.5, a.variation, 0.5), 1.0);
    return vec3<f32>(0.0, intensity, 0.0);
}

@compute @workgroup_size(8, 8)
fn main(@builtin(global_invocation_id) global_id: vec3<u32>) {
    let tex_x = global_id.x;
    let tex_y = global_id.y;
    
    // Early exit for out-of-bounds
    if tex_x >= uniforms.tex_width || tex_y >= uniforms.tex_height {
        return;
    }
    
    // Precompute scale factors (could be in uniforms for extra perf)
    let inv_tex_width = 1.0 / f32(uniforms.tex_width);
    let inv_tex_height = 1.0 / f32(uniforms.tex_height);
    let scale_x = (uniforms.world_max_x - uniforms.world_min_x) * inv_tex_width;
    let scale_y = (uniforms.world_max_y - uniforms.world_min_y) * inv_tex_height;
    
    // Map texture coordinates to world coordinates using fma
    let world_x = fma(f32(tex_x), scale_x, uniforms.world_min_x);
    let world_y = fma(f32(tex_y), scale_y, uniforms.world_min_y);
    
    let x = u32(world_x);
    let y = u32(world_y);
    let n = uniforms.dimension;
    
    // Single bounds check
    if x >= n || y >= n {
        textureStore(output_texture, vec2<i32>(i32(tex_x), i32(tex_y)), COLOR_BACKGROUND);
        return;
    }
    
    let d = xy2d(n, x, y);
    
    if d >= uniforms.file_size {
        textureStore(output_texture, vec2<i32>(i32(tex_x), i32(tex_y)), COLOR_BACKGROUND);
        return;
    }
    
    let analysis = analyze_bytes(d);
    let rgb = analysis_to_color(analysis);
    textureStore(output_texture, vec2<i32>(i32(tex_x), i32(tex_y)), vec4<f32>(rgb, 1.0));
}
