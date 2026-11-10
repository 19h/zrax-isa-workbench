// Similarity Matrix visualization compute shader
// Shows recurrence plot based on chi-squared distance between byte histograms
//
// Optimizations:
// - One precomputed normalized histogram per axis coordinate
// - Histogram reuse across all row/column comparisons

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
@group(0) @binding(3) var<storage, read> precomputed: array<f32>;

const WINDOW_SIZE: u32 = 32u;
const COLOR_BACKGROUND: vec4<f32> = vec4<f32>(0.039, 0.039, 0.059, 1.0);

// Each axis window is normalized once on the host, instead of constructing
// two private histograms and reading 64 file bytes in every output invocation.
fn chi_squared_distance(tex_x: u32, tex_y: u32) -> f32 {
    let base_x = tex_x * 16u;
    let base_y = (uniforms.tex_width + tex_y) * 16u;
    var chi_sq = 0.0;
    var total_x = 0.0;
    var total_y = 0.0;
    for (var i = 0u; i < 16u; i = i + 1u) {
        let px = precomputed[base_x + i];
        let py = precomputed[base_y + i];
        total_x += px;
        total_y += py;
        let sum = px + py;
        let diff = px - py;
        if sum > 0.0 { chi_sq += diff * diff / sum; }
    }
    if total_x == 0.0 || total_y == 0.0 { return 0.0; }
    return chi_sq;
}

// Convert similarity to color using inferno-style colormap
fn similarity_to_color(similarity: f32, is_diagonal: bool) -> vec3<f32> {
    // Apply gamma curve to enhance contrast
    let t = pow(clamp(similarity, 0.0, 1.0), 0.4);
    
    if is_diagonal {
        // Diagonal elements - bright cyan/white
        return vec3<f32>(0.7 + t * 0.3, 0.86 + t * 0.14, 1.0);
    }
    
    // Inferno-inspired colormap
    if t < 0.2 {
        let s = t / 0.2;
        return vec3<f32>(s * 0.25, 0.0, s * 0.35);
    } else if t < 0.4 {
        let s = (t - 0.2) / 0.2;
        return vec3<f32>(0.25 + s * 0.45, 0.0, 0.35 + s * 0.1);
    } else if t < 0.6 {
        let s = (t - 0.4) / 0.2;
        return vec3<f32>(0.7 + s * 0.25, s * 0.25, 0.45 - s * 0.35);
    } else if t < 0.8 {
        let s = (t - 0.6) / 0.2;
        return vec3<f32>(0.95 + s * 0.05, 0.25 + s * 0.45, 0.1 + s * 0.1);
    } else {
        let s = (t - 0.8) / 0.2;
        return vec3<f32>(1.0, 0.7 + s * 0.3, 0.2 + s * 0.7);
    }
}

@compute @workgroup_size(8, 8)
fn main(@builtin(global_invocation_id) global_id: vec3<u32>) {
    let tex_x = global_id.x;
    let tex_y = global_id.y;
    
    if tex_x >= uniforms.tex_width || tex_y >= uniforms.tex_height {
        return;
    }
    
    // Precompute scale factors
    let inv_tex_width = 1.0 / f32(uniforms.tex_width);
    let inv_tex_height = 1.0 / f32(uniforms.tex_height);
    let scale_x = (uniforms.world_max_x - uniforms.world_min_x) * inv_tex_width;
    let scale_y = (uniforms.world_max_y - uniforms.world_min_y) * inv_tex_height;
    let world_x = fma(f32(tex_x), scale_x, uniforms.world_min_x);
    let world_y = fma(f32(tex_y), scale_y, uniforms.world_min_y);
    
    let dim = f32(uniforms.dimension);
    
    // Early exit for out-of-bounds
    if world_x < 0.0 || world_y < 0.0 || world_x >= dim || world_y >= dim {
        textureStore(output_texture, vec2<i32>(i32(tex_x), i32(tex_y)), COLOR_BACKGROUND);
        return;
    }
    
    // Map world coordinates to file positions
    let inv_dim = 1.0 / dim;
    let file_scale = f32(uniforms.file_size) * inv_dim;
    let pos_x = u32(world_x * file_scale);
    let pos_y = u32(world_y * file_scale);
    
    let chi_sq = chi_squared_distance(tex_x, tex_y);

    // Convert distance to similarity (chi_sq ranges from 0 to 2)
    // sqrt(chi_sq/2) = sqrt(chi_sq) * 0.7071...
    let similarity = 1.0 - sqrt(chi_sq) * 0.70710678;
    
    let is_diagonal = abs(i32(pos_x) - i32(pos_y)) < i32(WINDOW_SIZE);
    let rgb = similarity_to_color(similarity, is_diagonal);
    textureStore(output_texture, vec2<i32>(i32(tex_x), i32(tex_y)), vec4<f32>(rgb, 1.0));
}
