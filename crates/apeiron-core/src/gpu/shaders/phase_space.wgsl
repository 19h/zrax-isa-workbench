// Byte Phase Space visualization compute shader
// Plots byte[i] vs byte[i+1] colored by position and frequency

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
@group(0) @binding(3) var<storage, read> phase_space: array<u32>; // 256x256x2 (last_pos, count)

// Convert HSV to RGB
fn hsv_to_rgb(h: f32, s: f32, v: f32) -> vec3<f32> {
    let h_mod = (h % 360.0) / 60.0;
    let c = v * s;
    let x = c * (1.0 - abs(h_mod % 2.0 - 1.0));
    let m = v - c;
    
    var rgb: vec3<f32>;
    if h_mod < 1.0 {
        rgb = vec3<f32>(c, x, 0.0);
    } else if h_mod < 2.0 {
        rgb = vec3<f32>(x, c, 0.0);
    } else if h_mod < 3.0 {
        rgb = vec3<f32>(0.0, c, x);
    } else if h_mod < 4.0 {
        rgb = vec3<f32>(0.0, x, c);
    } else if h_mod < 5.0 {
        rgb = vec3<f32>(x, 0.0, c);
    } else {
        rgb = vec3<f32>(c, 0.0, x);
    }
    
    return rgb + vec3<f32>(m, m, m);
}

// Precomputed constants
const COLOR_BACKGROUND: vec4<f32> = vec4<f32>(0.031, 0.031, 0.047, 1.0);
const HUE_COORD_SCALE: f32 = 0.703125; // 360/512

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
    
    let ps_x = i32(world_x);
    let ps_y = i32(world_y);
    
    // Early exit for out-of-bounds
    if ps_x < 0 || ps_x >= 256 || ps_y < 0 || ps_y >= 256 {
        textureStore(output_texture, vec2<i32>(i32(tex_x), i32(tex_y)), COLOR_BACKGROUND);
        return;
    }
    
    let idx = u32(ps_y * 256 + ps_x) * 2u;
    let last_pos = phase_space[idx];
    let count = phase_space[idx + 1u];
    
    if count == 0u {
        textureStore(output_texture, vec2<i32>(i32(tex_x), i32(tex_y)), COLOR_BACKGROUND);
        return;
    }
    
    // Precompute normalization factors
    let max_count = max(uniforms.file_size >> 8u, 1u); // /256 via shift
    let inv_sqrt_max = 1.0 / sqrt(f32(max_count));
    let inv_file_size = 1.0 / f32(uniforms.file_size);
    
    // Use sqrt for better contrast distribution
    let intensity = pow(sqrt(f32(count)) * inv_sqrt_max, 0.5);
    
    // Color by byte coordinates for spatial structure
    let coord_hue = f32(ps_x + ps_y) * HUE_COORD_SCALE;
    
    // Blend position-based hue with coordinate-based hue
    let position_ratio = f32(last_pos) * inv_file_size;
    let pos_hue = position_ratio * 120.0; // 0 (red) -> 120 (green)
    
    let hue = fma(coord_hue, 0.7, pos_hue * 0.3) % 360.0;
    let sat = fma(0.2, intensity, 0.75);
    let val = fma(0.9, intensity, 0.1);
    
    let rgb = hsv_to_rgb(hue, sat, val);
    textureStore(output_texture, vec2<i32>(i32(tex_x), i32(tex_y)), vec4<f32>(rgb, 1.0));
}
