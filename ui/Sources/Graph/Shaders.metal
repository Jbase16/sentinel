/*
Shaders.metal
The Visual Cortex of the Neural Interface.
Renders pulsating nodes and data-flow edges.
*/

#include <metal_stdlib>
using namespace metal;

struct VertexIn {
    float4 position [[attribute(0)]]; // xyz = pos, w = size
    float4 color [[attribute(1)]];
    float4 physics [[attribute(2)]];  // x=mass, y=charge, z=temp, w=structural
};

// --- Vertex Shader ---
struct VertexOut {
    float4 position [[position]];
    float4 color;
    float size [[point_size]];
    float depth; // Pass depth for fogging
};

vertex VertexOut vertex_main(
    VertexIn in [[stage_in]],
    constant Uniforms &uniforms [[buffer(1)]]
) {
    VertexOut out;
    
    // Animate Position (Subtle "Breathing" Data)
    float3 pos = in.position.xyz; // Unpack xyz
    float baseSize = in.position.w;   // Unpack size
    
    // Physics Properties
    float mass = in.physics.x;        // Gravity
    // float charge = in.physics.y;      // Polarity (Unused for now)
    float temperature = in.physics.z; // Friction/Heat
    // float structural = in.physics.w;  // 1.0 = Rigid
    
    // VIBRATION (Temperature)
    // High temperature (Friction) causes violent vibration
    // NOW 3D: Breathe in all axes, especially Z for depth perception
    float vibration = 0.05 + (temperature * 0.5); // Baseline breath + Friction
    float breath = sin(uniforms.time * (1.5 + temperature * 10.0) + pos.x * 5.0 + pos.y * 3.0) * vibration;
    pos += float3(breath * 0.4, breath * 0.4, breath * 0.6); // Exaggerate Z motion
    
    // GRAVITY (Mass)
    // Heavier nodes are larger visually
    float visualSize = baseSize + (mass * 0.5);
    
    // Project to Screen
    // Apply model rotation then view-projection
    float4 worldPos = uniforms.modelMatrix * float4(pos, 1.0);
    out.position = uniforms.viewProjectionMatrix * worldPos;
    out.depth = out.position.w; // Store linear depth for fog
    
    // Size attenuation based on depth
    out.size = max(5.0, visualSize * (100.0 / (out.position.w + 0.1)));
    
    out.color = in.color;
    return out;
}

// --- Fragment Shader ---
fragment float4 fragment_main(
    VertexOut in [[stage_in]],
    float2 pointCoord [[point_coord]]
) {
    // Cyberpunk Hex/Orbs
    float2 coord = pointCoord * 2.0 - 1.0; // -1 to 1
    float dist = length(coord);
    
    if (dist > 1.0) {
        discard_fragment();
    }
    
    // Hard core, soft glow edge
    float core = 1.0 - smoothstep(0.3, 0.4, dist);
    float glow = 1.0 - smoothstep(0.4, 1.0, dist);
    
    // Depth Fog / Contrast Compression
    // Map depth (approx 50 to 500) to 0..1 range
    float fog = clamp((in.depth - 50.0) / 400.0, 0.0, 1.0);
    
    float3 finalColor = in.color.rgb;
    
    // Modulate brightness with depth - subtle darkening
    finalColor *= mix(1.2, 0.6, fog);
    
    // Add a hot white core
    finalColor += float3(1.0) * core * 0.8;
    
    // Alpha falloff with depth (distant nodes more transparent)
    float alpha = in.color.a * glow * mix(1.0, 0.4, fog);
    
    return float4(finalColor, alpha);
}

// --- Line Fragment Shader (for edges) ---
fragment float4 fragment_line(
    VertexOut in [[stage_in]]
) {
    // Fade edges with depth so they don't form a flat spiderweb
    float fade = clamp(1.0 - (in.depth / 600.0), 0.05, 1.0);
    return float4(in.color.rgb, in.color.a * fade);
}
