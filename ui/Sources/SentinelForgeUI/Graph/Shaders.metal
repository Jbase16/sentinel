/*
Shaders.metal
The Visual Cortex of the Neural Interface.
Renders pulsating nodes and data-flow edges.
*/

#include <metal_stdlib>
using namespace metal;

struct VertexIn {
    float3 position [[attribute(0)]];
    float4 color [[attribute(1)]];
    float size [[attribute(2)]];
};

struct VertexOut {
    float4 position [[position]];
    float4 color;
    float size [[point_size]];
};

struct Uniforms {
    float4x4 view_projection_matrix;
    float4x4 model_matrix;
    float time;
};

// --- Vertex Shader ---
vertex VertexOut vertex_main(
    VertexIn in [[stage_in]],
    constant Uniforms &uniforms [[buffer(1)]]
) {
    VertexOut out;
    
    // Animate Position (Subtle "Breathing" Data)
    float3 pos = in.position;
    float breath = sin(uniforms.time * 1.5 + pos.x * 5.0 + pos.y * 3.0) * 0.05;
    pos *= (1.0 + breath * 0.2);
    
    // Project to Screen
    out.position = uniforms.view_projection_matrix * float4(pos, 1.0);
    
    // Size attenuation based on depth
    // float depth = out.position.z; 
    out.size = max(5.0, in.size * (100.0 / (out.position.w + 0.1)));
    
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
    
    float3 finalColor = in.color.rgb;
    
    // Add a hot white core
    finalColor += float3(1.0) * core * 0.8;
    
    // Alpha falloff
    float alpha = in.color.a * glow;
    
    return float4(finalColor, alpha);
}
