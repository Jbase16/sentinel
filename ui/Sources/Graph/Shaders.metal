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
    constant float4x4 &viewProjectionMatrix [[buffer(1)]],
    constant float4x4 &modelMatrix [[buffer(2)]],
    constant float &time [[buffer(3)]]
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
    float vibration = 0.05 + (temperature * 0.5); // Baseline breath + Friction
    float breath = sin(time * (1.5 + temperature * 10.0) + pos.x * 5.0 + pos.y * 3.0) * vibration;
    pos += float3(breath * 0.5, breath * 0.5, 0.0);
    
    // GRAVITY (Mass)
    // Heavier nodes are larger visually
    float visualSize = baseSize + (mass * 0.5);
    
    // Project to Screen
    out.position = viewProjectionMatrix * float4(pos, 1.0);
    
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
    
    float3 finalColor = in.color.rgb;
    
    // Add a hot white core
    finalColor += float3(1.0) * core * 0.8;
    
    // Alpha falloff
    float alpha = in.color.a * glow;
    
    return float4(finalColor, alpha);
}

// --- Line Fragment Shader (for edges) ---
fragment float4 fragment_line(
    VertexOut in [[stage_in]]
) {
    return float4(in.color.rgb, in.color.a);
}
