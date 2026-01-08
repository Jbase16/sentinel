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
    float4 physics [[attribute(2)]];  // x=mass, y=charge, z=temp, w=PRESSURE
};

struct Uniforms {
    float4x4 viewProjectionMatrix;
    float4x4 modelMatrix;
    float time;
    int selectedNodeIndex; // -1 = None
    float2 _pad; // Explicit padding to match 16-byte alignment
};

// --- Vertex Shader ---
struct VertexOut {
    float4 position [[position]];
    float4 color;
    float size [[point_size]];
    float depth; 
    float pressure;
    float isSelected; // 1.0 if selected, 0.0 otherwise
};

vertex VertexOut vertex_main(
    VertexIn in [[stage_in]],
    constant Uniforms &uniforms [[buffer(1)]],
    uint vid [[vertex_id]]
) {
    VertexOut out;
    
    // Check Selection
    bool isSelected = (int(vid) == uniforms.selectedNodeIndex);
    bool hasSelection = (uniforms.selectedNodeIndex != -1);
    out.isSelected = isSelected ? 1.0 : 0.0;
    
    // Animate Position (Subtle "Breathing" Data)
    float3 pos = in.position.xyz; // Unpack xyz
    float baseSize = in.position.w;   // Unpack size
    
    // Physics Properties
    float mass = in.physics.x;        // Gravity
    float temperature = in.physics.z; // Friction/Heat
    float pressure = in.physics.w;    // Semantic Pressure (0.0 to 1.0)
    
    out.pressure = pressure;
    
    // VIBRATION
    float baseVibe = 0.05 + (temperature * 0.2);
    float pressureVibe = pressure * 0.3; 
    float vibration = baseVibe + pressureVibe;
    
    // Multi-axis breathing
    float t = uniforms.time;
    float breathX = sin(t * (1.5 + pressure * 5.0) + pos.x) * vibration;
    float breathY = cos(t * (1.2 + pressure * 5.0) + pos.y) * vibration;
    float breathZ = sin(t * (2.0 + pressure * 8.0) + pos.z) * vibration * 1.5;
    
    pos += float3(breathX, breathY, breathZ);
    
    // Pulse
    float pulse = 1.0 + (sin(t * 8.0) * 0.1 * pressure);
    float visualSize = (baseSize + (mass * 0.5)) * pulse;
    
    // Selection Highlight: Selected node gets bigger
    if (isSelected) {
        visualSize *= 1.5;
    }
    
    // Project to Screen
    float4 worldPos = uniforms.modelMatrix * float4(pos, 1.0);
    out.position = uniforms.viewProjectionMatrix * worldPos;
    
    // DEPTH FIX
    out.depth = out.position.w; 
    
    // Size attenuation
    out.size = max(5.0, visualSize * (100.0 / (out.position.w + 0.1)));
    
    // If something IS selected, but this node is NOT selected, fade it out
    // We handle color/alpha dimming in fragment, but we can pass modified color here
    out.color = in.color;
    
    return out;
}

// --- Fragment Shader ---
fragment float4 fragment_main(
    VertexOut in [[stage_in]],
    float2 pointCoord [[point_coord]],
    constant Uniforms &uniforms [[buffer(1)]]
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
    
    // Depth Fog
    float fog = clamp((in.depth - 50.0) / 400.0, 0.0, 1.0);
    
    // PRESSURE COLOR RAMP (Refined)
    // Low Pressure = Original Type Color (Hue preserved)
    // High Pressure = Incandescent Glow (Brightness preserved, Hue shifts to Heat)
    
    float3 baseColor = in.color.rgb; 
    float3 critColor = float3(1.0, 0.0, 0.2); // Crimson
    
    // Boost brightness with pressure first
    float3 finalColor = baseColor * (1.0 + in.pressure * 1.5);
    
    // Smooth transition to critical color only at high pressure
    if (in.pressure > 0.6) {
        float critFactor = smoothstep(0.6, 1.0, in.pressure);
        finalColor = mix(finalColor, critColor * 2.0, critFactor); // Shift to hot red
    }
    
    // SELECTION DIMMING
    bool hasSelection = (uniforms.selectedNodeIndex != -1);
    bool isSelected = (in.isSelected > 0.5);
    
    if (hasSelection && !isSelected) {
        // Dim non-selected nodes significantly
        finalColor *= 0.2; // Darken
        finalColor = mix(finalColor, float3(0.1, 0.1, 0.1), 0.5); // Desaturate
    }
    
    // Modulate brightness with depth
    finalColor *= mix(1.2, 0.6, fog);
    
    // Hot core
    float coreIntensity = 0.8 + (in.pressure * 0.5);
    if (isSelected) {
        coreIntensity = 2.0; // Selected node is VERY bright
    }
    finalColor += float3(1.0) * core * coreIntensity;
    
    // Alpha falloff
    float alpha = in.color.a * glow * mix(1.0, 0.4, fog);
    
    if (hasSelection && !isSelected) {
        alpha *= 0.3; // Make transparent
    }
    
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
