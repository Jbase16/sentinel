#include <metal_stdlib>
using namespace metal;

// Vertex Shader Input
struct VertexIn {
    float4 position [[attribute(0)]];
    float3 normal [[attribute(1)]];
    float2 uv [[attribute(2)]];
};

// Vertex Shader Output
struct VertexOut {
    float4 position [[position]];
    float3 worldPosition;
    float3 normal;
    float2 uv;
    float edgeFactor;
};

struct Uniforms {
    float4x4 viewProjectionMatrix;
    float4x4 modelMatrix;
    float3 worldPosition;
    float pressure;       // 0.0 (Stable) to 1.0 (Critical)
    float time;
    float3 viewPosition;  // Camera position for Fresnel
};

// Simplex Noise Helper (Simplified for brevity)
float noise(float3 p) {
    return sin(p.x * 10.0 + sin(p.y * 5.0) * 2.0) * cos(p.z * 5.0 + cos(p.x * 2.0));
}

vertex VertexOut vertex_main(VertexIn in [[stage_in]], constant Uniforms &u [[buffer(0)]]) {
    VertexOut out;
    
    // 1. Calculate Base World Position
    float4 worldPos = u.modelMatrix * in.position;
    
    // 2. "Breathing" / Instability based on Pressure
    // High pressure nodes vibrate violently.
    float vibration = noise(in.position.xyz + u.time) * u.pressure * 0.15;
    
    // Pulse scaling: Nodes expand slightly as pressure builds
    float pulse = 1.0 + (sin(u.time * 4.0) * 0.05 * u.pressure);
    
    worldPos.xyz += in.normal * vibration;
    worldPos.xyz *= pulse;
    
    out.worldPosition = worldPos.xyz;
    out.position = u.viewProjectionMatrix * worldPos;
    out.normal = (u.modelMatrix * float4(in.normal, 0.0)).xyz;
    out.uv = in.uv;
    
    // 3. Calculate Fresnel Edge Factor (in vertex shader for optimization)
    float3 viewDir = normalize(u.viewPosition - worldPos.xyz);
    out.edgeFactor = 1.0 - dot(normalize(out.normal), viewDir);
    out.edgeFactor = pow(out.edgeFactor, 2.0); // Sharpness of the glow
    
    return out;
}

fragment float4 fragment_main(VertexOut in [[stage_in]], constant Uniforms &u [[buffer(0)]]) {
    // Color Interpolation: Cool Blue (Stable) -> Violent Red (Critical)
    float3 stableColor = float3(0.1, 0.3, 0.4); // Cyberpunk Teal
    float3 warnColor = float3(0.8, 0.5, 0.0);   // Amber
    float3 critColor = float3(1.0, 0.0, 0.1);   // Crimson Red
    
    float3 finalColor;
    if (u.pressure < 0.5) {
        finalColor = mix(stableColor, warnColor, u.pressure * 2.0);
    } else {
        finalColor = mix(warnColor, critColor, (u.pressure - 0.5) * 2.0);
    }
    
    // PBR Base
    float4 baseColor = float4(finalColor, 1.0);
    
    // Fresnel Emission (The "Hologram" Halo)
    float3 fresnelColor = float3(0.4, 0.6, 1.0) * in.edgeFactor * (0.5 + u.pressure * 1.0);
    
    // Critical nodes burn from within
    if (u.pressure > 0.8) {
        baseColor.rgb += float3(0.5) * sin(u.time * 20.0); // Glitch effect
        // Optional: Distortion/Heat Haze could be added here if we had background tex
    }
    
    return float4(baseColor.rgb + fresnelColor, 1.0);
}
