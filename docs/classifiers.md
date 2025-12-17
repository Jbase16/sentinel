# SentinelForge Classifier Reference

This document serves as the **Golden Record** for how Cortex classifies raw security tool output into structured `RawFinding` objects. All classification logic is centralized in [`core/toolkit/raw_classifier.py`](../core/toolkit/raw_classifier.py).

## Data Schema: `RawFinding`

Every finding is normalized into the following structure:

| Field | Type | Description |
|-------|------|-------------|
| `type` | `str` | High-level categorization (e.g., "Open Port", "Hidden Directory"). |
| `severity` | `str` | `INFO`, `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`. |
| `tool` | `str` | The source tool (e.g., `nmap`, `httpx`). |
| `target` | `str` | The target associated with the finding. |
| `message` | `str` | Human-readable summary. |
| `proof` | `str` | The raw output line or snippet that justified the finding. |
| `tags` | `List[str]` | Semantic tags for downstream routing (e.g., `exposure`, `surface-http`). |
| `families` | `List[str]` | Broader categories (e.g., `misconfiguration`, `supply-chain`). |
| `metadata` | `Dict` | Structured extraction (ports, versions, status codes). |

---

## Tool Classifiers

### Core Network Scanners

#### `nmap`
- **Output**: Open ports and services.
- **Severity**:
  - **MEDIUM**: Management ports (SSH/22, RDP/3389, SMB/445, etc.).
  - **LOW**: All other open ports.
- **Tags**: `exposure`
- **Metadata**: `port`, `service`

#### `masscan`
- **Output**: Fast port discovery.
- **Severity**: Same as nmap (MEDIUM for mgmt ports, LOW otherwise).
- **Tags**: `exposure`
- **Metadata**: `port`, `protocol`

### Web Enumeration

#### `httpx`
- **Output**: Live web servers, titles, tech stacks.
- **Severity**:
  - **HIGH**: HTTP 5xx errors (Potential DoS/Instability).
  - **MEDIUM**: HTTP 4xx errors.
  - **INFO**: HTTP 2xx/3xx.
- **Tags**: `surface-http`
- **Metadata**: `status`, `title`, `tech`

#### `whatweb`
- **Output**: Technology fingerprinting & CMS detection.
- **Severity**: **INFO** (Fingerprints are informational unless correlated).
- **Tags**: `tech-fingerprint`, `cms`
- **Families**: `supply-chain`
- **Specifics**: Extracts version numbers for `WordPress`, `Joomla`, `Drupal`, etc.

#### `wafw00f`
- **Output**: WAF detection.
- **Severity**: **INFO**
- **Tags**: `waf`, `defense`
- **Families**: `misconfiguration` (paradoxically, as it affects tool tuning).

### Directory & Fuzzing

#### `gobuster` / `dirsearch` / `feroxbuster`
- **Output**: Hidden paths and directories.
- **Severity**:
  - **MEDIUM**: 200/301 codes (Accessible content).
  - **LOW**: Other status codes.
- **Tags**: `dir-enum`, `surface-http`
- **Metadata**: `status`, `path`, `redirect`

### Vulnerability Scanners

#### `nikto` (via `nikto-shim`)
- **Output**: Known web vulnerabilities.
- **Severity**: Mapped from Nikto output (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).
- **Tags**: `web-scanner`, `misconfiguration`

---

## Global Detectors

These classifiers run on **all** tool output, regardless of the source tool.

### 1. Secret & Credential Leaks (`SECRET_PATTERNS`)
Scans for regex patterns indicating leaked keys.
- **Severity**: **HIGH** or **CRITICAL** (Context dependent).
- **Patterns**:
  - AWS Access/Secret Keys
  - Google/Firebase API Keys
  - GitHub/Slack Tokens
  - Private Keys (PEM Headers)
  - Stripe Secrets

### 2. Framework Detection
Extracts version numbers for:
- `Express`, `Flask`, `Django`, `Rails`, `Spring Boot`, `ASP.NET`, `Next.js`.

### 3. Private IP Leakage
Detects RFC 1918 addresses (`10.x`, `192.168.x`, `172.16-31.x`) leaked in public output.
- **Severity**: **LOW** (Information Disclosure).

### 4. Verbose Errors
Detects stack traces or debug output (e.g., "Traceback (most recent call last)").
- **Severity**: **LOW** to **MEDIUM**.

---

## Tagging Taxonomy

| Tag | Purpose |
|-----|---------|
| `exposure` | Network service or open port. |
| `surface-http` | Web endpoint (HTTP/80, 443, 8080). |
| `management-surface` | Dangerous port (SSH, RDP) exposed to internet. |
| `tech-fingerprint` | Version number or software identification. |
| `misconfiguration` | Deviation from best practice (headers, verbose errors). |
| `supply-chain` | Third-party component (CMS, Library). |
