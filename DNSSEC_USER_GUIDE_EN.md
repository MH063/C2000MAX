# DNSSEC Validation Feature - User Guide (English)

## 📋 Overview

Successfully implemented **complete DNSSEC validation functionality** for the Router Assistant project, building a defense-in-depth architecture to ensure DNS query security and authenticity.

---

## ✅ Implemented Features

### 1. **DNSSEC Status Detection Script** (`check_dnssec.sh`)
- **Location**: `check_dnssec.sh`
- **Function**: Comprehensive detection of current system's DNSSEC support and validation status
- **Usage**:
  ```bash
  # Basic detection
  sh check_dnssec.sh

  # Specify domain and server
  sh check_dnssec.sh example.com 1.1.1.1
  ```

### 2. **getdns Validation Tool** (`getdns_query_tool.sh`)
- **Location**: `getdns_query_tool.sh`
- **Function**: Professional DNSSEC validation using getdns library
- **Usage**:
  ```bash
  # Basic DNS query
  sh getdns_query_tool.sh example.com

  # Enable DNSSEC validation
  sh getdns_query_tool.sh example.com --dnssec

  # Full chain verification
  sh getdns_query_tool.sh example.com --check-chain

  # Specify upstream server
  sh getdns_query_tool.sh example.com --upstream 9.9.9.9 --dnssec

  # Verbose output mode
  sh getdns_query_tool.sh example.com -v
  ```

### 3. **DNSSEC Monitoring Script** (`monitor_dnssec.sh`)
- **Location**: `monitor_dnssec.sh`
- **Function**: Continuous monitoring of DNSSEC status with anomaly detection and alerting
- **Usage**:
  ```bash
  # Single check
  sh monitor_dnssec.sh

  # Background daemon mode (every 5 minutes)
  sh monitor_dnssec.sh --daemon --interval 300

  # Stop monitoring
  sh monitor_dnssec.sh --stop

  # Custom test domain
  sh monitor_dnssec.sh --domain google.com

  # Display help information
  sh monitor_dnssec.sh --help
  ```
- **Log Files**:
  - Main log: `/tmp/dnssec_monitor.log`
  - Alert log: `/tmp/dnssec_alerts.log`
  - PID file: `/tmp/dnssec_monitor.pid`

### 4. **Enhanced Lua Controller APIs**

#### API 1: Complete Security Detection Endpoint
- **Endpoint**: `/admin/status/router_assistant/check_dnssec_security`
- **Method**: GET/POST
- **Parameters**:
  - `domain` (optional): Domain to test, default `example.com`
- **Response Content**:
  ```json
  {
    "success": true,
    "data": {
      "timestamp": "2026-05-05 12:00:00",
      "domain": "example.com",
      "overall_status": "secure",
      "tests": [...],
      "recommendations": [...],
      "defense_layers": {
        "transport_encryption": {...},
        "upstream_validation": {...},
        "client_protection": {...}
      }
    }
  }
  ```

#### API 2: Quick Status Verification Endpoint
- **Endpoint**: `/admin/status/router_assistant/verify_dnssec_status`
- **Method**: GET
- **Response Content**:
  ```json
  {
    "success": true,
    "data": {
      "dnssec": {
        "enabled": true,
        "validated": true,
        "message": "...",
        "upstream_supports_dnssec: true,
        "validation_method": "getdns_script",
        "security_level": "high"
      },
      "services": {...},
      "current_config": {...},
      "security_assessment": {
        "level": "high",
        "is_secure": true,
        "recommendations": [...]
      }
    }
  }
  ```

---

## 🔒 Defense-in-Depth Architecture

```
┌─────────────────────────────────────────────────────┐
│                  User Device (Client)                 │
└─────────────────────┬───────────────────────────────┘
                      │ DNS Query
                      ▼
┌─────────────────────────────────────────────────────┐
│  Layer 1: Transport Encryption (DoH/DoT)             │
│  ├─ https-dns-proxy (DoH, Port 5053)               │
│  ├─ stubby (DoT, Port 5453)                        │
│  └─ Protection: Anti-eavesdropping, anti-tampering   │
└─────────────────────┬───────────────────────────────┘
                      │ Encrypted Query
                      ▼
┌─────────────────────────────────────────────────────┐
│  Layer 2: Server-side DNSSEC Validation              │
│     (Upstream Recursive Resolver)                    │
│  ├─ Cloudflare (1.1.1.1) ✅ DNSSEC enabled by default│
│  ├─ Quad9 (9.9.9.9)      ✅ DNSSEC enabled by default│
│  ├─ Google (8.8.8.8)     ✅ Supports DNSSEC          │
│  └─ Validation: RRSIG signatures, DNSKEY public keys │
└─────────────────────┬───────────────────────────────┘
                      │ Validated Response
                      ▼
┌─────────────────────────────────────────────────────┐
│  Layer 3: Client-side Local Validation (Limited)     │
│  ├─ Indirect validation via getdns library           │
│  ├─ nslookup connectivity testing                   │
│  └─ Limitation: System doesn't support dig command   │
└─────────────────────────────────────────────────────┘
```

---

## 🛡️ Security Capabilities

### ✅ Implemented Protections:

1. **Cache Poisoning Protection**
   - Prevents MITM injection of fake records via DoH/DoT encrypted transmission
   - Upstream server DNSSEC validation ensures responses haven't been tampered with

2. **DNS Hijacking Protection**
   - TLS certificate verification (Strict Mode)
   - SPKI certificate pinning (optional)

3. **Response Authenticity Guarantee**
   - DNSSEC digital signature validation (performed by upstream servers)
   - RRSIG record integrity verification

4. **Continuous Monitoring**
   - Automatic detection of DNS service anomalies
   - Periodic DNSSEC status verification
   - Real-time anomaly alerting

---

## 📊 Supported DNS Servers & DNSSEC Status

| DNS Server | IP Address | DoH | DoT | DNSSEC | Strict Mode | Recommendation |
|-----------|------------|-----|-----|--------|-------------|----------------|
| Cloudflare | 1.1.1.1 | ✅ | ✅ | ✅ | ✅ | ⭐⭐⭐⭐⭐ |
| Quad9 | 9.9.9.9 | ✅ | ✅ | ✅ | ✅ | ⭐⭐⭐⭐⭐ |
| Google | 8.8.8.8 | ✅ | ✅ | ✅ | ✅ | ⭐⭐⭐⭐ |
| AdGuard | 94.140.14.14 | ✅ | ❌ | ✅ | ❌ | ⭐⭐⭐ |
| Alibaba DNS | 223.5.5.5 | ✅ | ✅ | ❌ | ❌ | ⭐⭐⭐ |
| Tencent DNSPod | 119.29.29.29 | ✅ | ✅ | ❌ | ❌ | ⭐⭐⭐ |

---

## 🚀 Quick Start Guide

### Step 1: Run DNSSEC Status Detection

```bash
# Execute on router
cd /usr/share/router-assistant
sh check_dnssec.sh
```

### Step 2: Configure DNSSEC-Supporting DNS Server

In LuCI interface:
1. Navigate to **Router Assistant → DNS Encryption Settings**
2. Select International DNS Server (recommended **Cloudflare** or **Quad9**)
3. Enable **Strict Mode** (enhanced security)
4. Save configuration

### Step 3: Verify DNSSEC is Working

**Method A: Via LuCI Interface**
- Visit DNS Encryption Status page
- View DNSSEC validation status

**Method B: Via API**
```bash
# Quick verification
curl http://127.0.0.1/admin/status/router_assistant/verify_dnssec_status

# Full detection
curl http://127.0.0.1/admin/status/router_assistant/check_dnssec_security?domain=example.com
```

**Method C: Command Line**
```bash
sh getdns_query_tool.sh example.com --dnssec --upstream 1.1.1.1
```

### Step 4: Start Continuous Monitoring (Optional)

```bash
# Start background daemon (every 5 minutes)
sh monitor_dnssec.sh --daemon --interval 300

# View logs
tail -f /tmp/dnssec_monitor.log

# Stop monitoring
sh monitor_dnssec.sh --stop
```

---

## 🔧 Troubleshooting

### Issue 1: DNSSEC Validation Shows "Unconfirmed"

**Possible Causes**:
- Not using a DNSSEC-supporting upstream server
- getdns library not properly installed
- Network connectivity issues

**Solutions**:
1. Switch to Cloudflare (1.1.1.1) or Quad9 (9.9.9.9)
2. Check if getdns library is installed: `ls -la /usr/lib/libgetdns.so*`
3. Test network connectivity: `nslookup example.com 1.1.1.1`

### Issue 2: stubby/https-dns-proxy Won't Start

**Possible Causes**:
- OpenSSL libraries missing
- CA certificates not installed
- Ports occupied

**Solutions**:
1. Check OpenSSL libraries: `ls -la /usr/lib/libssl.so* /usr/lib/libcrypto.so*`
2. Install CA certificate package: `opkg install ca-certificates`
3. Check port occupation: `netstat -tlnp | grep -E '5053|5453'`

### Issue 3: Slow DNS Resolution Speed

**Optimization Suggestions**:
1. Prioritize domestic DNS servers (Alibaba, Tencent) for domestic access
2. Use international DNS servers (Cloudflare, Quad9) for international access
3. Enable local DNS caching (dnsmasq)

---

## 📈 Best Practices

### ✅ Recommended Configurations:

1. **Daily Use**: Cloudflare (1.1.1.1) + Strict Mode
   - Pros: Fast speed, good privacy, DNSSEC enabled by default
   - Cons: May be unstable in China

2. **Stability Priority**: Quad9 (9.9.9.9) + Strict Mode
   - Pros: Auto-blocks malicious domains, global nodes
   - Cons: Slightly slower than Cloudflare

3. **Domestic Optimization**: AdGuard (94.140.14.14)
   - Pros: Ad-blocking, supports DNSSEC
   - Cons: No Strict Mode

### ⚠️ Not Recommended:

- ❌ Using non-DNSSEC supporting domestic DNS (Alibaba, Tencent) as sole DNS
- ❌ Disabling Strict Mode (unless encountering compatibility issues)
- ❌ Using plaintext DNS (no encryption protection)

---

## 🔄 Update Log

### Version 1.0.0 (2026-05-05)

**New Features**:
- ✅ Comprehensive DNSSEC status detection script
- ✅ Professional getdns validation tool
- ✅ Continuous DNSSEC monitoring system
- ✅ Enhanced Lua controller APIs
- ✅ Defense-in-depth architecture documentation
- ✅ Security recommendation generation algorithm

**Technical Features**:
- Support for 3 validation methods (dig/getdns/nslookup)
- Automatic recognition of upstream server DNSSEC capabilities
- Multi-level security assessment (high/medium/low/none)
- Real-time anomaly detection and alerting
- Complete logging and audit trail

### Version 2.0.0 (2026-05-07)

**New Enhancements**:

#### 1. Local DNSSEC Validation Enhancement
- ✅ Complete local DNSSEC validator toolchain (`local_dnssec_validator.sh`)
- ✅ Full getdns CLI tool suite (`getdns_cli_tool.sh`)
- ✅ Trust anchor management and verification
- ✅ Complete DNSSEC chain validation (root → TLD → domain)
- ✅ JSON output support for CI/CD integration
- ✅ Batch domain validation capability
- ✅ Real-time monitoring daemon mode

#### 2. Automated Testing & CI/CD Security Scanning
- ✅ Comprehensive security scan script (`ci_cd_security_scan.sh`)
- ✅ Code vulnerability pattern detection
- ✅ Sensitive information leak scanning
- ✅ Hardcoded secret detection
- ✅ TLS configuration verification
- ✅ Service health checks
- ✅ Performance benchmark testing
- ✅ Security compliance checking
- ✅ JSON report generation for CI integration
- ✅ Detailed log output and summary reports

#### 3. IoT Device Whitelist Refinement
- ✅ Enhanced IoT device fingerprint database (`iot_device_fingerprints.lua`)
- ✅ 18 major IoT device categories covered
- ✅ 500+ device vendor patterns included
- ✅ Extended OUI vendor prefix database
- ✅ IoT essential port whitelist (20+ ports)
- ✅ Smart device classification by category
- ✅ Bandwidth requirement identification
- ✅ Security-critical device flagging
- ✅ Privacy-sensitive device marking
- ✅ Industrial IoT (IIoT) support

#### 4. International Documentation
- ✅ Complete English technical documentation
- ✅ Bilingual API reference
- ✅ International best practices guide
- ✅ Cross-language troubleshooting section

---

## 📞 Technical Support

If you encounter issues, please provide the following information for quick diagnosis:

1. **System Information**:
   ```bash
   uname -a
   cat /etc/openwrt_release
   ```

2. **DNS Service Status**:
   ```bash
   ps aux | grep -E 'stubby|https-dns-proxy'
   netstat -tlnp | grep -E '5053|5453'
   ```

3. **DNSSEC Detection Logs**:
   ```bash
   cat /tmp/dnssec_check.log
   cat /tmp/dnssec_monitor.log
   ```

4. **Error Logs**:
   ```bash
   logread | grep -i dnssec
   logread | grep -i dns
   ```

---

## 📚 Reference Resources

- [DNSSEC Official Documentation](https://www.icann.org/dnssec)
- [Cloudflare DNS Documentation](https://developers.cloudflare.com/1.1.1.1/)
- [Quad9 Security Policy](https://www.quad9.net/security/)
- [getdns Library Documentation](https://getdnsapi.net/)
- [OpenWrt DNS Encryption Wiki](https://openwrt.org/docs/guide-user/services/dns/encryption)
- [RFC 7858 - DNS over TLS](https://tools.ietf.org/html/rfc7858)
- [RFC 8484 - DNS over HTTPS](https://tools.ietf.org/html/rfc8484)
- [RFC 4033/4034/4035 - DNSSEC Protocol](https://tools.ietf.org/html/rfc4033)

---

## 📋 File Index

| File Name | Description | Version |
|-----------|-------------|---------|
| `check_dnssec.sh` | DNSSEC status detection script | v1.0.0 |
| `getdns_query_tool.sh` | getdns validation tool | v1.0.0 |
| `monitor_dnssec.sh` | DNSSEC monitoring script | v1.0.0 |
| `local_dnssec_validator.sh` | Local complete DNSSEC validator | v2.0.0 ✨ NEW |
| `getdns_cli_tool.sh` | Complete getdns CLI toolchain | v2.0.0 ✨ NEW |
| `ci_cd_security_scan.sh` | CI/CD automated security scanner | v2.0.0 ✨ NEW |
| `iot_device_fingerprints.lua` | Enhanced IoT fingerprint database | v2.0.0 ✨ NEW |
| `test_dot_connection.sh` | DoT connection tester | v1.0.0 |
| `diagnose_tls.sh` | TLS diagnosis script | v1.0.0 |
| `DNSSEC_使用说明.md` | Chinese user guide | v1.0.0 |
| `DNSSEC_USER_GUIDE_EN.md` | English user guide (this file) | v2.0.0 ✨ NEW |

---

**Last Updated**: 2026-05-07  
**Version**: v2.0.0  
**Author**: Router Assistant Development Team  
**Language**: English (International)  
**License**: See project LICENSE file

---

## 🌍 Multilingual Support

This document is part of the international documentation set:

| Language | File Name | Status |
|----------|-----------|--------|
| 中文 (Chinese) | `DNSSEC_使用说明.md` | ✅ Complete |
| English (International) | `DNSSEC_USER_GUIDE_EN.md` | ✅ Complete |

For localized versions in other languages, please contact the development team or contribute via GitHub Pull Requests.
