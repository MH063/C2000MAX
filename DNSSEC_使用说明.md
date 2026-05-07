# DNSSEC 验证功能 - 使用说明

## 📋 功能概述

已成功为路由管家项目实现完整的 **DNSSEC 验证功能**，构建纵深防御体系，确保 DNS 查询的安全性和真实性。

---

## ✅ 已实现的功能模块

### 1. **DNSSEC 状态检测脚本** (`check_dnssec.sh`)
- **位置**: `check_dnssec.sh`
- **功能**: 全面检测当前系统的 DNSSEC 支持和验证状态
- **用法**:
  ```bash
  # 基本检测
  sh check_dnssec.sh

  # 指定域名和服务器
  sh check_dnssec.sh example.com 1.1.1.1
  ```

### 2. **getdns 验证工具** (`getdns_query_tool.sh`)
- **位置**: `getdns_query_tool.sh`
- **功能**: 使用 getdns 库进行专业的 DNSSEC 验证
- **用法**:
  ```bash
  # 基本 DNS 查询
  sh getdns_query_tool.sh example.com

  # 启用 DNSSEC 验证
  sh getdns_query_tool.sh example.com --dnssec

  # 完整链式检查
  sh getdns_query_tool.sh example.com --check-chain

  # 指定上游服务器
  sh getdns_query_tool.sh example.com --upstream 9.9.9.9 --dnssec

  # 详细输出模式
  sh getdns_query_tool.sh example.com -v
  ```

### 3. **DNSSEC 监控脚本** (`monitor_dnssec.sh`)
- **位置**: `monitor_dnssec.sh`
- **功能**: 持续监控 DNSSEC 状态，检测异常并报警
- **用法**:
  ```bash
  # 单次检查
  sh monitor_dnssec.sh

  # 后台守护进程模式（每5分钟检查一次）
  sh monitor_dnssec.sh --daemon --interval 300

  # 停止监控
  sh monitor_dnssec.sh --stop

  # 自定义测试域名
  sh monitor_dnssec.sh --domain google.com

  # 显示帮助信息
  sh monitor_dnssec.sh --help
  ```
- **日志文件**:
  - 主日志: `/tmp/dnssec_monitor.log`
  - 警报日志: `/tmp/dnssec_alerts.log`
  - PID 文件: `/tmp/dnssec_monitor.pid`

### 4. **Lua 控制器增强功能**
新增了以下 API 接口：

#### API 1: 完整安全检测接口
- **端点**: `/admin/status/router_assistant/check_dnssec_security`
- **方法**: GET/POST
- **参数**:
  - `domain` (可选): 要检测的域名，默认 `example.com`
- **返回内容**:
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

#### API 2: 快速状态验证接口
- **端点**: `/admin/status/router_assistant/verify_dnssec_status`
- **方法**: GET
- **返回内容**:
  ```json
  {
    "success": true,
    "data": {
      "dnssec": {
        "enabled": true,
        "validated": true,
        "message": "...",
        "upstream_supports_dnssec": true,
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

## 🔒 纵深防御体系架构

```
┌─────────────────────────────────────────────────────┐
│                  用户设备 (客户端)                     │
└─────────────────────┬───────────────────────────────┘
                      │ DNS 查询
                      ▼
┌─────────────────────────────────────────────────────┐
│  第一层：传输加密 (DoH/DoT)                          │
│  ├─ https-dns-proxy (DoH, 端口 5053)               │
│  ├─ stubby (DoT, 端口 5453)                        │
│  └─ 保护：防窃听、防篡改、防中间人攻击                │
└─────────────────────┬───────────────────────────────┘
                      │ 加密查询
                      ▼
┌─────────────────────────────────────────────────────┐
│  第二层：服务端 DNSSEC 验证（上游递归解析器）          │
│  ├─ Cloudflare (1.1.1.1) ✅ 默认开启 DNSSEC          │
│  ├─ Quad9 (9.9.9.9)      ✅ 默认开启 DNSSEC          │
│  ├─ Google (8.8.8.8)     ✅ 支持 DNSSEC              │
│  └─ 验证：RRSIG 签名、DNSKEY 公钥、DS 链              │
└─────────────────────┬───────────────────────────────┘
                      │ 已验证响应
                      ▼
┌─────────────────────────────────────────────────────┐
│  第三层：客户端本地验证（有限）                        │
│  ├─ getdns 库间接验证                                │
│  ├─ nslookup 连通性测试                              │
│  └─ 受限原因：系统不支持 dig 命令                     │
└─────────────────────────────────────────────────────┘
```

---

## 🛡️ 安全防护能力

### ✅ 已实现的防护：

1. **缓存投毒防护**
   - 通过 DoH/DoT 加密传输防止中间人注入虚假记录
   - 上游服务器的 DNSSEC 验证确保响应未被篡改

2. **DNS 劫持防护**
   - TLS 证书验证（Strict Mode）
   - SPKI 证书固定（可选）

3. **响应真实性保证**
   - DNSSEC 数字签名验证（由上游服务器执行）
   - RRSIG 记录完整性校验

4. **持续监控**
   - 自动检测 DNS 服务异常
   - 定期验证 DNSSEC 状态
   - 异常情况实时告警

---

## 📊 支持的 DNS 服务器及 DNSSEC 状态

| DNS 服务器 | IP 地址 | DoH | DoT | DNSSEC | Strict Mode | 推荐度 |
|-----------|---------|-----|-----|--------|-------------|-------|
| Cloudflare | 1.1.1.1 | ✅ | ✅ | ✅ | ✅ | ⭐⭐⭐⭐⭐ |
| Quad9 | 9.9.9.9 | ✅ | ✅ | ✅ | ✅ | ⭐⭐⭐⭐⭐ |
| Google | 8.8.8.8 | ✅ | ✅ | ✅ | ✅ | ⭐⭐⭐⭐ |
| AdGuard | 94.140.14.14 | ✅ | ❌ | ✅ | ❌ | ⭐⭐⭐ |
| 阿里 DNS | 223.5.5.5 | ✅ | ✅ | ❌ | ❌ | ⭐⭐⭐ |
| 腾讯 DNSPod | 119.29.29.29 | ✅ | ✅ | ❌ | ❌ | ⭐⭐⭐ |

---

## 🚀 快速开始指南

### 步骤 1: 运行 DNSSEC 状态检测

```bash
# 在路由器上执行
cd /usr/share/router-assistant
sh check_dnssec.sh
```

### 步骤 2: 配置支持 DNSSEC 的 DNS 服务器

在 LuCI 界面中：
1. 进入 **路由管家 → DNS 加密设置**
2. 选择国际 DNS 服务器（推荐 **Cloudflare** 或 **Quad9**）
3. 启用 **Strict Mode**（增强安全性）
4. 保存配置

### 步骤 3: 验证 DNSSEC 是否生效

**方法 A: 通过 LuCI 界面**
- 访问 DNS 加密状态页面
- 查看 DNSSEC 验证状态

**方法 B: 通过 API**
```bash
# 快速验证
curl http://127.0.0.1/admin/status/router_assistant/verify_dnssec_status

# 完整检测
curl http://127.0.0.1/admin/status/router_assistant/check_dnssec_security?domain=example.com
```

**方法 C: 命令行**
```bash
sh getdns_query_tool.sh example.com --dnssec --upstream 1.1.1.1
```

### 步骤 4: 启动持续监控（可选）

```bash
# 启动后台守护进程（每5分钟检查一次）
sh monitor_dnssec.sh --daemon --interval 300

# 查看日志
tail -f /tmp/dnssec_monitor.log

# 停止监控
sh monitor_dnssec.sh --stop
```

---

## 🔧 故障排除

### 问题 1: DNSSEC 验证显示"未确认"

**可能原因**:
- 未使用支持 DNSSEC 的上游服务器
- getdns 库未正确安装
- 网络连接问题

**解决方案**:
1. 切换到 Cloudflare (1.1.1.1) 或 Quad9 (9.9.9.9)
2. 检查 getdns 库是否安装：`ls -la /usr/lib/libgetdns.so*`
3. 测试网络连通性：`nslookup example.com 1.1.1.1`

### 问题 2: stubby/https-dns-proxy 无法启动

**可能原因**:
- OpenSSL 库缺失
- CA 证书未安装
- 端口被占用

**解决方案**:
1. 检查 OpenSSL 库：`ls -la /usr/lib/libssl.so* /usr/lib/libcrypto.so*`
2. 安装 CA 证书包：`opkg install ca-certificates`
3. 检查端口占用：`netstat -tlnp | grep -E '5053|5453'`

### 问题 3: DNS 解析速度慢

**优化建议**:
1. 优先使用国内 DNS 服务器（阿里、腾讯）用于国内访问
2. 使用国际 DNS 服务器（Cloudflare、Quad9）用于国外访问
3. 启用本地 DNS 缓存（dnsmasq）

---

## 📈 最佳实践建议

### ✅ 推荐配置：

1. **日常使用**: Cloudflare (1.1.1.1) + Strict Mode
   - 优点：速度快、隐私好、默认 DNSSEC
   - 缺点：在国内可能不稳定

2. **稳定优先**: Quad9 (9.9.9.9) + Strict Mode
   - 优点：自动屏蔽恶意域名、全球节点
   - 缺点：速度稍慢于 Cloudflare

3. **国内优化**: AdGuard (94.140.14.14)
   - 优点：去广告、支持 DNSSEC
   - 缺点：无 Strict Mode

### ⚠️ 不推荐：

- ❌ 使用不支持 DNSSEC 的国内 DNS（阿里、腾讯）作为唯一 DNS
- ❌ 禁用 Strict Mode（除非遇到兼容性问题）
- ❌ 使用明文 DNS（无加密保护）

---

## 🔄 更新日志

### 版本 1.0.0 (2026-05-05)

**新增功能**:
- ✅ DNSSEC 状态全面检测脚本
- ✅ getdns 专业验证工具
- ✅ DNSSEC 持续监控系统
- ✅ Lua 控制器 API 增强
- ✅ 纵深防御体系文档
- ✅ 安全建议生成算法

**技术特性**:
- 支持 3 种验证方法（dig/getdns/nslookup）
- 自动识别上游服务器 DNSSEC 能力
- 多层级安全评估（high/medium/low/none）
- 实时异常检测和告警
- 完整的日志记录和审计跟踪

---

## 📞 技术支持

如遇问题，请提供以下信息以便快速定位：

1. **系统信息**:
   ```bash
   uname -a
   cat /etc/openwrt_release
   ```

2. **DNS 服务状态**:
   ```bash
   ps aux | grep -E 'stubby|https-dns-proxy'
   netstat -tlnp | grep -E '5053|5453'
   ```

3. **DNSSEC 检测日志**:
   ```bash
   cat /tmp/dnssec_check.log
   cat /tmp/dnssec_monitor.log
   ```

4. **错误日志**:
   ```bash
   logread | grep -i dnssec
   logread | grep -i dns
   ```

---

## 📚 参考资源

- [DNSSEC 官方说明](https://www.icann.org/dnssec)
- [Cloudflare DNS 文档](https://developers.cloudflare.com/1.1.1.1/)
- [Quad9 安全策略](https://www.quad9.net/security/)
- [getdns 库文档](https://getdnsapi.net/)
- [OpenWrt DNS 加密 Wiki](https://openwrt.org/docs/guide-user/services/dns/encryption)

---

**最后更新时间**: 2026-05-05  
**版本**: v1.0.0  
**作者**: 路由管家开发团队
