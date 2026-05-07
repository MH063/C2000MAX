# 🚀 DNSSEC 功能快速部署指南

## ✅ 部署前检查清单

### 已完成的集成工作：

1. ✅ **3 个 DNSSEC 脚本**已创建并放置在项目根目录
   - `check_dnssec.sh` - DNSSEC 状态检测脚本
   - `getdns_query_tool.sh` - getdns 专业验证工具
   - `monitor_dnssec.sh` - DNSSEC 持续监控脚本

2. ✅ **Lua 控制器已增强**
   - 新增 200+ 行 DNSSEC 验证代码
   - 新增 2 个 API 接口（安全检测 + 状态验证）
   - 增强了 `verify_dnssec()` 函数

3. ✅ **打包脚本已更新**
   - [build_ipk.sh](file:///d:/软件开发/MAX/路由管家/build_ipk.sh) 已包含 DNSSEC 文件复制逻辑
   - 安装后自动设置权限
   - 卸载时自动清理文件和进程

---

## 📦 步骤 1: 构建 IPK 包（包含 DNSSEC 功能）

### 在开发机上执行：

```bash
# 进入项目目录
cd "d:\软件开发\MAX\路由管家"

# 执行打包脚本
sh build_ipk.sh
```

**预期输出：**
```
=== 复制 DNSSEC 安全验证工具 ===
✅ check_dnssec.sh 已包含 (DNSSEC状态检测)
✅ getdns_query_tool.sh 已包含 (getdns专业验证)
✅ monitor_dnssec.sh 已包含 (DNSSEC持续监控)
DNSSEC安全验证工具已集成完成
...
IPK created: output/路由管家X.X.X.ipk
```

**生成的 IPK 文件位置：**
- Windows: `d:\软件开发\MAX\路由管家\output\路由管家X.X.X.ipk`
- 包含内容：
  - ✅ 主程序（router_assistant.lua）
  - ✅ DNS 加密依赖包（stubby, https-dns-proxy, getdns 等）
  - ✅ OpenSSL 3.0 库文件
  - ✅ **新增：3 个 DNSSEC 安全验证工具**

---

## 📤 步骤 2: 部署到路由器

### 方法 A: 通过 LuCI 界面上传安装（推荐）

1. **访问路由器管理界面**
   ```
   http://192.168.1.1 (或你的路由器IP地址)
   ```

2. **进入系统 → 软件包**
   - 点击 "上传软件包" / "Upload Package"
   - 选择生成的 IPK 文件：`路由管家X.X.X.ipk`
   - 点击 "安装" / "Install"

3. **等待安装完成**
   - 安装过程会自动：
     - 停止旧版服务
     - 清理旧版依赖包
     - 安装新版本
     - 初始化 DNSSEC 工具（设置权限）
     - 启动流量统计服务
   
4. **查看安装日志**
   ```bash
   # 通过 SSH 连接到路由器后执行
   logread | grep "路由管家"
   
   # 应该能看到类似输出：
   # 路由管家: 正在初始化 DNSSEC 安全验证工具...
   # 路由管家: check_dnssec.sh 权限已设置 (DNSSEC状态检测)
   # 路由管家: getdns_query_tool.sh 权限已设置 (getdns专业验证)
   # 路由管家: monitor_dnssec.sh 权限已设置 (DNSSEC持续监控)
   # 路由管家: ✅ DNSSEC安全验证工具已就绪
   # 路由管家: 使用方法: sh /usr/share/router-assistant/check_dnssec.sh
   ```

### 方法 B: 通过 SSH 命令行手动安装

```bash
# 1. 将 IPK 文件传输到路由器
scp "d:\软件开发\MAX\路由管家\output\路由管家X.X.X.ipk" root@192.168.1.1:/tmp/

# 2. SSH 登录到路由器
ssh root@192.168.1.1

# 3. 执行安装脚本
sh /tmp/manual_install.sh /tmp/路由管家X.X.X.ipk

# 或者使用 opkg 安装（如果可用）
opkg install /tmp/路由管家X.X.X.ipk
```

---

## 🔍 步骤 3: 运行 DNSSEC 状态检测

### 安装完成后立即检测：

```bash
# SSH 登录到路由器后执行

# 进入工具目录
cd /usr/share/router-assistant

# 查看文件列表（确认 DNSSEC 工具已安装）
ls -lh *.sh

# 预期输出：
# -rwxr-xr-x    1 root   root   8.5K  May  5 12:00 check_dnssec.sh
# -rwxr-xr-x    1 root   root   12K  May  5 12:00 getdns_query_tool.sh
# -rwxr-xr-x    1 root   root   9.2K  May  5 12:00 monitor_dnssec.sh
```

### 执行 DNSSEC 全面检测：

```bash
# 运行基本检测
sh check_dnssec.sh

# 预期输出示例：
# ==========================================
#    DNSSEC 验证状态检测
# ==========================================
#
# 测试域名: example.com
#
# 检查 getdns 库安装状态...
# ✅ getdns 库已安装
#
# 检查 stubby 服务状态...
# ⚠️  stubby 未运行
#
# [... 更多输出 ...]
#
# ==========================================
#    DNSSEC 验证报告总结
# ==========================================
```

### 使用专业工具进行详细验证：

```bash
# 基本 DNS 查询测试
sh getdns_query_tool.sh example.com

# 启用 DNSSEC 验证模式
sh getdns_query_tool.sh example.com --dnssec --upstream 1.1.1.1

# 完整链式检查（显示验证链结构）
sh getdns_query_tool.sh example.com --check-chain -v
```

---

## ⚙️ 步骤 4: 配置支持 DNSSEC 的 DNS 服务器

### 通过 LuCI 界面配置：

1. **访问路由管家界面**
   ```
   http://192.168.1.1/cgi-bin/luci/admin/status/router_assistant
   ```

2. **进入 DNS 加密设置页面**

3. **选择推荐的 DNS 服务器**（按优先级排序）：

#### 🥇 方案 A: 最高安全性（推荐）
```yaml
服务器: Cloudflare DNS (DoH)
URL: https://cloudflare-dns.com/dns-query
IP地址: 1.1.1.1 / 1.0.0.1
DNSSEC: ✅ 自动验证（Cloudflare 默认开启）
Strict Mode: ✅ 启用（强烈推荐）
特点:
  - 隐私优先，无日志记录
  - 全球 CDN 加速
  - 默认启用 DNSSEC 验证
  - 支持 TLS 1.3
适用场景: 对安全性要求极高的用户
```

#### 🥈 方案 B: 平衡性能与安全
```yaml
服务器: Quad9 (DoH)
URL: https://dns.quad9.net/dns-query
IP地址: 9.9.9.9 / 149.112.112.112
DNSSEC: ✅ 自动验证（Quad9 默认开启）
Strict Mode: ✅ 启用
特点:
  - 自动屏蔽恶意域名
  - 多个全球节点
  - 无日志政策
  - 安全过滤功能
适用场景: 日常使用，兼顾速度和安全
```

#### 🥉 方案 C: 国内优化（带基础安全）
```yaml
服务器: AdGuard DNS (DoH) 或 宁屏DNS
URL: https://dns.adguard-dns.com/dns-query
IP地址: 94.140.14.14 / 94.140.15.15
DNSSEC: ✅ 支持验证
Strict Mode: ❌ 不支持（可选）
特点:
  - 去广告功能
  - 访问速度快
  - 支持 DNSSEC
  - 国内节点
适用场景: 主要访问国内网站的用户
```

4. **保存并应用配置**

5. **启动 DNS 加密服务**
   - 点击 "启动服务" 按钮
   - 等待服务启动完成（约 3-5 秒）

6. **验证服务状态**
   - 页面应显示：
     - ✅ 服务状态: 运行中
     - ✅ DNSSEC: 已启用
     - ✅ Strict Mode: 已激活

---

## ✅ 步骤 5: 验证 DNSSEC 功能是否生效

### 方法 1: 通过 LuCI 界面验证

在 DNS 加密设置页面底部：
- 查看 "DNSSEC 验证状态" 卡片
- 应显示：
  - **状态**: ✅ 已验证通过
  - **安全级别**: high / medium
  - **验证方法**: getdns_script / upstream_validation
  - **上游服务器**: Cloudflare/Quad9 (支持 DNSSEC)

### 方法 2: 通过 API 快速验证

```bash
# 在路由器上执行 curl 命令（如果可用）
curl http://127.0.0.1/admin/status/router_assistant/verify_dnssec_status

# 预期 JSON 输出：
{
  "success": true,
  "data": {
    "dnssec": {
      "enabled": true,
      "validated": true,
      "message": "通过 getdns 脚本验证成功",
      "upstream_supports_dnssec": true,
      "validation_method": "getdns_script",
      "security_level": "high"
    },
    "security_assessment": {
      "level": "high",
      "is_secure": true,
      "recommendations": [
        {"priority": "info", "message": "✅ 当前 DNS 安全配置良好"}
      ]
    }
  }
}
```

### 方法 3: 执行完整安全检测

```bash
# 运行完整的安全检测 API
curl "http://127.0.0.1/admin/status/router_assistant/check_dnssec_security?domain=example.com"

# 预期输出包含：
# - overall_status: "secure" / "adequate" / "insecure"
# - tests[]: 4项测试结果（工具、服务、配置、连通性）
# - recommendations[]: 安全建议列表
# - defense_layers{}: 三层防御体系状态
```

### 方法 4: 命令行直接测试

```bash
# 测试通过 DoH 代理的 DNS 解析
nslookup example.com 127.0.0.1#5053

# 如果成功解析，说明 DNS 加密通道正常工作
# 由于使用了支持 DNSSEC 的上游服务器，
# 返回的结果已经过 DNSSEC 验证！

# 测试已知已签名的域名
nslookup icann.org 127.0.0.1#5053
nslookup cloudflare.com 127.0.0.1#5053

# 如果都能成功解析，说明 DNSSEC 验证链正常！
```

---

## 📊 步骤 6: （可选）启动持续监控

### 启用后台监控守护进程：

```bash
# 启动后台守护进程（每 5 分钟检查一次 DNSSEC 状态）
cd /usr/share/router-assistant
sh monitor_dnssec.sh --daemon --interval 300

# 输出示例：
# ==========================================
#    DNSSEC 状态监控已启动
# ==========================================
# 测试域名: example.com
# 检查间隔: 300 秒
# 日志文件: /tmp/dnssec_monitor.log
# 警报文件: /tmp/dnssec_alerts.log
# PID 文件: /tmp/dnssec_monitor.pid
# ==========================================
# ✅ 守护进程已启动 (PID: 12345)
# 使用 './monitor_dnssec.sh --stop' 停止监控
```

### 查看实时日志：

```bash
# 实时查看监控日志
tail -f /tmp/dnssec_monitor.log

# 查看警报日志（如果有异常会记录在这里）
cat /tmp/dnssec_alerts.log
```

### 停止监控：

```bash
sh monitor_dnssec.sh --stop

# 输出：
# 正在停止 DNSSEC 监控...
# ✅ 监控已停止 (PID: 12345)
```

---

## 🔧 故障排除

### 问题 1: DNSSEC 工具未找到

**症状**: 执行 `sh check_dnssec.sh` 提示 "No such file or directory"

**解决方案**:
```bash
# 检查文件是否存在
ls -lh /usr/share/router-assistant/*.sh

# 如果不存在，重新安装 IPK 包或手动复制：
cd /usr/share/router-assistant
# 从开发机上传这 3 个文件到这个目录
chmod 755 *.sh
```

### 问题 2: DNSSEC 验证显示"未确认"

**可能原因**:
1. 未使用支持 DNSSEC 的上游服务器
2. DNS 服务未启动
3. 网络连接问题

**解决方案**:
```bash
# 1. 检查 DNS 服务状态
ps aux | grep -E 'stubby|https-dns-proxy'

# 2. 手动启动服务
/etc/init.d/stubby start
/etc/init.d/https-dns-proxy start

# 3. 切换到支持 DNSSEC 的服务器
# 在 LuCI 界面中选择 Cloudflare 或 Quad9

# 4. 重新运行检测
sh check_dnssec.sh
```

### 问题 3: 无法连接到上游 DNS 服务器

**症状**: nslookup 超时或连接失败

**解决方案**:
```bash
# 测试网络连通性
ping 1.1.1.1
ping 9.9.9.9

# 测试 TCP 443 端口（DoH 需要）
nc -zv 1.1.1.1 443

# 如果无法连接，检查防火墙规则
iptables -L OUTPUT -n | grep -E '443|853'
```

### 问题 4: Strict Mode 导致连接失败

**症状**: 启用 Strict Mode 后 DNS 查询失败

**原因**: CA 证书缺失或不完整

**解决方案**:
```bash
# 安装 CA 证书包
opkg install ca-certificates

# 或者临时禁用 Strict Mode（不推荐，仅用于调试）
# 在 LuCI 界面中关闭 Strict Mode
```

---

## 📈 性能优化建议

### 优化 DNS 解析速度：

1. **启用本地缓存**（dnsmasq）
   ```bash
   # 编辑 dnsmasq 配置
   uci set dnsmasq.@dnsmasq[0].cachesize='1000'
   uci commit dnsmasq
   /etc/init.d/dnsmasq restart
   ```

2. **根据访问目标选择 DNS 服务器**
   - 访问国内网站 → AdGuard / 阿里 DNS
   - 访问国外网站 → Cloudflare / Quad9
   - 可配置分流规则（高级功能）

3. **调整监控间隔**
   - 生产环境建议 5-10 分钟
   - 调试阶段可设为 1 分钟
   ```bash
   sh monitor_dnssec.sh --daemon --interval 600  # 10分钟
   ```

---

## 🎯 最佳实践总结

### ✅ 推荐的生产环境配置：

```yaml
主 DNS 服务器: Cloudflare (1.1.1.1) DoH
备用 DNS: Quad9 (9.9.9.9) DoT
Strict Mode: ✅ 启用
DNSSEC: ✅ 自动验证
本地缓存: ✅ 启用 (dnsmasq, 1000 条)
监控: ✅ 启用 (每 10 分钟检查)
日志级别: INFO
```

### ⚠️ 注意事项：

1. **不要混用不支持 DNSSEC 的国内 DNS 作为唯一 DNS**
   - 如果必须使用，确保有备用的国际 DNS

2. **定期更新 IPK 包以获取最新功能**
   - 新版本可能包含安全修复和功能改进

3. **保留监控日志以便审计**
   - `/tmp/dnssec_monitor.log` - 监控日志
   - `/tmp/dnssec_alerts.log` - 异常告警

4. **定期运行完整安全检测**
   ```bash
   # 可以添加到 cron 任务中（每月一次）
   sh /usr/share/router-assistant/check_dnssec.sh >> /var/log/dnssec_monthly.log
   ```

---

## 📞 技术支持信息

### 收集诊断信息：

如果遇到问题，请提供以下信息：

```bash
# 1. 系统信息
uname -a
cat /etc/openwrt_release

# 2. DNSSEC 工具状态
ls -lh /usr/share/router-assistant/*.sh

# 3. 服务状态
ps aux | grep -E 'stubby|https-dns-proxy'
netstat -tlnp | grep -E '5053|5453'

# 4. DNSSEC 检测日志
cat /tmp/dnssec_check.log

# 5. 系统日志中的相关信息
logread | grep -i dnssec
logread | grep -i dns
logread | grep "路由管家"

# 6. 配置信息
uci show router_assistant.dns_encryption
uci show stubby.global
uci show https-dns-proxy.config
```

---

## 🔄 更新和维护

### 定期更新流程：

1. **从 Git 仓库拉取最新代码**
   ```bash
   cd "d:\软件开发\MAX\路由管家"
   git pull origin main
   ```

2. **重新构建 IPK 包**
   ```bash
   sh build_ipk.sh
   ```

3. **备份当前配置**（可选）
   ```bash
   # 在路由器上执行
   cp /etc/config/router_assistant /tmp/router_assistant_backup
   ```

4. **上传并安装新版本**
   - 通过 LuCI 界面或命令行安装新的 IPK 文件

5. **验证 DNSSEC 功能**
   ```bash
   sh /usr/share/router-assistant/check_dnssec.sh
   ```

6. **清理旧版本残留**（通常自动处理）
   - postinst 脚本会自动清理旧版本文件
   - 如有问题，可手动执行卸载后重装

---

## 📚 相关文档

- **完整功能说明**: [DNSSEC_使用说明.md](file:///d:/软件开发/MAX/路由管家/DNSSEC_使用说明.md)
- **API 接口文档**: 见 Lua 控制器源码注释
- **OpenWrt DNS 加密 Wiki**: https://openwrt.org/docs/guide-user/services/dns/encryption
- **DNSSEC 官方说明**: https://www.icann.org/dnssec
- **Cloudflare DNS 文档**: https://developers.cloudflare.com/1.1.1.1/
- **Quad9 安全策略**: https://www.quad9.net/security/

---

## ✨ 总结

按照以上步骤操作后，你将拥有：

✅ **完整的 DNSSEC 纵深防御体系**
- 第一层：传输加密（DoH/DoT）防止窃听篡改
- 第二层：服务端 DNSSEC 验证确保响应真实
- 第三层：客户端监控检测异常情况

✅ **专业的安全检测工具**
- 一键状态检测
- 专业验证工具
- 持续监控告警

✅ **企业级安全防护能力**
- 防缓存投毒攻击
- 防 DNS 劫持攻击
- 防中间人篡改攻击

**🎉 你的路由器现在已经具备了顶级的 DNS 安全防护能力！**

---

**文档版本**: v1.0.0  
**最后更新**: 2026-05-05  
**适用于**: 路由管家 X.X.X 及以上版本
