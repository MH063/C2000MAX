# 路由管家插件重构设计文档

## 概述

本文档描述路由管家插件的重构设计方案，旨在解决以下问题：
1. 单文件过大（8600+行）
2. MAC地址格式不统一
3. CSRF保护不完整
4. Shell调用过多

## 设计目标

### 主要目标
- 按功能模块拆分代码，提高可维护性
- 统一MAC地址格式为带冒号大写格式
- 所有API都需要CSRF验证
- 减少Shell调用，使用ubus API替代

### 关键约束
- **保护TF卡寿命**：减少文件写入操作，控制写入频率
- **保证插件可运行**：渐进式重构，每步都可验证

## 文件拆分结构

```
luasrc/
├── controller/
│   ├── router_assistant.lua    # 主入口（路由注册、CSRF验证）~200行
│   ├── devices.lua             # 设备管理API ~400行
│   ├── traffic.lua             # 流量统计API ~500行
│   ├── wifi.lua                # WiFi管理API ~300行
│   ├── security.lua            # 安全检测API ~600行
│   └── network.lua             # 网络诊断API ~400行
├── model/
│   ├── oui.lua                 # OUI数据库和设备识别 ~300行
│   ├── storage.lua             # 数据存储管理 ~200行
│   ├── cbi.lua                 # 保留现有
│   └── uci.lua                 # 保留现有
└── utils/
    ├── validate.lua            # 输入验证（MAC/IP/CSRF）~150行
    ├── format.lua              # 格式化工具（字节/时间/MAC）~100行
    └── cache.lua               # 缓存管理 ~150行
```

## MAC格式统一方案

### 统一格式
所有存储、API返回、内部处理都使用**带冒号大写格式**（AA:BB:CC:DD:EE:FF）

### 转换函数
```lua
-- utils/validate.lua
function M.format_mac(mac)
    if not mac then return nil end
    local clean = mac:upper():gsub("[^A-F0-9]", "")
    if #clean ~= 12 then return nil end
    return string.format("%s:%s:%s:%s:%s:%s",
        clean:sub(1,2), clean:sub(3,4), clean:sub(5,6),
        clean:sub(7,8), clean:sub(9,10), clean:sub(11,12))
end
```

## CSRF保护方案

### 策略
所有API（GET/POST）都需要CSRF验证

### 实现
```lua
-- controller/router_assistant.lua
local function require_csrf()
    local token = luci.http.formvalue("token")
    local session = luci.dispatcher.context.token
    if not token or token ~= session then
        luci.http.prepare_content("application/json")
        luci.http.write_json({code = -403, message = "CSRF验证失败"})
        return false
    end
    return true
end
```

## Shell调用优化方案

### 缓存策略

#### 内存缓存（零IO开销）
- TTL: 30秒
- 适用: 所有临时数据

#### 文件缓存（受控写入）
- 最小写入间隔: 5分钟
- 仅关键数据持久化

### 数据写入频率控制

| 数据类型 | 存储位置 | 写入频率 | 说明 |
|----------|----------|----------|------|
| ARP表 | 内存 | 0次/秒 | 临时数据，不持久化 |
| WiFi客户端 | 内存 | 0次/秒 | 临时数据，不持久化 |
| DHCP租约 | 内存 | 0次/秒 | 临时数据，不持久化 |
| 流量统计 | 内存 | 1次/5分钟 | 批量写入，减少IO |
| 设备备注 | 内存+文件 | 变更时写入 | 用户数据，必须持久化 |
| 黑名单 | 内存+文件 | 变更时写入 | 用户数据，必须持久化 |
| 月度快照 | 内存+文件 | 1次/天 | 历史数据，低频写入 |

### ubus API替代

| 原Shell命令 | 替代ubus API |
|-------------|--------------|
| ip route | ubus call network.interface dump |
| iw/iwinfo | ubus call hostapd.* get_clients |
| iptables -L | ubus call iptables list |

## 渐进式重构策略

### 阶段0：创建基础模块
- 创建 utils/validate.lua, utils/format.lua, utils/cache.lua
- 不修改现有代码
- 验证：新模块可被require

### 阶段1：创建Model模块
- 创建 model/oui.lua, model/storage.lua
- 使用新的缓存机制
- 验证：新模块API返回正确数据

### 阶段2：创建Controller模块
- 创建 controller/devices.lua, controller/traffic.lua 等
- 与旧代码并行运行
- 验证：新旧API返回相同数据

### 阶段3：切换入口
- 修改主入口使用新模块
- 验证：所有功能正常工作

### 阶段4：清理旧代码
- 删除旧代码中的冗余部分
- 验证：最终功能测试

## 验证检查点

每个阶段完成后验证：
1. **功能验证**：所有现有功能正常工作
2. **性能验证**：响应时间无明显增加
3. **IO验证**：TF卡写入频率符合预期
4. **兼容验证**：前端页面正常显示

## 风险评估

### 低风险
- 创建新模块（不影响现有代码）
- 添加工具函数

### 中风险
- 修改主入口文件
- 切换数据存储方式

### 高风险
- 删除旧代码
- 修改API响应格式

## 回滚方案

每个阶段保留回滚能力：
- 阶段0-1：直接删除新文件
- 阶段2：禁用新API路由
- 阶段3：恢复旧入口文件
- 阶段4：从git历史恢复

## 时间估算

| 阶段 | 预计工作量 |
|------|-----------|
| 阶段0 | 1小时 |
| 阶段1 | 2小时 |
| 阶段2 | 4小时 |
| 阶段3 | 2小时 |
| 阶段4 | 1小时 |
| **总计** | **10小时** |
