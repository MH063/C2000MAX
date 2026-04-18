'resource://luci.js';

-- DEPRECATED: 此控制器为轻量级备用控制器，功能与 router_assistant.lua 重叠
-- 主要差异：
--   - 此控制器直接获取设备列表，不包含流量统计和设备备注功能
--   - 上游接口过滤依赖硬编码（问题5&13），建议使用主控制器
-- 如需完整功能，请使用 router_assistant.lua

-- 安全 MAC 验证：只允许合法十六进制字符和冒号
function validate_mac(mac)
    if (!mac || type(mac) !== 'string')
        return false;
    return mac.match('^[0-9a-fA-F:]{17}$') !== null;
}

-- 标准化 MAC：转换为大写、替换短横为冒号
function normalize_mac(mac)
    if (!mac)
        return '';
    return mac.toUpperCase().replace(/-/g, ':');
}

-- 执行命令并返回输出
function exec_cmd(cmd)
{
    let output = '';
    let f = popen(cmd + ' 2>/dev/null');
    if (f) {
        output = f.read('a');
        f.close();
    }
    return output;
}

-- 获取设备列表（通过 ubus infocd terminal）
function get_devices() {
    let devices = [];

    // 通过 ubus 获取真实设备数据
    let ubus_output = exec_cmd("ubus call infocd terminal 2>/dev/null");
    if (ubus_output && ubus_output !== '') {
        let data = json.parse(ubus_output);
        if (data && data.client) {
            // 从 dhcp.leases 获取 hostname 映射
            let hostname_map = {};
            let leases_content = fs.readfile('/tmp/dhcp.leases') || '';
            let lease_lines = split(leases_content, '\n');
            for (let line of lease_lines) {
                if (!line) continue;
                let fields = split(line, ' ');
                if (fields.length >= 5) {
                    let mac = normalize_mac(fields[1]);
                    hostname_map[mac] = fields[3];
                }
            }

            // 遍历 ubus 返回的设备
            for (let mac in data.client) {
                let client = data.client[mac];
                let mac_normalized = normalize_mac(mac);

                // 过滤上游接口设备
                let ifname = client.ifname || '';
                let is_upstream = false;
                if (ifname === 'eth1' || ifname === 'eth3') {
                    is_upstream = true;
                }

                if (is_upstream)
                    continue;

                // 获取 hostname
                let hostname = hostname_map[mac_normalized] || client.hostname || 'Unknown';
                if (hostname === '*' || hostname === '')
                    hostname = hostname_map[mac_normalized] || 'Unknown';

                // 获取 IP
                let ip = client.ipaddr || '-';
                if (!ip || ip === '-') {
                    ip = client.ap_ipaddr || '-';
                }

                push(devices, {
                    ip: ip,
                    mac: mac_normalized,
                    hostname: hostname,
                    iface: ifname,
                    is_wifi: (client.type === 'wireless'),
                    signal: client.rssi || 0
                });
            }
        }
    }

    // 如果 ubus 失败，至少从 dhcp.leases 获取
    if (devices.length === 0) {
        let leases_content = fs.readfile('/tmp/dhcp.leases') || '';
        let lease_lines = split(leases_content, '\n');
        for (let line of lease_lines) {
            if (!line) continue;
            let fields = split(line, ' ');
            if (fields.length >= 5) {
                push(devices, {
                    ip: fields[2],
                    mac: normalize_mac(fields[1]),
                    hostname: fields[3],
                    leasetime: fields[0]
                });
            }
        }
    }

    return { code: 0, devices: devices };
}

-- 获取流量统计
function get_traffic() {
    let stats = [];

    // 尝试从 router_assistant 存储目录读取流量数据
    let storage_paths = [
        '/tmp/storage/mmcblk0p1/router_assistant/current.json',
        '/mnt/mmcblk0p1/router_assistant/current.json',
        '/tmp/router_assistant/current.json'
    ];

    let data = null;
    for (let path in storage_paths) {
        if (fs.stat(path)) {
            let content = fs.readfile(path) || '{}';
            data = json.parse(content);
            break;
        }
    }

    if (data) {
        for (let mac in data) {
            let info = data[mac];
            let rx = info.rx || 0;
            let tx = info.tx || 0;
            push(stats, {
                mac: normalize_mac(mac),
                rx: rx,
                tx: tx,
                rx_display: format_bytes(rx),
                tx_display: format_bytes(tx),
                total_display: format_bytes(rx + tx)
            });
        }
    }

    return { code: 0, devices: stats };
}

-- 获取 WiFi 状态（通过 ubus）
function get_wifi_status() {
    let wifi_list = [];

    // 通过 ubus 获取 WiFi 状态
    let ubus_output = exec_cmd("ubus call network.wireless status 2>/dev/null");
    if (ubus_output && ubus_output !== '') {
        let data = json.parse(ubus_output);
        if (data) {
            for (let dev in data) {
                let device = data[dev];
                if (device.up === true) {
                    push(wifi_list, {
                        device: dev,
                        up: true,
                        ssid: device.ssid || 'N/A'
                    });
                }
            }
        }
    }

    return { code: 0, wifi: wifi_list };
}

-- 踢出设备（执行 iptables + conntrack + iw 命令）
function kick_device(mac, device) {
    // 验证 MAC 地址
    if (!validate_mac(mac)) {
        return { code: -1, message: 'MAC地址格式无效' };
    }

    let mac_normalized = normalize_mac(mac);
    let mac_lower = mac_normalized.toLowerCase();
    let formatted_mac = mac_normalized;

    // 二次验证：确保MAC只包含合法字符（防止验证函数被绕过）
    if (!formatted_mac.match('^[0-9A-F:]{17}$')) {
        return { code: -1, message: 'MAC地址包含非法字符' };
    }

    // 获取设备 IP（如果提供）
    let device_ip = device && device.ip ? device.ip : '';

    // 验证IP格式（如果提供）
    if (device_ip && !device_ip.match('^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$')) {
        device_ip = '';  // 无效IP则忽略
    }

    // 构建踢出命令脚本（MAC和IP都经过验证）
    let cmds = [
        'iptables -I INPUT -m mac --mac-source ' + formatted_mac + ' -j DROP 2>/dev/null',
        'iptables -I FORWARD -m mac --mac-source ' + formatted_mac + ' -j DROP 2>/dev/null'
    ];

    if (device_ip) {
        cmds.push('conntrack -D -s ' + device_ip + ' 2>/dev/null');
        cmds.push('conntrack -D -d ' + device_ip + ' 2>/dev/null');
    }
    cmds.push('conntrack -D -m ' + mac_lower.replace(/:/g, '') + ' 2>/dev/null');

    // 踢出无线连接（接口名硬编码防止注入）
    let ifaces = ['ra0', 'rai0', 'ra1', 'rai1', 'apcli0', 'apcli1'];
    for (let i = 0; i < length(ifaces); i++) {
        cmds.push('timeout 3 iw dev ' + ifaces[i] + ' station del ' + formatted_mac + ' 2>/dev/null || true');
    }

    // 执行命令
    for (let i = 0; i < length(cmds); i++) {
        exec_cmd(cmds[i]);
    }

    return {
        code: 0,
        message: '设备已断开',
        mac: mac_normalized,
        ip: device_ip,
        success: true
    };
}

function get_version() {
    return {
        code: 0,
        version: '1.0.0',
        author: 'MH',
        name: 'RouterAssistant'
    };
}

function format_bytes(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
    return (bytes / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
}

return {
    get_devices: get_devices,
    get_traffic: get_traffic,
    get_wifi_status: get_wifi_status,
    kick_device: kick_device,
    get_version: get_version
};