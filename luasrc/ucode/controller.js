'resource://luci.js';

function get_devices() {
    let devices = [];
    let leases = fs.readfile('/tmp/dhcp.leases') || '';

    let lines = split(leases, '\n');
    for (let line of lines) {
        if (!line) continue;
        let fields = split(line, ' ');
        if (fields.length >= 5) {
            push(devices, {
                ip: fields[2],
                mac: fields[1].toUpperCase(),
                hostname: fields[3],
                leasetime: fields[0]
            });
        }
    }

    return { code: 0, devices: devices };
}

function get_traffic() {
    let stats = [];

    // Get traffic stats from /tmp/traffic_stats/device_stats.json
    let stats_file = '/tmp/traffic_stats/device_stats.json';
    if (fs.stat(stats_file)) {
        let data = json.parse(fs.readfile(stats_file) || '{}');
        for (let mac, info of data) {
            push(stats, {
                mac: mac,
                rx: info.rx || 0,
                tx: info.tx || 0,
                rx_display: format_bytes(info.rx || 0),
                tx_display: format_bytes(info.tx || 0),
                total_display: format_bytes((info.rx || 0) + (info.tx || 0))
            });
        }
    }

    return { code: 0, devices: stats };
}

function get_wifi_status() {
    let wifi_list = [];

    return { code: 0, wifi: wifi_list };
}

function kick_device(mac, device) {
    return { code: 0, message: 'Device kicked successfully' };
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