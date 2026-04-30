/**
 * @deprecated 此控制器已废弃，请使用 router_assistant.lua
 * 保留此文件仅为历史兼容，新版本将移除
 *
 * 原因：
 * 1. 功能与 router_assistant.lua 完全重叠
 * 2. 上游接口过滤依赖硬编码（已修复为动态检测）
 * 3. 不支持流量统计和设备备注功能
 */

return {
    get_version: function() {
        return { code: -1, message: "此 API 已废弃，请使用 /admin/status/router_assistant/get_version", deprecated: true };
    },
    get_devices: function() {
        return { code: -1, message: "此 API 已废弃，请使用 /admin/status/router_assistant/get_devices", deprecated: true };
    },
    get_traffic: function() {
        return { code: -1, message: "此 API 已废弃，请使用 /admin/status/router_assistant/get_traffic", deprecated: true };
    },
    get_wifi_status: function() {
        return { code: -1, message: "此 API 已废弃，请使用 /admin/status/router_assistant/get_wifi_status", deprecated: true };
    },
    kick_device: function() {
        return { code: -1, message: "此 API 已废弃，请使用 /admin/status/router_assistant/kick_device", deprecated: true };
    }
};
