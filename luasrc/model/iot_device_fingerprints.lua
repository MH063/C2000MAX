-- ============================================================
-- 增强的 IoT 设备厂商指纹库
-- 功能：提供全面的智能设备识别能力
-- 包含：智能家居、可穿戴、家电、安防、医疗等类别
-- 版本: 2.0.0
-- 更新时间: 2026-05-07
-- ============================================================

local M = {}

-- 设备类别定义
M.DEVICE_CATEGORIES = {
    "smart_home",      -- 智能家居中心
    "lighting",        -- 智能照明
    "climate",         -- 环境控制（空调、暖气等）
    "security",        -- 安防系统
    "camera",          -- 摄像头/监控
    "speaker",         -- 智能音箱
    "tv",              -- 电视/投影仪
    "appliance",       -- 智能家电（冰箱、洗衣机等）
    "wearable",        -- 可穿戴设备
    "health",          -- 医疗健康
    "robotics",        -- 机器人/吸尘器
    "sensor",          -- 传感器
    "lock",            -- 智能门锁
    "garden",          -- 园艺/灌溉
    "energy",          -- 能源管理
    "networking",      -- 网络设备
    "automotive",      -- 汽车相关
    "industrial",      -- 工业物联网
}

-- ============================================================
-- 完整的 IoT 设备指纹库
-- ============================================================
M.IOT_DEVICE_FINGERPRINTS = {

    -- ========================
    -- 1. 智能家居平台/中心
    -- ========================
    ["smart_home_hub"] = {
        patterns = {
            "homekit", "homepod", "apple_tv",
            "smartthings", "samsung_connect",
            "philips_hue_bridge", "hue_bridge",
            "xiaomi_gateway", "mi_gateway", "aqara_gateway",
            "tuya_smart_life", "smart_life",
            "alexa", "echo_plus", "echo_show",
            "google_home", "google_nest_hub",
            "home_assistant", "openhab",
            "broadlink_rmpro", "rm_mini",
            "ir_remote", "rf_bridge"
        },
        vendor = "Smart Home Hub",
        device_type = "smart_home",
        category = "control",
        priority_ports = {5353, 1900, 8080, 443, 1883, 8883},
        essential_services = {"mDNS", "SSDP", "MQTT"},
        description = "智能家居控制中心"
    },

    -- ========================
    -- 2. 智能照明系统
    -- ========================
    ["smart_lighting"] = {
        patterns = {
            "philips_hue", "hue_light", "lifx",
            "yeelight", "xiaomi_light", "mi_light",
            "tp-link_kasa", "kasa_smart",
            "sengled", "cree_connected",
            "nanoleaf", "lifx_bulb",
            "tuya_light", "smart_bulb",
            "wiz_light", "belkin_wemo",
            "ikea_tradfri", "tradfri",
            "ge_c_by_ge", "cree_lighting",
            "osram_lightify", "lightify",
            "eqiva", "rademacher"
        },
        vendor = "Smart Lighting",
        device_type = "lighting",
        category = "lighting",
        priority_ports = {5353, 80, 443, 9999},
        essential_services = {"mDNS", "HTTP/HTTPS"},
        description = "智能照明设备"
    },

    -- ========================
    -- 3. 环境控制系统（空调/暖气）
    -- ========================
    ["climate_control"] = {
        patterns = {
            "nest_thermostat", "nest_learning",
            "ecobee", "honeywell_lyric",
            "daikin_ac", "mitsubishi_ac",
            "gree_ac", "midea_ac", "tcl_ac",
            "samsung_ac", "lg_ac", "panasonic_ac",
            "air_conditioner", "ac_controller",
            "thermostat", "heating_control",
            "humidifier", "dehumidifier",
            "air_purifier", "purifier",
            "fan_control", "ceiling_fan",
            "space_heater", "radiator"
        },
        vendor = "Climate Control",
        device_type = "climate",
        category = "climate",
        priority_ports = {80, 443, 5353},
        essential_services = {"HTTP/HTTPS", "mDNS"},
        description = "空调/温控/空气净化器"
    },

    -- ========================
    -- 4. 安防与报警系统
    -- ========================
    ["security_system"] = {
        patterns = {
            "ring_doorbell", "ring_alarm",
            "nest_cam_outdoor", "nest_hello",
            "arlo_pro", "arlo_ultra",
            "eufy_security", "eufy_cam",
            "simplisafe", "adt_pulse",
            "vivint", "frontpoint",
            "abode_system", "samsung_smartthings_cam",
            "yale_lock", "august_lock", "schlage_encode",
            "motion_sensor", "door_window_sensor",
            "glass_break_sensor", "smoke_detector",
            "co_detector", "leak_sensor",
            "alarm_panel", "security_keypad",
            "siren", "strobe_light"
        },
        vendor = "Security System",
        device_type = "security",
        category = "security",
        priority_ports = {443, 80, 554, 1935, 8883},
        essential_services = {"RTSP", "MQTT", "HTTPS"},
        description = "安防报警系统"
    },

    -- ========================
    -- 5. 摄像头与监控设备
    -- ========================
    ["ip_camera"] = {
        patterns = {
            "nest_cam", "google_nest_cam",
            "arlo", "netgear_arlo",
            "ring_camera", "ring_floodlight",
            "amcrest", "foscam", "dahua", "hikvision",
            "reolink", "ezviz", "yi_camera",
            "wyze_cam", "blink_camera",
            "logitech_circle", "canary",
            "tp-link_kasa_cam", "tapo_camera",
            "axis_communications", "uniview",
            "swann", "lorlux",
            "ip_camera", "cctv", "surveillance",
            "baby_monitor", "pet_monitor",
            "dashcam", "action_cam"
        },
        vendor = "IP Camera",
        device_type = "camera",
        category = "camera",
        priority_ports = {554, 80, 443, 8000, 8554, 37777, 34567},
        essential_services = {"RTSP", "ONVIF", "HTTP/HTTPS"},
        bandwidth_requirement = "high",
        description = "网络摄像头/监控设备"
    },

    -- ========================
    -- 6. 智能音箱与音频
    -- ========================
    ["smart_speaker"] = {
        patterns = {
            "amazon_echo", "echo_dot", "echo_studio",
            "google_home", "google_nest_audio", "google_nest_mini",
            "apple_homepod", "homepod_mini",
            "sonos_one", "sonos_move", "sonos_beam",
            "harmon_kardon_citation", "bose_home",
            "jbl_link", "jbl_authentics",
            "xiaomi_ai_speaker", "mi_speaker", "redmi_speaker",
            "tencent_tsb", "dingdong_speaker",
            "baidu_duer", "aligenie_speaker",
            "roku_streambar", "amazon_fire_tv_stick",
            "chromecast_audio", "chromecast_google_nest",
            "bluetooth_speaker", "wifi_speaker"
        },
        vendor = "Smart Speaker",
        device_type = "speaker",
        category = "audio",
        priority_ports = {5353, 8009, 9000, 1400, 49152-49162},
        essential_services = {"AirPlay", "DLNA", "Cast", "mDNS"},
        bandwidth_requirement = "medium",
        description = "智能音箱/音频播放设备"
    },

    -- ========================
    -- 7. 智能电视与显示设备
    -- ========================
    ["smart_tv"] = {
        patterns = {
            "samsung_smart_tv", "tizen_tv",
            "lg_webos", "webos_tv",
            "sony_android_tv", "bravia",
            "philips_android_tv", "android_tv",
            "tcl_roku_tv", "roku_tv",
            "hisense_vidaa", "vidaa_tv",
            "sharp_aquos", "aquos_tv",
            "panasonic_viera", "viera_tv",
            "toshiba_fire_tv", "fire_tv_edition",
            "vizio_smartcast", "vizio_tv",
            "xbox_one", "playstation_4", "ps4",
            "nintendo_switch", "switch_console",
            "apple_tv", "tv_box",
            "projector", "beam_projector",
            "digital_signage", "display_screen"
        },
        vendor = "Smart TV",
        device_type = "tv",
        category = "display",
        priority_ports = {5353, 1900, 80, 443, 8001, 8002},
        essential_services = {"mDNS", "SSDP", "DLNA", "AirPlay"},
        bandwidth_requirement = "high",
        description = "智能电视/机顶盒/游戏主机"
    },

    -- ========================
    -- 8. 大型智能家电
    -- ========================
    ["smart_appliance"] = {
        patterns = {
            "samsung_refrigerator", "samsung_family_hub",
            "lg_thinq_fridge", "whirlpool_smart",
            "ge_appliances", "bosch_home_connect",
            "samsung_washer", "lg_washer",
            "whirlpool_washer", "miele_washer",
            "samsung_dryer", "lg_dryer",
            "dishwasher_smart", "bosch_dishwasher",
            "samsung_oven", "lg_instaview",
            "instant_pot", "pressure_cooker",
            "coffee_machine", "nespresso",
            "robot_vacuum", "roomba", "shark_ion",
            "deebot", "iRobot", "neato",
            "window_ac", "portable_ac",
            "water_heater", "boiler",
            "washer_dryer_combo", "laundry_center"
        },
        vendor = "Smart Appliance",
        device_type = "appliance",
        category = "appliance",
        priority_ports = {80, 443, 5353, 1883},
        essential_services = {"HTTP/HTTPS", "MQTT", "mDNS"},
        bandwidth_requirement = "low",
        description = "大型智能家电"
    },

    -- ========================
    -- 9. 可穿戴设备
    -- ========================
    ["wearable_device"] = {
        patterns = {
            "apple_watch", "watch_os",
            "fitbit", "fitbit_ionic", "fitbit_versa",
            "garmin", "garmin_fenix", "garmin_forerunner",
            "samsung_gear", "galaxy_watch", "galaxy_fit",
            "huawei_watch", "gt_2", "gt_3",
            "xiaomi_band", "mi_band", "redmi_watch",
            "oneplus_watch", "oppo_watch", "vivo_watch",
            "amazfit", "amazfit_bip", "amazfit_gts",
            "fossil_gen", "fossil_q",
            "ticwatch", "mobvoi",
            "whoop", "oura_ring",
            "peloton", "nordictrack",
            "fitness_tracker", "heart_rate_monitor",
            "sleep_tracker", "activity_tracker"
        },
        vendor = "Wearable Device",
        device_type = "wearable",
        category = "health_fitness",
        priority_ports = {5353, 80, 443},
        essential_services = {"BLE", "WiFi Sync", "mDNS"},
        bandwidth_requirement = "low",
        description = "智能手表/手环/健康追踪器"
    },

    -- ========================
    -- 10. 医疗与健康设备
    -- ========================
    ["medical_health"] = {
        patterns = {
            "withings_scale", "body_composition",
            "omron_bp", "blood_pressure_monitor",
            "glucose_meter", "blood_glucose",
            "pulse_oximeter", "spo2_monitor",
            "ecg_monitor", "ekg_monitor",
            "nebulizer", "inhaler_smart",
            "insulin_pump", "cgm_monitor",
            "telemedicine", "remote_health",
            "pill_dispenser", "medication_reminder",
            "fall_detection", "elderly_monitor",
            "baby_monitor_medical", "apnea_monitor",
            "thermometer_smart", "fever_monitor"
        },
        vendor = "Medical Device",
        device_type = "health",
        category = "medical",
        priority_ports = {443, 80, 5353, 1883},
        essential_services = {"HTTPS", "Bluetooth LE", "mDNS"},
        privacy_sensitive = true,
        data_encryption_required = true,
        description = "医疗健康监测设备"
    },

    -- ========================
    -- 11. 机器人与自动化
    -- ========================
    ["robotics_automation"] = {
        patterns = {
            "irobot_roomba", "roomba_", "irobot_",
            "shark_ion_robot", "shark_robot",
            "ecovacs_deebot", "deebot_",
            "ilife_a", "ilife_robot",
            "neato_botvac", "neato_",
            "roborock", "xiaomi_vacuum",
            "eufy_robovac", "robovac_",
            "bissell", "bissell_smart",
            "lawn_mower_robot", "husqvarna_automower",
            "window_cleaning_robot", "ecovacs_winbot",
            "pool_cleaner_robot", "dolphin_pool",
            "gutter_cleaning_robot",
            "robot_arm", "manipulator",
            "agv", "automated_guided_vehicle",
            "drone", "uav", "quadcopter"
        },
        vendor = "Robot & Automation",
        device_type = "robotics",
        category = "automation",
        priority_ports = {443, 80, 5353, 8883},
        essential_services = {"HTTPS", "MQTT", "mDNS"},
        bandwidth_requirement = "medium",
        description = "机器人/自动化设备"
    },

    -- ========================
    -- 12. 传感器网络
    -- ========================
    ["iot_sensor"] = {
        patterns = {
            "temperature_sensor", "temp_sensor",
            "humidity_sensor", "hygrometer",
            "motion_sensor_pir", "pir_motion",
            "light_sensor", "lux_sensor",
            "pressure_sensor", "barometer",
            "air_quality_sensor", "pm25_sensor",
            "co2_sensor", "voc_sensor",
            "soil_moisture", "soil_sensor",
            "water_level", "flow_sensor",
            "ultrasonic_sensor", "distance_sensor",
            "accelerometer", "gyroscope",
            "magnetometer", "compass",
            "current_sensor", "power_meter",
            "gas_sensor", "smoke_gas",
            "radiation_sensor", "geiger",
            "vibration_sensor", "seismic"
        },
        vendor = "IoT Sensor",
        device_type = "sensor",
        category = "sensing",
        priority_ports = {1883, 8883, 5683, 80},
        essential_services = {"MQTT", "CoAP", "HTTP"},
        bandwidth_requirement = "very_low",
        battery_powered = true,
        description = "各类传感器设备"
    },

    -- ========================
    -- 13. 智能门锁与门禁
    -- ========================
    ["smart_lock_access"] = {
        patterns = {
            "august_smart_lock", "august_wifi",
            "schlage_encode", "schlage_sense",
            "yale_assure", "yale_real_living",
            "kwikset_kevo", "kwikset_halo",
            "level_lock", "level_touch",
            "nuki_smart_lock", "nuki_",
            "danalock", "danalock_v3",
            "lockly", "secure_pro",
            "smart_deadbolt", "electronic_lock",
            "keypad_entry", "access_control",
            "video_intercom", "door_phone",
            "gate_opener", "garage_door",
            "electric_strike", "maglock",
            "rfid_reader", "biometric_reader"
        },
        vendor = "Smart Lock",
        device_type = "lock",
        category = "access_control",
        priority_ports = {443, 80, 5353, 1883},
        essential_services = {"HTTPS", "BLE", "Zigbee/Z-Wave"},
        security_critical = true,
        description = "智能锁/门禁系统"
    },

    -- ========================
    -- 14. 园艺与户外设备
    -- ========================
    ["garden_outdoor"] = {
        patterns = {
            "rachio", "rainmachine", "orbit_irrigation",
            "smart_sprinkler", "irrigation_controller",
            "weather_station", "ambient_weather",
            "netatmo_weather", "weather_flow",
            "solar_panel_monitor", "enphase_envoy",
            "ev_charger", "tesla_wallconnector",
            "juicebox", "chargepoint_home",
            "pool_automation", "pentair_intelliFlo",
            "hot_tub_control", "jacuzzi_smart",
            "outlet_switch", "smart_plug",
            "light_strip", "led_strip",
            "christmas_light", "holiday_decoration",
            "bird_feeder_camera", "wildlife_camera"
        },
        vendor = "Garden & Outdoor",
        device_type = "garden",
        category = "outdoor",
        priority_ports = {80, 443, 1883, 5353},
        essential_services = {"HTTP/HTTPS", "MQTT", "mDNS"},
        weather_resistant = true,
        description = "园艺/户外/能源设备"
    },

    -- ========================
    -- 15. 能源管理系统
    -- ========================
    ["energy_management"] = {
        patterns = {
            "sense_energy", "sense_monitor",
            "ted_pro", "the_energy_detective",
            "emporia_vue", "emporia_smart",
            "wiser_energy", "schneider_electric",
            "smappee", "smappee_energy",
            "neurio_power", "neurio",
            "smart_meter", "ami_meter",
            "solar_inverter", "string_inverter",
            "battery_storage", "powerwall",
            "home_battery", "tesla_powerwall",
            "ups_system", "backup_power",
            "smart_breaker", "leviton_smart",
            "load_controller", "demand_response",
            "evse", "electric_vehicle_supply"
        },
        vendor = "Energy Management",
        device_type = "energy",
        category = "energy",
        priority_ports = {80, 443, 502, 1883},
        essential_services = {"Modbus", "MQTT", "HTTP/HTTPS"},
        safety_critical = true,
        description = "能源监控/储能/充电桩"
    },

    -- ========================
    -- 16. 网络与通信设备
    -- ========================
    ["networking_infrastructure"] = {
        patterns = {
            "router", "gateway", "access_point",
            "switch_managed", "poe_switch",
            "wireless_controller", "wifi_controller",
            "mesh_system", "eero", "orbi", "deco",
            "extender_repeater", "range_extender",
            "nas_server", "synology", "qnap",
            "media_server", "plex_server", "emby",
            "vpn_router", "firewall",
            "load_balancer", "reverse_proxy",
            "dns_server", "dhcp_server",
            "print_server", "file_server",
            "voip_gateway", "sip_phone",
            "video_conference", "zoom_room"
        },
        vendor = "Network Infrastructure",
        device_type = "networking",
        category = "infrastructure",
        priority_ports = {53, 80, 443, 22, 8080, 8443},
        essential_services = {"DNS", "DHCP", "SSH", "HTTP/HTTPS"},
        always_online = true,
        description = "网络基础设施设备"
    },

    -- ========================
    -- 17. 汽车与车载设备
    -- ========================
    ["automotive_iot"] = {
        patterns = {
            "tesla_model", "model_s", "model_3", "model_x", "model_y",
            "bmw_connected", "mercedes_me",
            "ford_sync", "chevrolet_onstar",
            "toyota_entune", "honda_link",
            "audi_mmi", "volvo_oncall",
            "tesla_wallconnector", "home_charging",
            "obdii_scanner", "elm327",
            "dashcam_gps", "blackvue", "thinkware",
            "tire_pressure_monitor", "tpms",
            "car_tracking", "gps_tracker",
            "remote_starter", "compustar",
            "seat_heater", "car_precondition",
            "vehicle_diagnostic", "can_bus"
        },
        vendor = "Automotive IoT",
        device_type = "automotive",
        category = "automotive",
        priority_ports = {443, 80, 5353, 1883},
        essential_services = {"HTTPS", "MQTT", "mDNS"},
        mobile_capable = true,
        description = "汽车互联/车载设备"
    },

    -- ========================
    -- 18. 工业物联网 (IIoT)
    -- ========================
    ["industrial_iot"] = {
        patterns = {
            "plc_programmable", "siemens_s7",
            "modbus_tcp", "bacnet_ip",
            "scada_system", "hmi_panel",
            "industrial_sensor", "proximity_switch",
            "motor_controller", "variable_frequency_drive",
            "conveyor_system", "assembly_line",
            "quality_inspection", "machine_vision",
            "predictive_maintenance", "vibration_analysis",
            "asset_tracking", "rfid_reader_industrial",
            "environmental_monitor_industrial",
            "hazardous_area_sensor",
            "flow_meter_industrial", "level_transmitter",
            "pressure_transmitter", "temperature_probe",
            "actuator_valve", "servo_motor",
            "robotic_arm_industrial", "cnc_machine",
            "3d_printer_industrial", "laser_cutter"
        },
        vendor = "Industrial IoT",
        device_type = "industrial",
        category = "industrial",
        priority_ports = {502, 102, 44818, 443, 80},
        essential_services = {"Modbus TCP", "EtherNet/IP", "BACnet", "OPC UA"},
        reliability_critical = true,
        latency_sensitive = false,
        description = "工业物联网设备"
    }
}

-- ============================================================
-- 特殊端口白名单（IoT 设备常用端口）
-- ============================================================
M.IOT_PORT_WHITELIST = {
    -- mDNS / DNS-SD
    [5353] = {
        name = "mDNS/DNS-SD",
        protocol = "UDP",
        description = "多播 DNS - 设备发现服务",
        category = "discovery",
        essential_for = {"all_apple_devices", "printer_discovery", "chromecast"}
    },
    
    -- SSDP (Simple Service Discovery Protocol)
    [1900] = {
        name = "UPnP/SSDP",
        protocol = "UDP",
        description = "通用即插即用 - IoT 设备发现",
        category = "discovery",
        essential_for = {"smart_tv", "media_renderer", "upnp_devices"}
    },
    
    -- MQTT (Message Queuing Telemetry Transport)
    [1883] = {
        name = "MQTT",
        protocol = "TCP",
        description = "消息队列遥测传输 - IoT 核心协议",
        category = "communication",
        essential_for = {"smart_home_hub", "sensors", "automation"}
    },
    
    -- MQTTS (Secure MQTT)
    [8883] = {
        name = "MQTTS",
        protocol = "TCP",
        description = "安全 MQTT 连接",
        category = "communication_secure",
        essential_for = {"secure_iot", "industrial_iot"}
    },
    
    -- CoAP (Constrained Application Protocol)
    [5683] = {
        name = "CoAP",
        protocol = "UDP",
        description = "受限应用协议 - 轻量级 IoT 协议",
        category = "communication",
        essential_for = {"sensors", "resource_constrained_devices"}
    },
    
    -- RTSP (Real Time Streaming Protocol) - 用于摄像头
    [554] = {
        name = "RTSP",
        protocol = "TCP",
        description = "实时流协议 - 视频监控",
        category = "streaming",
        essential_for = {"ip_camera", "video_surveillance"}
    },
    
    -- ONVIF 设备管理
    [8000] = {
        name = "ONVIF",
        protocol = "TCP",
        description = "开放网络视频接口论坛",
        category = "device_management",
        essential_for = {"ip_camera", "nvr", "video_management"}
    },
    
    -- AirPlay
    [7000] = {
        name = "AirPlay",
        protocol = "TCP",
        description = "Apple 无线投屏协议",
        category = "casting",
        essential_for = {"apple_tv", "homepod", "airport_express"}
    },
    
    -- Chromecast / Google Cast
    [8009] = {
        name = "Google Cast",
        protocol = "TCP",
        description = "Google 投屏服务",
        category = "casting",
        essential_for = {"chromecast", "google_home", "android_tv"}
    },
    
    -- DLNA/UPnP AV Transport
    [5000] = {
        name = "DLNA/UPnP AV",
        protocol = "TCP",
        description = "数字生活网络联盟媒体传输",
        category = "media_sharing",
        essential_for = {"smart_tv", "media_server", "dlna_renderer"}
    },
    
    -- Zigbee gateway (common ports)
    [8989] = {
        name = "Zigbee Gateway",
        protocol = "TCP",
        description = "Zigbee 网关管理",
        category = "protocol_gateway",
        essential_for = {"zigbee_devices", "smart_home_hub"}
    },
    
    -- Z-Wave gateway
    [4999] = {
        name = "Z-Wave Gateway",
        protocol = "TCP",
        description = "Z-Wave 网关管理",
        category = "protocol_gateway",
        essential_for = {"zwave_devices", "home_automation"}
    },
    
    -- Home Assistant
    [8123] = {
        name = "Home Assistant",
        protocol = "TCP",
        description = "开源智能家居平台",
        category = "platform",
        essential_for = {"home_assistant_instance"}
    },
    
    -- Tuya Smart Life platform
    [443] = {
        name = "HTTPS/Tuya Cloud",
        protocol = "TCP",
        description = "涂鸦智能云连接",
        category = "cloud_service",
        essential_for = {"tuya_devices", "smart_life_products"}
    },
    
    -- Philips Hue API
    [80] = {
        name = "Hue Bridge API",
        protocol = "TCP",
        description = "飞利浦 Hue 桥接 API",
        category = "device_api",
        essential_for = {"philips_hue", "hue_ecosystem"}
    }
}

-- ============================================================
-- OUI 厂商前缀扩展数据库
-- ============================================================
M.OUI_VENDOR_EXTENSIONS = {
    -- 智能家居厂商
    ["A47C28"] = {vendor = "Philips Hue", category = "lighting"},
    ["D07E34"] = {vendor = "Xiaomi/Aqara", category = "smart_home"},
    ["04CF8C"] = {vendor = "Xiaomi/Mi", category = "smart_home"},
    ["E09760"] = {vendor = "Tuya Smart", category = "smart_home"},
    ["68572D"] = {vendor = "Samsung SmartThings", category = "smart_home"},
    
    -- 安防厂商
    ["30AE4E"] = {vendor = "Ring (Amazon)", category = "security"},
    ["48F1B7"] = {vendor = "Arlo (Netgear)", category = "camera"},
    ["E406E8"] = {vendor = "Nest (Google)", category = "camera"},
    ["DC2914"] = {vendor = "Eufy (Anker)", category = "security"},
    
    -- 音频厂商
    ["407C2F"] = {vendor = "Sonos", category = "speaker"},
    ["58CB52"] = {vendor = "Amazon Echo", category = "speaker"},
    ["A45D56"] = {vendor = "Google Nest", category = "speaker"},
    ["FCF5C5"] = {vendor = "Apple HomePod", category = "speaker"},
    
    -- 电视厂商
    ["CCB2D2"] = {vendor = "Samsung TV", category = "tv"},
    ["30588A"] = {vendor = "LG TV (WebOS)", category = "tv"},
    ["404A03"] = {vendor = "Sony TV", category = "tv"},
    ["08EA40"] = {vendor = "Roku", category = "tv"},
    
    -- 可穿戴厂商
    ["746573"] = {vendor = "Fitbit", category = "wearable"},
    ["24FD10"] = {vendor = "Garmin", category = "wearable"},
    ["881BF0"] = {vendor = "Samsung Galaxy Watch", category = "wearable"},
    ["41C25F"] = {vendor = "Apple Watch", category = "wearable"},
    
    -- 家电厂商
    ["B056CD"] = {vendor = "iRobot Roomba", category = "robotics"},
    ["F4EC13"] = {vendor = "Ecovacs Deebot", category = "robotics"},
    ["70EE50"] = {vendor = "TP-Link Kasa", category = "appliance"},
    ["50C7BF"] = {vendor = "Belkin WeMo", category = "appliance"},
    
    -- 工业厂商
    ["00A0C0"] = {vendor = "Siemens Industrial", category = "industrial"},
    ["00E0FC"] = {vendor = "Rockwell Automation", category = "industrial"},
    ["00065B"] = {vendor = "Mitsubishi Electric", category = "industrial"},
    ["00BBAA"] = {vendor = "Schneider Electric", category = "industrial"}
}

-- ============================================================
-- 功能函数
-- ============================================================

--- 根据 MAC 地址或设备标识识别 IoT 设备类型
function M.identify_device(device_info)
    local device_name = device_info.hostname or ""
    local mac_address = device_info.mac or ""
    local oui_prefix = mac_address:sub(1, 8):upper():gsub(":", "")
    
    local matched_category = nil
    local confidence_score = 0
    
    -- 方法1：通过主机名模式匹配
    for category_id, fingerprint in pairs(M.IOT_DEVICE_FINGERPRINTS) do
        for _, pattern in ipairs(fingerprint.patterns) do
            if device_name:lower():find(pattern:lower(), 1, true) then
                local score = calculate_confidence(pattern, device_name)
                if score > confidence_score then
                    confidence_score = score
                    matched_category = category_id
                end
            end
        end
    end
    
    -- 方法2：通过 OUI 前缀匹配
    if M.OUI_VENDOR_EXTENSIONS[oui_prefix] then
        local oui_info = M.OUI_VENDOR_EXTENSIONS[oui_prefix]
        
        if not matched_category or confidence_score < 90 then
            return {
                category = oui_info.category,
                vendor = oui_info.vendor,
                method = "oui_match",
                confidence = 95
            }
        else
            -- 结合两种方法提高准确率
            return {
                category = matched_category,
                vendor = M.IOT_DEVICE_FINGERPRINTS[matched_category].vendor,
                oui_vendor = oui_info.vendor,
                method = "combined_match",
                confidence = math.min(confidence_score + 20, 100)
            }
        end
    end
    
    if matched_category then
        local fingerprint = M.IOT_DEVICE_FINGERPRINTS[matched_category]
        return {
            category = matched_category,
            vendor = fingerprint.vendor,
            device_type = fingerprint.device_type,
            description = fingerprint.description,
            method = "hostname_pattern",
            confidence = confidence_score
        }
    end
    
    return nil
end

--- 计算匹配置信度
function calculate_confidence(pattern, hostname)
    local pattern_len = #pattern
    local hostname_lower = hostname:lower()
    local pattern_lower = pattern:lower()
    
    if hostname_lower == pattern_lower then
        return 100  -- 完全匹配
    elseif hostname_lower:find("^" .. pattern_lower) then
        return math.min(90 + pattern_len, 99)  -- 前缀匹配
    elseif hostname_lower:find(pattern_lower) then
        return math.min(70 + pattern_len * 2, 89)  -- 部分匹配
    else
        return 50  -- 模糊匹配
    end
end

--- 判断端口是否为 IoT 必需端口
function M.is_iot_essential_port(port_num)
    port_num = tonumber(port_num)
    return M.IOT_PORT_WHITELIST[port_num] ~= nil
end

--- 获取端口信息
function M.get_port_info(port_num)
    port_num = tonumber(port_num)
    return M.IOT_PORT_WHITELIST[port_num]
end

--- 获取所有 IoT 关键端口列表
function M.get_all_iot_ports()
    local ports = {}
    for port, _ in pairs(M.IOT_PORT_WHITELIST) do
        table.insert(ports, tonumber(port))
    end
    table.sort(ports)
    return ports
end

--- 获取设备类别的必需端口
function M.get_category_ports(category_id)
    local fingerprint = M.IOT_DEVICE_FINGERPRINTS[category_id]
    if fingerprint and fingerprint.priority_ports then
        return fingerprint.priority_ports
    end
    return {}
end

--- 检查设备是否为高带宽需求设备
function M.is_high_bandwidth_device(device_category)
    local fingerprint = M.IOT_DEVICE_FINGERPRINTS[device_category]
    return fingerprint and fingerprint.bandwidth_requirement == "high"
end

--- 检查设备是否为安全关键设备
function M.is_security_critical(device_category)
    local fingerprint = M.IOT_DEVICE_FINGERPRINTS[device_category]
    return fingerprint and fingerprint.security_critical == true
end

--- 检查设备是否为隐私敏感设备
function M.is_privacy_sensitive(device_category)
    local fingerprint = M.IOT_DEVICE_FINGERPRINTS[device_category]
    return fingerprint and fingerprint.privacy_sensitive == true
end

--- 获取设备描述信息
function M.get_device_description(category_id)
    local fingerprint = M.IOT_DEVICE_FINGERPRINTS[category_id]
    if fingerprint then
        return {
            vendor = fingerprint.vendor,
            type = fingerprint.device_type,
            category = fingerprint.category,
            description = fingerprint.description,
            essential_services = fingerprint.essential_services,
            priority_ports = fingerprint.priority_ports
        }
    end
    return nil
end

--- 导出完整的指纹库（用于调试或外部使用）
function M.export_fingerprint_database()
    return {
        version = "2.0.0",
        last_updated = "2026-05-07",
        total_categories = #M.DEVICE_CATEGORIES,
        total_fingerprints = 0,
        categories = M.DEVICE_CATEGORIES,
        fingerprints = M.IOT_DEVICE_FINGERPRINTS,
        port_whitelist = M.IOT_PORT_WHITELIST,
        oui_extensions = M.OUI_VENDOR_EXTENSIONS
    }
end

return M
