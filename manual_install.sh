#!/bin/bash

# ============================================================
# 路由管家 - 手动安装脚本
# 功能：不依赖opkg，直接解压安装插件及所有依赖
# 使用方法: sh manual_install.sh <ipk文件路径>
# 示例: sh manual_install.sh /tmp/路由管家1.0.0.ipk
# ============================================================

set -e

IPK_FILE="$1"

if [ -z "$IPK_FILE" ]; then
    echo "错误: 请指定IPK文件路径"
    echo "用法: sh $0 <ipk文件>"
    echo "示例: sh $0 /tmp/路由管家1.0.0.ipk"
    exit 1
fi

if [ ! -f "$IPK_FILE" ]; then
    echo "错误: IPK文件不存在: $IPK_FILE"
    exit 1
fi

echo "========================================="
echo "  路由管家 - 手动安装工具"
echo "========================================="
echo ""
echo "IPK文件: $IPK_FILE"
echo ""

# 创建临时工作目录
TMP_DIR="/tmp/router_assistant_install"
echo "[1/6] 准备安装环境..."
rm -rf "$TMP_DIR" 2>/dev/null
mkdir -p "$TMP_DIR"
echo "✓ 临时目录已创建: $TMP_DIR"

# 步骤1: 解压IPK文件
echo ""
echo "[2/6] 解压IPK文件..."
cd "$TMP_DIR"
if tar xzf "$IPK_FILE" 2>/dev/null; then
    echo "✓ IPK文件解压成功"
else
    echo "✗ 错误: IPK文件解压失败，请检查文件是否损坏"
    rm -rf "$TMP_DIR"
    exit 1
fi

# 验证必要文件
if [ ! -f data.tar.gz ] || [ ! -f control.tar.gz ]; then
    echo "✗ 错误: IPK文件格式不正确，缺少data.tar.gz或control.tar.gz"
    rm -rf "$TMP_DIR"
    exit 1
fi
echo "✓ IPK文件验证通过"

# 步骤2: 插件程序数据
echo ""
echo "[3/6] 安装插件程序文件..."
if tar xzf data.tar.gz -C / 2>/dev/null; then
    echo "✓ 程序文件已安装到系统目录"
else
    echo "✗ 错误: 程序文件安装失败"
    rm -rf "$TMP_DIR"
    exit 1
fi

# 设置可执行权限
chmod +x /etc/init.d/traffic-stats 2>/dev/null
chmod +x /usr/bin/homebox 2>/dev/null
chmod +x /usr/libexec/router_assistant/* 2>/dev/null
echo "✓ 可执行权限已设置"

# 步骤3: 安装控制信息
echo ""
echo "[4/6] 安装控制信息..."
mkdir -p /usr/lib/opkg/info 2>/dev/null
if tar xzf control.tar.gz -C /usr/lib/opkg/info/ 2>/dev/null; then
    echo "✓ 控制信息已安装"
else
    echo "⚠ 控制信息安装失败（非致命）"
fi

# 步骤4: 手动安装DNS加密依赖包
echo ""
echo "[5/6] 检查并安装DNS加密依赖包..."
DEPS_DIR="/usr/share/router-assistant/packages"
if [ -d "$DEPS_DIR" ]; then
    DEPS_COUNT=$(ls "$DEPS_DIR"/*.ipk 2>/dev/null | wc -l)
    echo "发现 $DEPS_COUNT 个依赖包"
    
    for dep_ipk in "$DEPS_DIR"/*.ipk; do
        [ -f "$dep_ipk" ] || continue
        
        dep_name=$(basename "$dep_ipk" .ipk)
        dep_base=$(echo "$dep_name" | sed 's/_.*//')
        
        # 根据包名确定检查文件
        case $dep_base in
            stubby) check_file="/usr/bin/stubby" ;;
            https-dns-proxy) check_file="/usr/bin/https-dns-proxy" ;;
            libcares) check_file="/usr/lib/libcares.so.2" ;;
            getdns) check_file="/usr/lib/libgetdns.so.10" ;;
            libev) check_file="/usr/lib/libev.so.4" ;;
            *) 
                echo "  ⚠ 未知的依赖包: $dep_base，跳过"
                continue 
                ;;
        esac
        
        # 如果关键文件不存在，则手动安装
        if [ ! -f "$check_file" ]; then
            echo "  → 安装依赖: $dep_base ..."
            
            dep_tmp="/tmp/install_$dep_base"
            rm -rf "$dep_tmp" 2>/dev/null
            mkdir -p "$dep_tmp"
            
            if cd "$dep_tmp" && tar xzf "$dep_ipk" 2>/dev/null; then
                [ -f data.tar.gz ] && tar xzf data.tar.gz -C / 2>/dev/null
                mkdir -p /usr/lib/opkg/info 2>/dev/null
                [ -f control.tar.gz ] && tar xzf control.tar.gz -C /usr/lib/opkg/info/ 2>/dev/null
                [ -f control/postinst ] && sh control/postinst install 2>/dev/null
                echo "  ✓ $dep_base 安装完成"
            else
                echo "  ✗ $dep_base 解压失败"
            fi
            
            rm -rf "$dep_tmp" 2>/dev/null
        else
            echo "  ✓ $dep_base 已存在，跳过"
        fi
    done
else
    echo "⚠ 未找到依赖包目录: $DEPS_DIR"
fi

# 步骤5: 执行postinst初始化脚本
echo ""
echo "[6/6] 执行初始化配置..."
POSTINST="/usr/lib/opkg/info/路由管家.postinst"
if [ -f "$POSTINST" ]; then
    # 清理旧版状态（防止冲突）
    /etc/init.d/traffic-stats stop 2>/dev/null || true
    
    # 执行安装后脚本
    if sh "$POSTINST" install 2>/dev/null; then
        echo "✓ 初始化配置完成"
    else
        echo "⚠ 初始化脚本执行出错（可能部分功能不可用）"
    fi
else
    echo "⚠ 未找到postinst脚本，跳过初始化"
fi

# 清理临时目录
rm -rf "$TMP_DIR" 2>/dev/null

# 验证安装结果
echo ""
echo "========================================="
echo "  安装完成！验证结果："
echo "========================================="

check_status() {
    local desc="$1"
    local file="$2"
    if [ -f "$file" ]; then
        echo "  ✓ $desc"
        return 0
    else
        echo "  ✗ $desc (缺失)"
        return 1
    fi
}

check_status "主程序控制器" "/usr/lib/lua/luci/controller/router_assistant.lua"
check_status "前端页面" "/usr/lib/lua/luci/view/router_assistant/panel.htm"
check_status "流量统计服务" "/etc/init.d/traffic-stats"
check_status "流量采集脚本" "/usr/libexec/router_assistant/collect_traffic.lua"
check_status "Homebox测速工具" "/usr/bin/homebox"

# 检查依赖包
echo ""
echo "--- DNS加密依赖 ---"
check_status "stubby (DoT客户端)" "/usr/bin/stubby"
check_status "https-dns-proxy (DoH客户端)" "/usr/bin/https-dns-proxy"
check_status "libcares (DNS解析库)" "/usr/lib/libcares.so.2"
check_status "getdns (DNS库)" "/usr/lib/libgetdns.so.10"

# 服务状态
echo ""
echo "--- 服务状态 ---"
if pgrep -f traffic-stats >/dev/null 2>&1; then
    echo "  ✓ 流量统计服务运行中"
else
    echo "  ⚠ 流量统计服务未运行（重启后自动启动）"
fi

echo ""
echo "========================================="
echo "  提示：请刷新浏览器访问LuCI界面"
echo "========================================="
