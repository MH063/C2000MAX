# 内置软件包说明

本目录包含DNS加密功能所需的依赖包，用于在路由器上自动安装。

## 软件包列表

### DNS加密核心依赖

1. **libcares.ipk** - c-ares库
   - https-dns-proxy的核心依赖（DoH需要）
   - 提供异步DNS解析功能
   - 架构：aarch64_cortex-a53
   - 版本：1.34.6（已更新，支持DoH）
   - ✅ 已通过WSL交叉编译生成，可直接使用

2. **getdns.ipk** - getdns库
   - stubby的核心依赖（DoT需要）
   - 提供DNS over TLS (DoT)支持
   - 架构：aarch64_cortex-a53
   - 版本：1.7.0

### DNS加密服务

3. **stubby.ipk** - DoT服务
   - 提供DNS over TLS (DoT)功能
   - 依赖：getdns
   - 版本：0.4.3

4. **https-dns-proxy.ipk** - DoH服务
   - 提供DNS over HTTPS (DoH)功能
   - 依赖：libcares（需要1.34+版本）
   - 版本：2025.12.29-r5
   - ✅ 配合新版 libcares 1.34.6 可正常使用

### 其他依赖

5. **libev.ipk** - 事件循环库
   - 通用的异步事件处理库

## 架构兼容性

所有软件包均为 `aarch64_cortex-a53` 架构，适用于：
- 鲲鹏C2000max
- 联发科MT7987平台
- 其他ARMv8 64位处理器

## 使用建议

### 编译新版 libcares 1.34.6（DoH 必需）

由于 https-dns-proxy 需要 c-ares 1.34+ 版本才能正常工作（DoH功能），需要使用 OpenWrt SDK 编译：

#### 前置条件

1. **下载 OpenWrt SDK**（对应你的路由器架构）

   对于鲲鹏C2000max (aarch64_cortex-a53)：
   
   ```bash
   # 从 OpenWrt 官网下载对应的 SDK
   # 例如: openwrt-sdk-23.05.x-armvirt_aarch64_cortex-a53_gcc-13.3.0_musl.Linux-x86_64.tar.xz
   
   wget https://downloads.openwrt.org/releases/23.05.x/targets/armvirt/64/openwrt-sdk-23.05.x-armvirt_aarch64_cortex-a53_gcc-13.3.0_musl.Linux-x86_64.tar.xz
   
   tar -xf openwrt-sdk-*.tar.xz
   ```

2. **安装编译依赖**

   ```bash
   sudo apt-get update
   sudo apt-get install build-essential libncurses-dev gawk git subversion \
       python3 python3-pip zlib1g-dev libssl-dev rsync unzip file
   ```

#### 使用自动编译脚本

项目提供了 `build_libcares.sh` 脚本来自动完成编译：

```bash
# 在 Linux 环境中执行
cd /path/to/路由管家
chmod +x build_libcares.sh

# 运行编译脚本，指定SDK路径
./build_libcares.sh /path/to/openwrt-sdk-*
```

编译成功后：
- 生成的 `libcares.ipk` 会自动复制到 `files/packages/` 目录
- 版本：1.34.6
- 架构：aarch64_cortex-a53

#### 手动编译（如果脚本失败）

```bash
# 1. 进入SDK目录
cd /path/to/openwrt-sdk-*

# 2. 创建feeds目录并复制Makefile
mkdir -p package/feeds/router-assistant
cp ../packages/libcares/Makefile package/feeds/router-assistant/

# 3. 复制源码包到DL目录
cp ../files/packages/c-ares-1.34.6.tar.gz dl/

# 4. 更新feeds
./scripts/feeds update packages
./scripts/feeds install libcares

# 5. 配置
make defconfig
echo "CONFIG_PACKAGE_libcares=y" >> .config
make defconfig

# 6. 编译
make package/libcares/compile V=s

# 7. 查找生成的ipk
find bin/packages/aarch64_cortex-a53/ -name "libcares_*.ipk"
```

### DNS加密功能状态

- ✅ **DoT (stubby)** - 完全可用，推荐使用
- ✅ **DoH (https-dns-proxy)** - 已集成 libcares 1.34.6，完全可用

### DoT 配置

插件已内置优化的 stubby 配置文件，使用国内DNS服务器：
- 阿里DNS (223.5.5.5, 223.6.6.6)
- DNSPod (119.29.29.29, 119.28.28.28)

### 自动安装

当用户在路由管家界面中启用DNS加密功能时，系统会：
1. 检测是否已安装所需依赖
2. 自动从本目录安装缺失的依赖包
3. 配置并启动DNS加密服务

## 更新日志

- 2026-05-03: 添加c-ares编译脚本和Makefile，支持DoH功能
- 2026-05-03: 更新libcares版本说明为1.34.6
- 2026-05-03: 添加c-ares-1.34.6.tar.gz源码包，用于升级DoH依赖
- 2026-05-03: 添加libcares和getdns依赖包，解决DNS加密服务启动失败问题
- 2026-05-03: 优化stubby配置，使用国内DNS服务器
- 2026-05-03: 添加stubby.yml配置文件到插件
