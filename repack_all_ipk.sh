#!/bin/bash

PACKAGES_DIR="/mnt/d/软件开发/MAX/路由管家/files/packages"
TEMP_DIR="/tmp/repack_ipk"

mkdir -p "$TEMP_DIR"

for ipk_file in "$PACKAGES_DIR"/*.ipk; do
    if [ -f "$ipk_file" ]; then
        pkg_name=$(basename "$ipk_file" .ipk)
        echo "处理: $pkg_name"
        
        rm -rf "$TEMP_DIR/$pkg_name"
        mkdir -p "$TEMP_DIR/$pkg_name"
        cd "$TEMP_DIR/$pkg_name"
        
        cp "$ipk_file" .
        
        ar -x "$pkg_name.ipk"
        
        if [ -f control.tar.gz ]; then
            tar -xzf control.tar.gz
            
            if [ -f control ]; then
                sed -i 's/Architecture: .*/Architecture: all/' control
                sed -i '/^Depends:/d' control
                sed -i '/^SourceName:/d' control
                sed -i '/^SourceDateEpoch:/d' control
                sed -i '/^Source:/d' control
                sed -i '/^License:/d' control
                sed -i '/^LicenseFiles:/d' control
                
                echo "修改后的控制文件:"
                cat control
                
                tar -czf control.tar.gz control
                rm -f control
                
                rm -f "$pkg_name.ipk"
                ar r "$pkg_name.ipk" debian-binary control.tar.gz data.tar.gz
                
                cp "$pkg_name.ipk" "$PACKAGES_DIR/"
                echo "已更新: $pkg_name.ipk"
                ls -lh "$PACKAGES_DIR/$pkg_name.ipk"
            fi
        fi
    fi
done

echo "完成！"
