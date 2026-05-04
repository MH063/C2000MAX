#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IPK格式转换工具: Debian ar格式 -> tar.gz格式
用于解决精简OpenWrt环境不支持ar解压的问题
"""

import os
import sys
import struct
import tarfile
import gzip
import shutil
import tempfile
import io

def read_ar_header(f):
    """读取Debian ar文件头（60字节）"""
    data = f.read(60)
    if len(data) < 60:
        return None
    name = data[0:16].decode('ascii', errors='ignore').strip()
    size = int(data[48:58].decode('ascii').strip())
    return {'name': name, 'size': size}

def extract_ar_to_targz(ipk_path, output_path):
    """将Debian ar格式的IPK转换为tar.gz格式"""
    
    print(f"Processing: {os.path.basename(ipk_path)}")
    
    with open(ipk_path, 'rb') as f:
        magic = f.read(8)
        if magic != b'!<arch>\n':
            print(f"  ERROR: Not valid ar format (magic: {magic})")
            return False
        
        members = []
        while True:
            header = read_ar_header(f)
            if not header:
                break
            
            name = header['name']
            size = header['size']
            
            if name in ['/', '//']:
                f.seek(size + (size % 2), 1)
                continue
            
            data = f.read(size)
            if size % 2:
                f.read(1)
            
            members.append({'name': name, 'data': data})
        
        print(f"  Found {len(members)} members: {[m['name'] for m in members]}")
        
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpfile = os.path.join(tmpdir, 'content.tar')
            
            with tarfile.open(tmpfile, 'w') as tar:
                for member in members:
                    info = tarfile.TarInfo(name=member['name'])
                    info.size = len(member['data'])
                    # Use BytesIO to wrap bytes data for addfile
                    tar.addfile(info, io.BytesIO(member['data']))
            
            with open(tmpfile, 'rb') as tf:
                with gzip.open(output_path, 'wb') as gf:
                    shutil.copyfileobj(tf, gf)
        
        orig_size = os.path.getsize(ipk_path)
        new_size = os.path.getsize(output_path)
        print(f"  OK: {orig_size} -> {new_size} bytes")
        return True

def main():
    packages_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'files', 'packages')
    
    if not os.path.isdir(packages_dir):
        print(f"ERROR: Package dir not found: {packages_dir}")
        sys.exit(1)
    
    ipk_files = [f for f in os.listdir(packages_dir) if f.endswith('.ipk')]
    
    if not ipk_files:
        print("No .ipk files found")
        sys.exit(1)
    
    print(f"Found {len(ipk_files)} IPK files")
    print("=" * 50)
    
    success = 0
    fail = 0
    
    for ipk_file in sorted(ipk_files):
        ipk_path = os.path.join(packages_dir, ipk_file)
        output_path = ipk_path
        
        backup_path = ipk_path + '.bak'
        if not os.path.exists(backup_path):
            shutil.copy2(ipk_path, backup_path)
        
        try:
            if extract_ar_to_targz(ipk_path, output_path):
                success += 1
            else:
                fail += 1
        except Exception as e:
            print(f"  FAILED: {e}")
            fail += 1
    
    print("=" * 50)
    print(f"Done! Success: {success}, Failed: {fail}")
    
    if fail > 0:
        print("\nNote: Failed files kept original, .bak is backup")
        sys.exit(1)

if __name__ == '__main__':
    main()
