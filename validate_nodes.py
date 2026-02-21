import base64
import json
import re
import urllib.parse

def decode_vmess(link):
    """解码 vmess 链接检查有效性"""
    try:
        if link.startswith('vmess://'):
            b64_data = link[8:]
            # 补全 base64 填充
            b64_data += '=' * (4 - len(b64_data) % 4)
            json_str = base64.b64decode(b64_data).decode('utf-8')
            return json.loads(json_str)
    except:
        return None
    return None

def is_safe_node(node_info):
    """检查节点是否安全（过滤恶意节点）"""
    if not node_info:
        return False
    
    # 检查是否包含危险端口（如 22-SSH, 3389-RDP）
    port = node_info.get('port', 0)
    if port in [22, 23, 3389, 3306, 1433, 5432]:
        return False
    
    # 检查是否包含内网IP（防止代理到本地）
    ip = node_info.get('add', '')
    private_ips = ['127.', '10.', '192.168.', '172.']
    if any(ip.startswith(x) for x in private_ips):
        return False
    
    return True

# 读取并处理
with open('锋哥软件库节点', 'r', encoding='utf-8') as f:
    content = f.read()

valid_nodes = []
invalid_count = 0

# 支持多种格式：Base64编码或明文
try:
    # 尝试 Base64 解码
    decoded = base64.b64decode(content + '=' * (4 - len(content) % 4)).decode('utf-8')
    lines = decoded.strip().split('\n')
    is_base64 = True
except:
    lines = content.strip().split('\n')
    is_base64 = False

for line in lines:
    line = line.strip()
    if not line:
        continue
    
    # 验证 vmess 节点
    if line.startswith('vmess://'):
        info = decode_vmess(line)
        if is_safe_node(info):
            valid_nodes.append(line)
        else:
            invalid_count += 1
    # 验证 vless/trojan/ss 节点（格式检查）
    elif any(line.startswith(p) for p in ['vless://', 'trojan://', 'ss://', 'ssr://']):
        # 基础格式验证
        if re.match(r'^(vless|trojan|ss|ssr)://[^/\s]+', line):
            valid_nodes.append(line)
        else:
            invalid_count += 1
    else:
        # 保留其他可能的内容（如注释）
        if not line.startswith('#'):
            valid_nodes.append(line)

# 输出统计
print(f"✓ Valid nodes: {len(valid_nodes)}")
print(f"✗ Filtered invalid/dangerous nodes: {invalid_count}")
print(f"Original format: {'Base64' if is_base64 else 'Plain text'}")

# 重新编码为 Base64（v2rayN 标准格式）
output_content = '\n'.join(valid_nodes)
output_base64 = base64.b64encode(output_content.encode()).decode()

with open('nodes_safe.txt', 'w') as f:
    f.write(output_base64)

with open('nodes_plain.txt', 'w') as f:
    f.write(output_content)

print("Generated: nodes_safe.txt (Base64) and nodes_plain.txt (Plain)")
