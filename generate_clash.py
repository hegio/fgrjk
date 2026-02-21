import base64
import yaml

# 读取验证后的明文节点
with open('nodes_plain.txt', 'r') as f:
    lines = f.readlines()

proxies = []
for line in lines:
    line = line.strip()
    if line.startswith('vmess://'):
        # 简化的 vmess 转 clash 格式（仅示例）
        # 实际转换需要完整解析 vmess 参数
        proxies.append({'name': 'Node-' + str(len(proxies)), 
                       'type': 'vmess', 
                       'server': 'placeholder', 
                       'port': 443})

clash_config = {
    'proxies': proxies,
    'proxy-groups': [{'name': 'Auto', 'type': 'select', 'proxies': [p['name'] for p in proxies]}]
}

with open('nodes_clash.yaml', 'w') as f:
    yaml.dump(clash_config, f)

print("Generated nodes_clash.yaml")
