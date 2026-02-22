import json

# 读取明文节点
with open('nodes_plain.txt', 'r') as f:
    lines = [l.strip() for l in f if l.strip()]

outbounds = [{"type": "direct", "tag": "direct"}]

for i, line in enumerate(lines):
    if line.startswith(('vmess://', 'vless://', 'trojan://', 'ss://')):
        outbounds.append({
            "type": "selector",
            "tag": f"node_{i}",
            "outbounds": ["direct"]
        })

config = {
    "log": {"level": "info"},
    "dns": {"servers": [{"address": "8.8.8.8"}]},
    "outbounds": outbounds
}

with open('nodes_singbox.json', 'w') as f:
    json.dump(config, f, indent=2)

print("Generated nodes_singbox.json")
