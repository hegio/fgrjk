import base64
import re
import urllib.parse

# 读取文件
with open('锋哥软件库节点', 'r', encoding='utf-8') as f:
    content = f.read()

# 尝试 Base64 解码
try:
    decoded = base64.b64decode(content + '=' * (4 - len(content) % 4)).decode('utf-8')
    lines = [l.strip() for l in decoded.split('\n') if l.strip()]
except:
    lines = [l.strip() for l in content.split('\n') if l.strip()]

# 保存明文
with open('nodes_plain.txt', 'w') as f:
    f.write('\n'.join(lines))

print(f"Processed {len(lines)} lines")
