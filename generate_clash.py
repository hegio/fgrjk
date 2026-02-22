import yaml
import base64
import json
import urllib.parse
import re

def parse_vmess(link):
    """解析 vmess:// 链接"""
    try:
        b64_data = link[8:]
        b64_data += '=' * (4 - len(b64_data) % 4)
        json_str = base64.b64decode(b64_data).decode('utf-8')
        data = json.loads(json_str)
        
        node = {
            'name': data.get('ps', 'VMess Node'),
            'type': 'vmess',
            'server': data.get('add', ''),
            'port': int(data.get('port', 443)),
            'uuid': data.get('id', ''),
            'alterId': int(data.get('aid', 0)),
            'cipher': 'auto',
            'tls': data.get('tls', '') == 'tls',
            'network': data.get('net', 'tcp'),
            'ws-opts': {}
        }
        
        # WebSocket 配置
        if node['network'] == 'ws':
            node['ws-opts']['path'] = data.get('path', '/')
            if data.get('host'):
                node['ws-opts']['headers'] = {'Host': data['host']}
        
        # 跳过无效节点
        if not node['server'] or not node['uuid']:
            return None
        return node
    except Exception as e:
        print(f"Parse vmess error: {e}")
        return None

def parse_vless(link):
    """解析 vless:// 链接"""
    try:
        # vless://uuid@server:port?params#name
        match = re.match(r'vless://([^@]+)@([^:]+):(\d+)\?([^#]+)#(.+)', link)
        if not match:
            # 尝试不带 name 的格式
            match = re.match(r'vless://([^@]+)@([^:]+):(\d+)\?(.+)', link)
            if match:
                uuid, server, port, params = match.groups()
                name = f"VLESS-{server}"
            else:
                return None
        else:
            uuid, server, port, params, name = match.groups()
        
        query = urllib.parse.parse_qs(params)
        
        node = {
            'name': urllib.parse.unquote(name),
            'type': 'vless',
            'server': server,
            'port': int(port),
            'uuid': uuid,
            'tls': query.get('security', [''])[0] == 'tls',
            'network': query.get('type', ['tcp'])[0],
            'udp': True
        }
        
        # XTLS/Flow 支持
        flow = query.get('flow', [''])[0]
        if flow:
            node['flow'] = flow
        
        # WebSocket / gRPC
        if node['network'] == 'ws':
            node['ws-opts'] = {
                'path': query.get('path', ['/'])[0],
                'headers': {'Host': query.get('sni', [server])[0]}
            }
        
        return node
    except Exception as e:
        print(f"Parse vless error: {e}")
        return None

def parse_trojan(link):
    """解析 trojan:// 链接"""
    try:
        # trojan://password@server:port?params#name
        match = re.match(r'trojan://([^@]+)@([^:]+):(\d+)\?([^#]+)#(.+)', link)
        if not match:
            match = re.match(r'trojan://([^@]+)@([^:]+):(\d+)#(.+)', link)
            if match:
                password, server, port, name = match.groups()
                params = ''
            else:
                return None
        else:
            password, server, port, params, name = match.groups()
        
        query = urllib.parse.parse_qs(params) if params else {}
        
        node = {
            'name': urllib.parse.unquote(name),
            'type': 'trojan',
            'server': server,
            'port': int(port),
            'password': password,
            'tls': True,
            'sni': query.get('sni', [server])[0],
            'udp': True
        }
        
        # 跳过无效
        if not node['server'] or not node['password']:
            return None
        return node
    except Exception as e:
        print(f"Parse trojan error: {e}")
        return None

def parse_ss(link):
    """解析 ss:// 链接"""
    try:
        # ss://method:password@server:port#name
        # 或 ss://base64(method:password)@server:port#name
        if link.startswith('ss://'):
            content = link[5:]
        
        # 检查是否是 base64 编码
        if '@' not in content and content.startswith('Ym'):
            # base64 编码的旧格式
            parts = content.split('@')
            if len(parts) == 2:
                b64 = parts[0] + '=' * (4 - len(parts[0]) % 4)
                method_pass = base64.b64decode(b64).decode('utf-8')
                server_part = parts[1]
            else:
                return None
        else:
            # 新格式：直接解析
            match = re.match(r'(.+?)@(.+)', content)
            if not match:
                return None
            method_pass = urllib.parse.unquote(match.group(1))
            server_part = match.group(2)
        
        method, password = method_pass.split(':', 1)
        
        # 解析 server:port#name
        if '#' in server_part:
            server_port, name = server_part.split('#', 1)
            name = urllib.parse.unquote(name)
        else:
            server_port = server_part
            name = f"SS-{server_part.split(':')[0]}"
        
        server, port = server_port.split(':')
        
        node = {
            'name': name,
            'type': 'ss',
            'server': server,
            'port': int(port),
            'cipher': method,
            'password': password,
            'udp': True
        }
        return node
    except Exception as e:
        print(f"Parse ss error: {e}")
        return None

# 读取明文节点
with open('nodes_plain.txt', 'r') as f:
    lines = f.readlines()

proxies = []
errors = []

for line in lines:
    line = line.strip()
    if not line:
        continue
    
    node = None
    if line.startswith('vmess://'):
        node = parse_vmess(line)
    elif line.startswith('vless://'):
        node = parse_vless(line)
    elif line.startswith('trojan://'):
        node = parse_trojan(line)
    elif line.startswith('ss://'):
        node = parse_ss(line)
    
    if node:
        # 去重：检查是否已有相同 name
        existing = [p for p in proxies if p['name'] == node['name']]
        if not existing:
            proxies.append(node)
        else:
            node['name'] = node['name'] + '-2'
            proxies.append(node)
    else:
        errors.append(line[:50] + '...' if len(line) > 50 else line)

print(f"✓ Successfully parsed {len(proxies)} nodes")
print(f"✗ Failed to parse {len(errors)} lines")

# 生成 Clash 配置
clash_config = {
    'mixed-port': 7890,
    'allow-lan': True,
    'mode': 'rule',
    'log-level': 'info',
    'external-controller': '0.0.0.0:9090',
    'dns': {
        'enable': True,
        'nameserver': ['114.114.114.114', '8.8.8.8']
    },
    'proxies': proxies,
    'proxy-groups': [
        {
            'name': 'Auto',
            'type': 'select',
            'proxies': [p['name'] for p in proxies[:10]]  # 最多前10个
        },
        {
            'name': 'LoadBalance',
            'type': 'load-balance',
            'strategy': 'consistent-hashing',
            'proxies': [p['name'] for p in proxies],
            'url': 'http://www.gstatic.com/generate_204',
            'interval': 300
        }
    ],
    'rules': [
        'DOMAIN-SUFFIX,google.com,Auto',
        'DOMAIN-SUFFIX,youtube.com,Auto',
        'DOMAIN-KEYWORD,google,Auto',
        'MATCH,DIRECT'
    ]
}

with open('nodes_clash.yaml', 'w', encoding='utf-8') as f:
    yaml.dump(clash_config, f, default_flow_style=False, allow_unicode=True)

print("Generated nodes_clash.yaml")

# 同时生成适合 Clash Verge/CFW 的 config.yaml
with open('config.yaml', 'w', encoding='utf-8') as f:
    yaml.dump(clash_config, f, default_flow_style=False, allow_unicode=True)
    
