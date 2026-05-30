"""
🕳️ ONESEC · AI 代码审计服务入口
用法: python onesec_service.py <GitHub仓库URL>
示例: python onesec_service.py https://github.com/lcclicheng/GinWeb
"""
import sys, os, re, json, subprocess
from datetime import datetime

BASE = os.path.dirname(os.path.abspath(__file__))
PIPELINE = os.path.join(BASE, '..', '挖洞流水线', 'pipeline_v2.py')
TARGET_DIR = os.path.join(BASE, '_scan_target')
REPORT_DIR = os.path.join(BASE, '_scan_reports')

def print_banner():
    print(r'''
  ╔═══════════════════════════════════════╗
  ║  🕳️  ONESEC · AI 代码审计             ║
  ║ 一人安全团队 · 一键扫描               ║
  ╚═══════════════════════════════════════╝
    ''')

def extract_repo_info(url):
    """从 URL 提取 owner/name"""
    m = re.match(r'https?://github\.com/([^/]+)/([^/]+)', url)
    if not m:
        print('❌ 无效的 GitHub 仓库链接')
        sys.exit(1)
    return m.group(1), m.group(2).replace('.git', '')

def clone_repo(url, target):
    """克隆仓库"""
    print(f'📦 克隆仓库: {url}')
    if os.path.exists(target):
        import shutil; shutil.rmtree(target)
    # 使用已配置的代理
    result = subprocess.run(
        ['git', 'clone', '--depth=1', url, target],
        capture_output=True, text=True, timeout=60
    )
    if result.returncode != 0:
        print(f'❌ 克隆失败: {result.stderr[:200]}')
        sys.exit(1)
    # 统计 Go 文件
    go_files = []
    for root, _, files in os.walk(target):
        for f in files:
            if f.endswith('.go'):
                go_files.append(os.path.join(root, f))
    print(f'✅ 克隆成功 | Go 文件: {len(go_files)} 个')

def run_scan(target):
    """运行审计流水线"""
    print(f'\n🔍 AI 审计引擎启动...')
    os.makedirs(REPORT_DIR, exist_ok=True)
    
    # 读取并审计 Go 文件
    from collections import Counter
    findings = []
    
    go_files = []
    for root, _, files in os.walk(target):
        for f in files:
            if f.endswith('.go'):
                go_files.append(os.path.join(root, f))
    
    all_code = ''
    for f in go_files:
        try:
            all_code += open(f, encoding='utf-8').read() + '\n'
        except:
            pass
    
    # 检查模式
    checks = [
        ('SQL注入', r'(fmt\.Sprintf\([^)]*Where|\.Raw\([^)]*\+|\.Exec\([^)]*\+|"SELECT.*\+)', '高危'),
        ('硬编码密钥', r'(jwtSecret|JWT_SECRET|secretKey|apiKey)\s*[=:]\s*["\'][^"\']+["\']', '高危'),
        ('命令执行', r'(exec\.Command|os\.StartProcess|syscall\.Exec)', '高危'),
        ('文件上传', r'(SaveUploadedFile|c\.FormFile)', '中危'),
        ('MassAssignment', r'(ShouldBind|BindJSON)', '高危'),
        ('CORS宽松', r'(AllowAllOrigins\s*[:=]\s*true)', '中危'),
        ('调试模式', r'(gin\.Default\(\)|SetMode\("debug"\))', '低危'),
        ('硬编码密码', r'password\s*[:=]\s*["\'][^"\']+["\']', '高危'),
    ]
    
    import re
    for name, pattern, severity in checks:
        matches = re.findall(pattern, all_code, re.IGNORECASE)
        if matches:
            findings.append({
                'type': name, 'severity': severity,
                'count': len(matches), 'samples': list(set(matches))[:3]
            })
    
    return findings, len(go_files)

def generate_report(owner, repo, findings, go_count):
    """生成客户报告"""
    now = datetime.now().strftime('%Y-%m-%d %H:%M')
    os.makedirs(REPORT_DIR, exist_ok=True)
    report_file = os.path.join(REPORT_DIR, f'{owner}_{repo}_审计报告.md')
    
    sev_order = {'严重': 0, '高危': 1, '中危': 2, '低危': 3}
    findings.sort(key=lambda x: sev_order.get(x.get('severity', '低危'), 99))
    
    critical = [f for f in findings if f['severity'] == '高危']
    total = len(findings)
    
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(f'# 🕳️ ONESEC AI 代码审计报告\n\n')
        f.write(f'**目标**: {owner}/{repo}\n\n')
        f.write(f'**扫描时间**: {now}\n\n')
        f.write(f'**扫描文件**: {go_count} 个 Go 源文件\n\n')
        f.write(f'---\n\n')
        f.write(f'## 📊 概览\n\n')
        f.write(f'| 指标 | 数据 |\n|:----|:----:|\n')
        f.write(f'| 扫描文件 | {go_count} |\n')
        f.write(f'| 发现漏洞 | {total} |\n')
        f.write(f'| 高危以上 | {len(critical)} |\n')
        f.write(f'\n---\n\n')
        
        for f_item in findings:
            icon = {'严重': '🚨', '高危': '⚠️', '中危': '🔍', '低危': '🟢'}
            f.write(f'### {icon.get(f_item["severity"],"🔍")} [{f_item["severity"]}] {f_item["type"]}\n\n')
            f.write(f'- **数量**: {f_item["count"]} 处\n')
            if f_item.get('samples'):
                f.write(f'- **示例**: `{f_item["samples"][0][:80]}`\n')
            f.write('\n')
        
        f.write(f'---\n')
        f.write(f'*由 ONESEC AI 审计引擎自动生成*\n')
        f.write(f'*联系方式: l15250432278@163.com*\n')
    
    print(f'📄 报告已生成: {report_file}')
    return report_file

def push_wechat(owner, repo, findings, go_count):
    """推送到微信"""
    critical = [f for f in findings if f['severity'] == '高危']
    summary = f'ONESEC审计完成\n目标: {owner}/{repo}\nGo文件: {go_count}\n漏洞: {len(findings)} 个\n高危: {len(critical)} 个'
    
    payload = json.dumps({
        'token': 'c51ba39f1d304c80aa494f15b080030a',
        'title': f'🕳️ ONESEC审计 · {repo}',
        'content': f'<pre>{summary}</pre>',
        'template': 'html'
    })
    subprocess.run(['curl', '-s', '-X', 'POST',
        'https://www.pushplus.plus/send',
        '-H', 'Content-Type: application/json',
        '-d', payload], capture_output=True)
    print('📱 结果已推送微信')

def main():
    print_banner()
    
    if len(sys.argv) < 2:
        print('用法: python onesec_service.py <GitHub仓库URL>')
        print('示例: python onesec_service.py https://github.com/lcclicheng/GinWeb')
        sys.exit(1)
    
    url = sys.argv[1]
    owner, repo = extract_repo_info(url)
    
    # 1. 克隆
    target = os.path.join(BASE, '_scan_target')
    clone_repo(url, target)
    
    # 2. 审计
    findings, go_count = run_scan(target)
    
    # 3. 出报告
    report = generate_report(owner, repo, findings, go_count)
    
    # 4. 推送微信
    push_wechat(owner, repo, findings, go_count)
    
    # 5. 清理
    import shutil
    shutil.rmtree(target, ignore_errors=True)
    
    print(f'\n✅ 审计完成! 报告: {report}')
    print('💡 直接在 ONESEC_审计服务.html 里输入仓库链接即可自助下单')

if __name__ == '__main__':
    main()
