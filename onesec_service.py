"""
🕳️ ONESEC · AI 代码审计服务 v3.0
   调用 pipeline_v3 引擎 (Scrapling + Playwright)
"""
import sys, os, re, json, subprocess
from datetime import datetime

BASE = os.path.dirname(os.path.abspath(__file__))
PIPELINE = os.path.join(BASE, 'pipeline_v3.py')
TARGET_DIR = os.path.join(BASE, '_scan_target')
REPORT_DIR = os.path.join(BASE, '_scan_reports')
os.makedirs(REPORT_DIR, exist_ok=True)

def print_banner():
    print(r'''
  ╔═══════════════════════════════════════╗
  ║  🕳️  ONESEC v3.0                      ║
  ║  Scrapling侦察 + Playwright验证       ║
  ╚═══════════════════════════════════════╝
    ''')

def extract_repo_info(url):
    m = re.match(r'https?://github\.com/([^/]+)/([^/]+)', url)
    if not m:
        print('❌ 无效的 GitHub 仓库链接')
        sys.exit(1)
    return m.group(1), m.group(2).replace('.git', '')

def clone_repo(url, target):
    print(f'📦 克隆: {url}')
    if os.path.exists(target):
        import shutil
        shutil.rmtree(target, ignore_errors=True)
    r = subprocess.run(['git', 'clone', '--depth=1', url, target],
                       capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        print(f'❌ 克隆失败: {r.stderr[:200]}')
        sys.exit(1)
    go_files = sum(1 for _, _, fs in os.walk(target) for f in fs if f.endswith('.go'))
    print(f'✅ 成功 | Go 文件: {go_files}')

def run_scan(target, url=''):
    """调用 pipeline_v3 引擎"""
    env = os.environ.copy()
    if url:
        env['TARGET_URL'] = url
    
    result = subprocess.run(
        [sys.executable, PIPELINE],
        cwd=os.path.dirname(PIPELINE),
        capture_output=True, text=True, timeout=300,
        env=env
    )
    print(result.stdout)
    if result.stderr:
        print('⚠️ ', result.stderr[:500])

def collect_report(repo, target):
    """收集 v3 生成的报告"""
    reports_dir = os.path.join(os.path.dirname(PIPELINE), 'reports-v3')
    if os.path.exists(reports_dir):
        reports = [f for f in os.listdir(reports_dir) if f.endswith('.md')]
        if reports:
            src = os.path.join(reports_dir, reports[-1])
            dst = os.path.join(REPORT_DIR, f'{repo}_审计报告.md')
            import shutil
            shutil.copy2(src, dst)
            print(f'📄 报告: {dst}')
            return dst
    return None

def push_wechat(repo, report_file):
    """推微信"""
    if not report_file or not os.path.exists(report_file):
        return
    with open(report_file, encoding='utf-8') as f:
        content = f.read()
    lines = content.split('\n')[:30]
    summary = '\n'.join([l for l in lines if l.strip() and not l.startswith('#')][:15])
    
    payload = json.dumps({
        'token': 'c51ba39f1d304c80aa494f15b080030a',
        'title': f'🕳️ ONESEC v3.0 · {repo}',
        'content': f'<pre>{summary[:800]}</pre>',
        'template': 'html'
    })
    subprocess.run(['curl', '-s', '-X', 'POST',
        'https://www.pushplus.plus/send',
        '-H', 'Content-Type: application/json',
        '-d', payload], capture_output=True)
    print('📱 已推送微信')

def main():
    print_banner()
    if len(sys.argv) < 2:
        print('用法: python onesec_service.py <GitHub仓库URL> [目标网站URL]')
        print('示例: python onesec_service.py https://github.com/xxx/repo')
        print('      python onesec_service.py https://github.com/xxx/repo https://app.com')
        sys.exit(1)
    
    repo_url = sys.argv[1]
    target_url = sys.argv[2] if len(sys.argv) > 2 else ''
    owner, repo = extract_repo_info(repo_url)
    
    target = os.path.join(BASE, '_scan_target')
    clone_repo(repo_url, target)
    
    # 把克隆的目录软链接到 pipeline 的目标位置
    pipe_target = os.path.join(os.path.dirname(PIPELINE), 'target_project')
    if os.path.exists(pipe_target):
        import shutil
        shutil.rmtree(pipe_target, ignore_errors=True)
    
    # 直接复制整个目录
    import shutil
    shutil.copytree(target, pipe_target)
    
    run_scan(pipe_target, target_url)
    
    report_file = collect_report(repo, target)
    push_wechat(repo, report_file)
    
    # 清理
    shutil.rmtree(target, ignore_errors=True)
    shutil.rmtree(pipe_target, ignore_errors=True)
    
    print(f'\n✅ 审计完成!')

if __name__ == '__main__':
    main()
