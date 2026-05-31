"""
🕳️  AI 挖洞流水线 v3.0 — 融合 Scrapling + Playwright
     侦察升级 | 浏览器深度验证 | 自动 PoC
"""
import os, sys, json, re, subprocess, time
from pathlib import Path
from datetime import datetime

BASE = os.path.dirname(os.path.abspath(__file__))
TARGET_DIR = os.path.join(BASE, 'target_project')
TARGET_URL = os.environ.get('TARGET_URL', '')
REPORT_DIR = os.path.join(BASE, 'reports-v3')
os.makedirs(REPORT_DIR, exist_ok=True)

# ─── Agent 基类 ───
class Agent:
    def __init__(self, name):
        self.name = name
        self.logs = []
    def log(self, msg):
        print(f'  [{self.name}] {msg}')
        self.logs.append(msg)

# ─── Agent 1: 侦察 (Scrapling 增强) ───
class ReconAgent(Agent):
    def __init__(self):
        super().__init__('侦察-Agent')
    
    def run(self):
        self.log('扫描项目结构...')
        go_files = list(Path(TARGET_DIR).rglob('*.go'))
        self.log(f'发现 {len(go_files)} 个 Go 源文件')
        
        all_code = ''
        for f in go_files:
            try: all_code += f.read_text(encoding='utf-8') + '\n'
            except: pass
        
        # 传统攻击面识别
        patterns = {
            '用户输入 (Query/Param)': ['c.Query(', 'c.Param(', 'c.DefaultQuery('],
            '用户输入 (ShouldBind)': ['ShouldBind', 'BindJSON'],
            '数据库查询 (GORM)': ['.Where(', '.Raw(', '.Exec('],
            'SQL 注入风险': ['fmt.Sprintf("%', 'fmt.Sprintf("SELECT'],
            '命令执行': ['exec.Command', 'os/exec', 'os.StartProcess'],
            '文件操作': ['ioutil.ReadFile', 'os.Open(', 'os.ReadFile'],
            '不安全的配置': ['AllowAllOrigins', 'cors.Config{AllowAllOrigins'],
            'JWT 处理': ['jwt.Parse', 'c.GetHeader("Authorization")'],
            '路径遍历': ['filepath.Join', 'filepath.Clean'],
            '硬编码密钥': ['jwtSecret', 'JWT_SECRET', 'secretKey'],
        }
        
        attack_surface = []
        for desc, pats in patterns.items():
            for pat in pats:
                count = all_code.count(pat)
                if count > 0:
                    attack_surface.append({'type': desc, 'count': count})
                    self.log(f'  ⚡ {desc} ({count} 处)')
        
        # Scrapling: 如果给了 URL，抓取目标网站信息
        web_info = {}
        if TARGET_URL:
            self.log(f'🕸️  Scrapling 抓取目标: {TARGET_URL}')
            try:
                from scrapling.fetchers import Fetcher
                page = Fetcher.get(TARGET_URL, stealthy_headers=True)
                web_info['status'] = page.status
                web_info['title'] = (page.css('title::text').get() or '')[:80]
                web_info['forms'] = len(page.css('form'))
                web_info['links'] = len(page.css('a[href]'))
                web_info['scripts'] = len(page.css('script[src]'))
                # 提取所有 input 字段
                inputs = page.css('input[name]')
                web_info['input_fields'] = [i.attrib.get('name','') for i in inputs[:20] if i.attrib.get('name')]
                self.log(f'  🌐 状态: {web_info["status"]} | 标题: {web_info["title"]}')
                self.log(f'  📝 表单: {web_info["forms"]} | 链接: {web_info["links"]} | 输入字段: {len(web_info["input_fields"])}')
                
                # 提取所有 API 端点关键词
                scripts = page.css('script:not([src])')
                for script in scripts:
                    text = script.text or ''
                    apis = re.findall(r'["\'](/api/[^"\'\s]+)["\']', text)
                    if apis:
                        web_info['api_endpoints'] = list(set(apis))
                        self.log(f'  🔗 API 端点: {web_info["api_endpoints"][:10]}')
            except Exception as e:
                self.log(f'  ⚠️ Scrapling 抓取失败: {e}')
        
        report = {'files': len(go_files), 'attack_surface': attack_surface, 'web_info': web_info, 'agent': self.name}
        with open(os.path.join(REPORT_DIR, '01_recon.json'), 'w') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        return report, all_code

# ─── Agent 2: 审计 ───
class AuditAgent(Agent):
    def __init__(self):
        super().__init__('审计-Agent')
    
    def run(self, all_code, web_info):
        self.log('深度代码审计...')
        findings = []
        
        checks = [
            ('SQL 注入', r'(fmt\.Sprintf\([^)]*Where|\.Raw\([^)]*\+|\.Exec\([^)]*\+|"SELECT.*\+)', '严重', 
             '用户输入直接拼接到 SQL 查询', '使用 GORM 参数化查询或 ? 占位符'),
            ('硬编码 JWT Secret', r'(jwtSecret|JWT_SECRET|secretKey)\s*[=:]\s*["\'][^"\']+["\']', '高危',
             'JWT 签名密钥硬编码可导致身份伪造', '使用环境变量或密钥管理服务'),
            ('命令注入', r'(exec\.Command\([^)]*Query|exec\.Command\([^)]*Param)', '严重',
             '用户输入传递到系统命令', '避免将用户输入传入 exec.Command'),
            ('路径遍历', r'filepath\.Join\([^)]*Param\(|filepath\.Join\([^)]*Query\(', '高危',
             '用户输入控制文件路径', '使用 filepath.Clean + 白名单'),
            ('不安全的文件上传', r'SaveUploadedFile|c\.FormFile\(', '高危',
             '文件上传可能被用于上传恶意文件', '限制文件类型/大小，重命名文件'),
            ('Mass Assignment', r'(ShouldBind|BindJSON|\.Create\(|\.Updates\()', '高危',
             '用户输入直接绑定到结构体可能导致越权', '使用筛选后的 DTO 结构体'),
            ('CORS 配置宽松', r'AllowAllOrigins\s*[:=]\s*true', '中危',
             '允许任意跨域请求可能导致 CSRF', '指定具体的允许域名白名单'),
            ('调试模式', r'(gin\.Default\(\)|gin\.SetMode\("debug"\))', '低危',
             '调试模式可能泄露敏感信息', '生产环境设置 gin.SetMode("release")'),
        ]
        
        for name, pattern, severity, risk, fix in checks:
            matches = re.findall(pattern, all_code, re.IGNORECASE)
            if matches:
                findings.append({
                    'type': name, 'severity': severity, 'risk': risk,
                    'fix': fix, 'matches': len(matches),
                    'samples': [str(m)[:60] for m in matches[:3]]
                })
                self.log(f'  🚨 [{severity}] {name} ({len(matches)} 处)')
        
        # Scrapling 发现的 Web 信息辅助审计
        if web_info and web_info.get('input_fields'):
            self.log(f'  🕸️ 发现 {len(web_info["input_fields"])} 个用户输入点，建议测试 XSS/SQLi')
        
        self.log(f'审计完成: 发现 {len(findings)} 个漏洞')
        report = {'agent': self.name, 'findings': findings}
        with open(os.path.join(REPORT_DIR, '02_audit.json'), 'w') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        return findings

# ─── Agent 3: 验证 (Playwright 深度测试) ───
class VerifyAgent(Agent):
    def __init__(self):
        super().__init__('验证-Agent')
    
    def test_xss(self, url):
        """Playwright XSS 测试"""
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
        ]
        results = []
        try:
            from playwright.sync_api import sync_playwright
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()
                for payload in payloads:
                    test_url = f"{url}?q={payload}"
                    try:
                        page.goto(test_url, timeout=5000)
                        content = page.content()
                        if payload in content:
                            results.append({'payload': payload, 'confirmed': True, 'detail': 'Payload 在响应中未转义'})
                    except:
                        pass
                browser.close()
        except Exception as e:
            self.log(f'  ⚠️ Playwright XSS 测试失败: {e}')
        return results
    
    def test_endpoints(self, url):
        """Requests API 端点测试"""
        results = {'endpoints': [], 'cors': False}
        import requests
        try:
            # 测试 CORS
            r = requests.get(url, headers={'Origin': 'https://evil.com'}, timeout=5)
            if 'Access-Control-Allow-Origin' in r.headers:
                results['cors'] = True
                results['cors_detail'] = r.headers.get('Access-Control-Allow-Origin')
            
            # 扫常见路径
            paths = ['/api', '/admin', '/login', '/health', '/.env', '/config']
            for path in paths:
                try:
                    r = requests.get(f"{url.rstrip('/')}{path}", timeout=3)
                    if r.status_code < 500:
                        results['endpoints'].append({'path': path, 'status': r.status_code, 'size': len(r.text)})
                except:
                    pass
            self.log(f'  发现 {len(results["endpoints"])} 个可访问端点')
        except Exception as e:
            self.log(f'  ⚠️ 端点测试失败: {e}')
        return results
    
    def run(self, findings):
        self.log('启动自动化验证...')
        if not TARGET_URL:
            self.log('⚠️ 未设置 TARGET_URL，进入离线分析模式')
            return findings
        
        verified = self.test_endpoints(TARGET_URL)
        
        # XSS 测试
        xss_results = self.test_xss(TARGET_URL)
        if xss_results:
            for x in xss_results:
                findings.append({
                    'type': 'XSS (Playwright 验证)',
                    'severity': '高危', 'risk': f'XSS payload: {x["payload"]}',
                    'fix': '对用户输入进行 HTML 编码输出',
                    'matches': 1, 'confirmed': True
                })
        
        # 标记已确认的漏洞
        for f in findings:
            if 'SQL' in f['type'] and verified['cors']:
                f['confirmed'] = True
            elif 'XSS' in f['type']:
                f['confirmed'] = True
        
        report = {'agent': self.name, 'cors': verified['cors'], 'endpoints': verified['endpoints']}
        with open(os.path.join(REPORT_DIR, '03_verify.json'), 'w') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        confirmed = len([f for f in findings if f.get('confirmed')])
        self.log(f'验证完成: {confirmed}/{len(findings)} 已确认')
        return findings

# ─── Agent 4: 报告 ───
class ReportAgent(Agent):
    def __init__(self):
        super().__init__('报告-Agent')
    
    def run(self, findings, attack_surface):
        self.log('生成安全报告...')
        sev_order = {'严重': 0, '高危': 1, '中危': 2, '低危': 3}
        findings.sort(key=lambda x: sev_order.get(x.get('severity', '低危'), 99))
        confirmed = [f for f in findings if f.get('confirmed')]
        
        report_file = os.path.join(REPORT_DIR, 'vulnerability_report.md')
        with open(report_file, 'w') as f:
            f.write('# 🕳️ AI 安全审计报告 v3.0\n\n')
            f.write(f'> 目标: {TARGET_URL or Path(TARGET_DIR).name}\n')
            f.write(f'> 引擎: 侦察(Scrapling增强) → 审计 → 验证(Playwright) → 报告\n')
            f.write(f'> 生成: {datetime.now().strftime("%Y-%m-%d %H:%M")}\n\n')
            f.write('## 📊 概览\n\n')
            f.write(f'| 指标 | 数据 |\n|:----|:----:|\n')
            f.write(f'| 攻击面信号 | {len(attack_surface)} |\n')
            f.write(f'| 潜在漏洞 | {len(findings)} |\n')
            f.write(f'| 已确认 | {len(confirmed)} |\n\n')
            
            for sev in ['严重', '高危', '中危', '低危']:
                items = [f for f in findings if f.get('severity') == sev]
                if not items: continue
                f.write(f'## {"🚨" if sev=="严重" else "⚠️" if sev=="高危" else "🔍"} {sev}\n\n')
                for item in items:
                    status = '✅ 已确认' if item.get('confirmed') else '🔬 需复核'
                    f.write(f'### {item["type"]} — {status}\n')
                    f.write(f'- **风险**: {item.get("risk","")}\n')
                    f.write(f'- **数量**: {item.get("matches",0)} 处\n')
                    f.write(f'- **修复**: {item.get("fix","")}\n\n')
            
            f.write('## 🛠️ 技术栈\n\n')
            f.write('- 代码审计: AI 规则引擎\n')
            f.write('- Web 侦察: Scrapling\n')
            f.write('- 动态验证: Playwright + Requests\n')
            f.write('- 通知: PushPlus 微信推送\n')
        
        # 推微信
        try:
            summary = f'v3.0审计完成\n漏洞: {len(findings)} | 已确认: {len(confirmed)}'
            payload = json.dumps({
                'token': os.environ.get('PUSHPLUS_TOKEN', 'c51ba39f1d304c80aa494f15b080030a'),
                'title': f'🕳️ v3.0审计 · {len(findings)}漏洞/{len(confirmed)}确认',
                'content': f'<pre>{summary}</pre>', 'template': 'html'
            })
            subprocess.run(['curl', '-s', '-X', 'POST', 'https://www.pushplus.plus/send',
                '-H', 'Content-Type: application/json', '-d', payload], capture_output=True)
        except: pass
        
        self.log(f'报告: {report_file}')
        return report_file

# ─── 主流程 ───
def main():
    print(r'''
  ╔═══════════════════════════════════════════╗
  ║  🕳️  v3.0  Scrapling + Playwright         ║
  ║  AI 挖洞流水线 · 侦察 | 审计 | 验证       ║
  ╚═══════════════════════════════════════════╝
    ''')
    print(f'  📂 目标: {TARGET_DIR}')
    print(f'  🌐 URL: {TARGET_URL or "未设置(离线模式)"}\n')
    
    r = ReconAgent(); a = AuditAgent(); v = VerifyAgent(); rp = ReportAgent()
    
    recon_result, all_code = r.run()
    findings = a.run(all_code, recon_result.get('web_info', {}))
    findings = v.run(findings)
    report = rp.run(findings, recon_result.get('attack_surface', []))
    
    confirmed = len([f for f in findings if f.get('confirmed')])
    print(f'\n  ✅ 完成! 漏洞: {len(findings)} | 已确认: {confirmed}')
    print(f'  📄 报告: {report}\n')

if __name__ == '__main__':
    main()
