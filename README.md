# 🕳️ ONESEC · AI 代码审计

**一人安全团队 · 一键扫描你的 GitHub 项目**

把仓库链接发过来，AI 自动审计代码漏洞，5 分钟出报告。

## 用法

### 方式一：GitHub Actions（推荐）

1. 打开 → https://github.com/lcclicheng/onesec/actions
2. 点 **ONESEC 自动审计** → **Run workflow**
3. 输入你的仓库链接 → 点绿色按钮
4. 等几分钟 → 下载报告

### 方式二：本地运行

```bash
git clone https://github.com/lcclicheng/onesec.git
cd onesec
pip install requests
python onesec_service.py https://github.com/用户名/仓库名
```

## 定价

| 级别 | 价格 | 内容 |
|:----|:----:|:-----|
| 免费试扫 | $0 | GitHub Actions 自助扫描 |
| 标准审计 | $500 | 全量审计 + 修复建议 + 人工复核 |
| 深度审计 | $2000 | 含 PoC 验证 + 持续监控 |

## 技术栈

- 审计引擎: Python + AI 模式匹配
- CI/CD: GitHub Actions
- 通知: PushPlus 微信推送
- 目标: Go / 通用 Web 项目

---

> 联系方式: l15250432278@163.com
