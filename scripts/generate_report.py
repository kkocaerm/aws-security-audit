#!/usr/bin/env python3
"""
AWS Güvenlik Denetimi - Gelişmiş Rapor Oluşturucu
Prowler JSON çıktısından interaktif HTML raporu oluşturur.
"""

import json
import argparse
import sys
from datetime import datetime
from pathlib import Path
from collections import defaultdict, Counter
from typing import Any


# ─── Argüman ayrıştırma ──────────────────────────────────────────────────────
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Prowler JSON raporundan HTML raporu oluştur"
    )
    parser.add_argument("--input", required=True, help="Prowler JSON rapor dosyası")
    parser.add_argument("--output", required=True, help="Çıktı HTML dosyası")
    parser.add_argument("--environment", default="dev", help="Ortam adı")
    parser.add_argument("--account", default="", help="AWS hesap ID")
    parser.add_argument(
        "--format", choices=["html", "json", "csv"], default="html", help="Çıktı formatı"
    )
    return parser.parse_args()


# ─── Veri işleme ─────────────────────────────────────────────────────────────
def load_findings(json_path: str) -> list[dict]:
    """Prowler JSON raporunu yükle."""
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        print(f"✅ {len(data)} bulgu yüklendi")
        return data
    except FileNotFoundError:
        print(f"❌ Dosya bulunamadı: {json_path}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"❌ JSON ayrıştırma hatası: {e}", file=sys.stderr)
        sys.exit(1)


def categorize_findings(findings: list[dict]) -> dict[str, Any]:
    """Bulguları kategorize et ve istatistik oluştur."""
    stats = {
        "total": len(findings),
        "by_status": Counter(),
        "by_severity": Counter(),
        "by_service": defaultdict(list),
        "critical_fails": [],
        "high_fails": [],
        "pass_count": 0,
        "fail_count": 0,
    }

    for finding in findings:
        status = finding.get("Status", "UNKNOWN")
        severity = finding.get("Severity", "unknown").lower()
        service = finding.get("ServiceName", "unknown")

        stats["by_status"][status] += 1
        stats["by_severity"][severity] += 1

        if status == "FAIL":
            stats["fail_count"] += 1
            stats["by_service"][service].append(finding)
            if severity == "critical":
                stats["critical_fails"].append(finding)
            elif severity == "high":
                stats["high_fails"].append(finding)
        elif status == "PASS":
            stats["pass_count"] += 1

    # En riskli servisler
    stats["top_risky_services"] = sorted(
        stats["by_service"].items(),
        key=lambda x: len(x[1]),
        reverse=True
    )[:10]

    return stats


def get_severity_color(severity: str) -> str:
    colors = {
        "critical": "#dc2626",
        "high": "#ea580c",
        "medium": "#d97706",
        "low": "#2563eb",
        "informational": "#6b7280",
    }
    return colors.get(severity.lower(), "#6b7280")


def get_severity_badge(severity: str) -> str:
    colors = {
        "critical": "bg-red-100 text-red-800",
        "high": "bg-orange-100 text-orange-800",
        "medium": "bg-yellow-100 text-yellow-800",
        "low": "bg-blue-100 text-blue-800",
    }
    css = colors.get(severity.lower(), "bg-gray-100 text-gray-800")
    return f'<span class="badge {css}">{severity.upper()}</span>'


# ─── HTML raporu ─────────────────────────────────────────────────────────────
def generate_html_report(
    findings: list[dict],
    stats: dict,
    environment: str,
    account: str,
    output_path: str,
) -> None:
    """Interaktif HTML güvenlik raporu oluştur."""

    report_date = datetime.now().strftime("%d %B %Y, %H:%M")
    pass_rate = (stats["pass_count"] / stats["total"] * 100) if stats["total"] > 0 else 0

    # Bulgular tablosu HTML
    findings_rows = ""
    for f in sorted(findings, key=lambda x: (
        {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(
            x.get("Severity", "low").lower(), 4
        )
    )):
        if f.get("Status") != "FAIL":
            continue

        severity = f.get("Severity", "unknown")
        service = f.get("ServiceName", "N/A")
        check = f.get("CheckTitle", "N/A")
        resource = f.get("ResourceArn", f.get("ResourceId", "N/A"))
        region = f.get("Region", "N/A")
        remediation = (
            f.get("Remediation", {}).get("Recommendation", {}).get("Text", "N/A")
        )
        remediation_url = (
            f.get("Remediation", {}).get("Recommendation", {}).get("Url", "")
        )

        resource_short = resource[-60:] if len(resource) > 60 else resource

        findings_rows += f"""
        <tr class="finding-row" data-severity="{severity.lower()}" data-service="{service.lower()}">
          <td>{get_severity_badge(severity)}</td>
          <td><span class="service-badge">{service}</span></td>
          <td class="check-title">{check}</td>
          <td><code class="resource">{resource_short}</code></td>
          <td class="region">{region}</td>
          <td class="remediation">
            {remediation}
            {f'<a href="{remediation_url}" target="_blank" class="doc-link">📖 Dok</a>' if remediation_url else ''}
          </td>
        </tr>"""

    # En riskli servisler grafik
    service_bars = ""
    max_count = max((len(v) for _, v in stats["top_risky_services"]), default=1)
    for svc, svc_findings in stats["top_risky_services"][:8]:
        count = len(svc_findings)
        width = int(count / max_count * 100)
        service_bars += f"""
        <div class="service-bar-row">
          <span class="service-name">{svc}</span>
          <div class="bar-container">
            <div class="bar" style="width:{width}%">{count}</div>
          </div>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="tr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AWS Güvenlik Denetimi — {environment.upper()}</title>
  <style>
    :root {{
      --red: #dc2626; --orange: #ea580c; --yellow: #d97706;
      --blue: #2563eb; --green: #16a34a; --gray: #6b7280;
      --bg: #0f172a; --surface: #1e293b; --border: #334155;
      --text: #e2e8f0; --text-muted: #94a3b8;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: 'Inter', system-ui, sans-serif; background: var(--bg); color: var(--text); line-height: 1.5; }}
    .container {{ max-width: 1400px; margin: 0 auto; padding: 0 1.5rem; }}

    /* Header */
    header {{ background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%); border-bottom: 1px solid var(--border); padding: 2rem 0; }}
    .header-content {{ display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 1rem; }}
    .header-title {{ display: flex; align-items: center; gap: 1rem; }}
    .header-title h1 {{ font-size: 1.75rem; font-weight: 700; color: #f1f5f9; }}
    .header-title .shield {{ font-size: 2.5rem; }}
    .header-meta {{ text-align: right; color: var(--text-muted); font-size: 0.875rem; }}
    .env-badge {{ display: inline-block; padding: 0.25rem 0.75rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; background: #1d4ed8; color: #bfdbfe; margin-bottom: 0.5rem; }}

    /* Score card */
    .score-section {{ padding: 2rem 0; }}
    .score-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; }}
    .score-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 1.5rem; text-align: center; transition: transform 0.2s; }}
    .score-card:hover {{ transform: translateY(-2px); }}
    .score-card.critical {{ border-color: var(--red); }}
    .score-card.high {{ border-color: var(--orange); }}
    .score-card.pass {{ border-color: var(--green); }}
    .score-number {{ font-size: 2.5rem; font-weight: 800; line-height: 1; }}
    .score-label {{ font-size: 0.8rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; margin-top: 0.5rem; }}
    .score-card.critical .score-number {{ color: var(--red); }}
    .score-card.high .score-number {{ color: var(--orange); }}
    .score-card.medium .score-number {{ color: var(--yellow); }}
    .score-card.pass .score-number {{ color: var(--green); }}

    /* Progress bar */
    .progress-section {{ background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 1.5rem; margin-bottom: 1.5rem; }}
    .progress-bar-outer {{ background: #334155; border-radius: 9999px; height: 12px; overflow: hidden; margin-top: 0.75rem; }}
    .progress-bar-inner {{ height: 100%; border-radius: 9999px; background: linear-gradient(90deg, var(--green), #4ade80); transition: width 1s ease; }}
    .progress-label {{ display: flex; justify-content: space-between; font-size: 0.875rem; color: var(--text-muted); }}

    /* Charts */
    .charts-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; margin-bottom: 1.5rem; }}
    @media (max-width: 768px) {{ .charts-grid {{ grid-template-columns: 1fr; }} }}
    .chart-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 1.5rem; }}
    .chart-card h3 {{ font-size: 1rem; font-weight: 600; margin-bottom: 1.25rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; font-size: 0.75rem; }}
    .service-bar-row {{ display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.75rem; }}
    .service-name {{ font-size: 0.8rem; min-width: 100px; color: var(--text-muted); }}
    .bar-container {{ flex: 1; background: #334155; border-radius: 4px; height: 20px; overflow: hidden; }}
    .bar {{ height: 100%; background: linear-gradient(90deg, #3b82f6, #6366f1); display: flex; align-items: center; justify-content: flex-end; padding-right: 8px; font-size: 0.7rem; font-weight: 700; min-width: 28px; transition: width 0.8s ease; }}

    /* Findings table */
    .findings-section {{ background: var(--surface); border: 1px solid var(--border); border-radius: 12px; overflow: hidden; margin-bottom: 2rem; }}
    .findings-header {{ padding: 1.5rem; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem; }}
    .findings-header h2 {{ font-size: 1.1rem; font-weight: 600; }}
    .filters {{ display: flex; gap: 0.5rem; flex-wrap: wrap; }}
    .filter-btn {{ padding: 0.35rem 0.75rem; border-radius: 6px; border: 1px solid var(--border); background: transparent; color: var(--text-muted); cursor: pointer; font-size: 0.8rem; transition: all 0.15s; }}
    .filter-btn:hover, .filter-btn.active {{ background: #3b82f6; border-color: #3b82f6; color: white; }}
    .search-box {{ padding: 0.35rem 0.75rem; border-radius: 6px; border: 1px solid var(--border); background: var(--bg); color: var(--text); font-size: 0.8rem; width: 200px; }}
    .search-box:focus {{ outline: none; border-color: #3b82f6; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
    th {{ padding: 0.75rem 1rem; text-align: left; font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); border-bottom: 1px solid var(--border); font-weight: 600; }}
    td {{ padding: 0.75rem 1rem; border-bottom: 1px solid #1e293b; vertical-align: top; }}
    tr:hover td {{ background: rgba(255,255,255,0.02); }}
    .badge {{ padding: 0.2rem 0.6rem; border-radius: 9999px; font-size: 0.7rem; font-weight: 700; white-space: nowrap; }}
    .bg-red-100 {{ background: rgba(220,38,38,0.15); }} .text-red-800 {{ color: #fca5a5; }}
    .bg-orange-100 {{ background: rgba(234,88,12,0.15); }} .text-orange-800 {{ color: #fdba74; }}
    .bg-yellow-100 {{ background: rgba(217,119,6,0.15); }} .text-yellow-800 {{ color: #fcd34d; }}
    .bg-blue-100 {{ background: rgba(37,99,235,0.15); }} .text-blue-800 {{ color: #93c5fd; }}
    .bg-gray-100 {{ background: rgba(107,114,128,0.15); }} .text-gray-800 {{ color: #d1d5db; }}
    .service-badge {{ background: rgba(99,102,241,0.15); color: #a5b4fc; padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.75rem; white-space: nowrap; }}
    code.resource {{ font-size: 0.75rem; color: #94a3b8; font-family: 'Courier New', monospace; }}
    .doc-link {{ color: #60a5fa; text-decoration: none; margin-left: 0.5rem; }}
    .doc-link:hover {{ text-decoration: underline; }}
    .finding-row.hidden {{ display: none; }}
    .no-results {{ text-align: center; padding: 3rem; color: var(--text-muted); }}

    footer {{ text-align: center; padding: 2rem; color: var(--text-muted); font-size: 0.8rem; border-top: 1px solid var(--border); }}
  </style>
</head>
<body>

<header>
  <div class="container">
    <div class="header-content">
      <div class="header-title">
        <span class="shield">🛡️</span>
        <div>
          <div><span class="env-badge">{environment}</span></div>
          <h1>AWS Güvenlik Denetimi</h1>
          <p style="color: var(--text-muted); font-size:0.9rem">Hesap: {account} · Prowler ile otomatik denetim</p>
        </div>
      </div>
      <div class="header-meta">
        <div>📅 {report_date}</div>
        <div>🔍 {stats['total']} kontrol çalıştırıldı</div>
      </div>
    </div>
  </div>
</header>

<main class="container" style="padding-top:1.5rem">

  <!-- Skor kartları -->
  <div class="score-section">
    <div class="score-grid">
      <div class="score-card critical">
        <div class="score-number">{stats['by_severity'].get('critical', 0)}</div>
        <div class="score-label">🔴 Kritik</div>
      </div>
      <div class="score-card high">
        <div class="score-number">{stats['by_severity'].get('high', 0)}</div>
        <div class="score-label">🟠 Yüksek</div>
      </div>
      <div class="score-card medium">
        <div class="score-number">{stats['by_severity'].get('medium', 0)}</div>
        <div class="score-label">🟡 Orta</div>
      </div>
      <div class="score-card">
        <div class="score-number" style="color:var(--blue)">{stats['by_severity'].get('low', 0)}</div>
        <div class="score-label">🔵 Düşük</div>
      </div>
      <div class="score-card pass">
        <div class="score-number">{stats['pass_count']}</div>
        <div class="score-label">✅ Başarılı</div>
      </div>
      <div class="score-card">
        <div class="score-number" style="color:var(--red)">{stats['fail_count']}</div>
        <div class="score-label">❌ Başarısız</div>
      </div>
    </div>
  </div>

  <!-- Uyumluluk skoru -->
  <div class="progress-section">
    <div class="progress-label">
      <span>Genel Uyumluluk Skoru</span>
      <span style="font-weight:700;color:{'#16a34a' if pass_rate >= 80 else '#d97706' if pass_rate >= 60 else '#dc2626'}">{pass_rate:.1f}%</span>
    </div>
    <div class="progress-bar-outer">
      <div class="progress-bar-inner" style="width:{pass_rate:.0f}%"></div>
    </div>
  </div>

  <!-- Grafikler -->
  <div class="charts-grid">
    <div class="chart-card">
      <h3>🔥 En Riskli Servisler</h3>
      {service_bars if service_bars else '<p style="color:var(--text-muted)">Başarısız bulgu yok</p>'}
    </div>
    <div class="chart-card">
      <h3>📊 Önem Seviyesi Dağılımı</h3>
      {"".join(f'''<div class="service-bar-row">
        <span class="service-name">{sev.title()}</span>
        <div class="bar-container"><div class="bar" style="width:{int(cnt/max(stats['fail_count'],1)*100)}%;background:{'linear-gradient(90deg,#dc2626,#ef4444)' if sev=='critical' else 'linear-gradient(90deg,#ea580c,#f97316)' if sev=='high' else 'linear-gradient(90deg,#d97706,#fbbf24)' if sev=='medium' else 'linear-gradient(90deg,#2563eb,#60a5fa)'}">{cnt}</div></div>
      </div>''' for sev, cnt in [("critical", stats['by_severity'].get('critical',0)), ("high", stats['by_severity'].get('high',0)), ("medium", stats['by_severity'].get('medium',0)), ("low", stats['by_severity'].get('low',0))])}
    </div>
  </div>

  <!-- Bulgular tablosu -->
  <div class="findings-section">
    <div class="findings-header">
      <h2>🔍 Güvenlik Bulguları ({stats['fail_count']} FAIL)</h2>
      <div class="filters">
        <input type="text" class="search-box" id="searchBox" placeholder="Ara..." oninput="filterFindings()">
        <button class="filter-btn active" onclick="filterBySeverity('all', this)">Tümü</button>
        <button class="filter-btn" onclick="filterBySeverity('critical', this)">Kritik</button>
        <button class="filter-btn" onclick="filterBySeverity('high', this)">Yüksek</button>
        <button class="filter-btn" onclick="filterBySeverity('medium', this)">Orta</button>
        <button class="filter-btn" onclick="filterBySeverity('low', this)">Düşük</button>
      </div>
    </div>
    <div style="overflow-x:auto">
      <table id="findingsTable">
        <thead>
          <tr>
            <th>Önem</th>
            <th>Servis</th>
            <th>Kontrol</th>
            <th>Kaynak</th>
            <th>Bölge</th>
            <th>Öneri</th>
          </tr>
        </thead>
        <tbody id="findingsBody">
          {findings_rows if findings_rows else '<tr><td colspan="6" class="no-results">✅ Bu kategoride başarısız bulgu yok!</td></tr>'}
        </tbody>
      </table>
    </div>
  </div>

</main>

<footer>
  <p>AWS Güvenlik Denetimi Raporu · {report_date} · Prowler tarafından oluşturuldu</p>
  <p style="margin-top:0.25rem">Bu rapor otomatik oluşturulmuştur. Bulguları manuel doğrulayınız.</p>
</footer>

<script>
  let currentSeverity = 'all';

  function filterBySeverity(severity, btn) {{
    currentSeverity = severity;
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    filterFindings();
  }}

  function filterFindings() {{
    const search = document.getElementById('searchBox').value.toLowerCase();
    const rows = document.querySelectorAll('.finding-row');
    let visible = 0;

    rows.forEach(row => {{
      const sev = row.dataset.severity;
      const text = row.textContent.toLowerCase();
      const matchesSev = currentSeverity === 'all' || sev === currentSeverity;
      const matchesSearch = !search || text.includes(search);

      if (matchesSev && matchesSearch) {{
        row.classList.remove('hidden');
        visible++;
      }} else {{
        row.classList.add('hidden');
      }}
    }});

    const noResults = document.querySelector('.no-results-msg');
    if (visible === 0 && rows.length > 0) {{
      if (!noResults) {{
        const tr = document.createElement('tr');
        tr.className = 'no-results-msg';
        tr.innerHTML = '<td colspan="6" class="no-results">🔍 Sonuç bulunamadı</td>';
        document.getElementById('findingsBody').appendChild(tr);
      }}
    }} else if (noResults) {{
      noResults.remove();
    }}
  }}

  // Animasyonlu progress bar
  window.addEventListener('load', () => {{
    const bar = document.querySelector('.progress-bar-inner');
    if (bar) {{ bar.style.width = bar.style.width; }}
  }});
</script>

</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"✅ HTML raporu oluşturuldu: {output_path}")
    file_size = Path(output_path).stat().st_size / 1024
    print(f"   Boyut: {file_size:.1f} KB")


# ─── Ana akış ────────────────────────────────────────────────────────────────
def main() -> None:
    args = parse_args()

    print("\n🔒 AWS Güvenlik Raporu Oluşturucu")
    print("=" * 40)

    findings = load_findings(args.input)
    stats = categorize_findings(findings)

    print(f"📊 İstatistikler:")
    print(f"   Toplam: {stats['total']}, Başarılı: {stats['pass_count']}, Başarısız: {stats['fail_count']}")
    print(f"   Kritik: {stats['by_severity'].get('critical', 0)}, Yüksek: {stats['by_severity'].get('high', 0)}")

    generate_html_report(
        findings=findings,
        stats=stats,
        environment=args.environment,
        account=args.account,
        output_path=args.output,
    )

    print("\n✅ Rapor oluşturma tamamlandı!")


if __name__ == "__main__":
    main()
