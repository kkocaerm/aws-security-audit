#!/usr/bin/env python3
"""
AWS Güvenlik Denetimi - Bildirim Gönderici
Güvenlik bulgularını Slack ve AWS SNS üzerinden bildirir.
"""

import argparse
import json
import os
import sys
import urllib.request
import urllib.error
from datetime import datetime


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Güvenlik denetim bildirimleri gönder")
    parser.add_argument("--summary", help="Özet metin dosyası")
    parser.add_argument("--critical", type=int, default=0, help="Kritik bulgu sayısı")
    parser.add_argument("--high", type=int, default=0, help="Yüksek bulgu sayısı")
    parser.add_argument("--total-fail", type=int, default=0, help="Toplam FAIL sayısı")
    parser.add_argument("--environment", default="dev", help="Ortam adı")
    parser.add_argument("--account", default="", help="AWS hesap ID")
    parser.add_argument("--slack-webhook", help="Slack webhook URL")
    parser.add_argument("--sns-topic", help="SNS topic ARN")
    parser.add_argument("--s3-report-url", help="S3'teki rapor URL")
    return parser.parse_args()


def get_severity_level(critical: int, high: int) -> tuple[str, str]:
    """Önem seviyesi ve emoji döndür."""
    if critical > 0:
        return "🚨 KRİTİK", "#dc2626"
    elif high > 5:
        return "⚠️  YÜKSEK", "#ea580c"
    elif high > 0:
        return "⚡ DİKKAT", "#d97706"
    else:
        return "✅ TEMİZ", "#16a34a"


def send_slack_notification(
    webhook_url: str,
    critical: int,
    high: int,
    total_fail: int,
    environment: str,
    account: str,
    s3_url: str = "",
) -> bool:
    """Slack'e bildirim gönder."""
    level_label, color = get_severity_level(critical, high)
    date_str = datetime.now().strftime("%d.%m.%Y %H:%M")

    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{level_label} — AWS Güvenlik Denetimi Tamamlandı"
            }
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*🌍 Ortam:*\n{environment.upper()}"},
                {"type": "mrkdwn", "text": f"*🏦 Hesap:*\n{account}"},
                {"type": "mrkdwn", "text": f"*📅 Tarih:*\n{date_str}"},
                {"type": "mrkdwn", "text": f"*❌ Toplam FAIL:*\n{total_fail}"},
            ]
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"*Bulgu Özeti:*\n"
                    f"🔴 *Kritik:* {critical}\n"
                    f"🟠 *Yüksek:* {high}\n"
                )
            }
        }
    ]

    if critical > 0:
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "⚠️ *Acil müdahale gerekiyor!* Kritik güvenlik açıkları tespit edildi."
            }
        })

    if s3_url:
        blocks.append({
            "type": "actions",
            "elements": [{
                "type": "button",
                "text": {"type": "plain_text", "text": "📊 Raporu Görüntüle"},
                "url": s3_url,
                "style": "primary"
            }]
        })

    payload = json.dumps({"blocks": blocks, "attachments": [{"color": color}]}).encode()

    try:
        req = urllib.request.Request(
            webhook_url,
            data=payload,
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status == 200:
                print("✅ Slack bildirimi gönderildi")
                return True
    except urllib.error.URLError as e:
        print(f"❌ Slack bildirimi gönderilemedi: {e}", file=sys.stderr)

    return False


def send_sns_notification(
    topic_arn: str,
    critical: int,
    high: int,
    total_fail: int,
    environment: str,
    account: str,
) -> bool:
    """AWS SNS üzerinden bildirim gönder."""
    try:
        import boto3  # type: ignore
        level_label, _ = get_severity_level(critical, high)
        date_str = datetime.now().strftime("%d.%m.%Y %H:%M")

        subject = f"[{level_label}] AWS Güvenlik Denetimi — {environment.upper()}"
        message = f"""AWS Güvenlik Denetimi Raporu
============================
Ortam   : {environment.upper()}
Hesap   : {account}
Tarih   : {date_str}

BULGULAR:
  Kritik  : {critical}
  Yüksek  : {high}
  Toplam FAIL : {total_fail}

{"⚠️  UYARI: Kritik güvenlik açıkları tespit edildi! Acil müdahale gerekiyor." if critical > 0 else "Denetim tamamlandı."}
"""

        client = boto3.client("sns")
        client.publish(
            TopicArn=topic_arn,
            Subject=subject,
            Message=message,
        )
        print("✅ SNS bildirimi gönderildi")
        return True

    except ImportError:
        print("❌ boto3 bulunamadı: pip install boto3", file=sys.stderr)
    except Exception as e:
        print(f"❌ SNS bildirimi gönderilemedi: {e}", file=sys.stderr)

    return False


def main() -> None:
    args = parse_args()

    print("\n📢 Bildirim Gönderici")
    print("=" * 30)
    print(f"  Kritik: {args.critical}, Yüksek: {args.high}, Toplam FAIL: {args.total_fail}")

    success = False

    # Slack
    slack_url = args.slack_webhook or os.environ.get("SLACK_WEBHOOK_URL", "")
    if slack_url:
        success |= send_slack_notification(
            webhook_url=slack_url,
            critical=args.critical,
            high=args.high,
            total_fail=args.total_fail,
            environment=args.environment,
            account=args.account,
            s3_url=args.s3_report_url or "",
        )

    # SNS
    sns_topic = args.sns_topic or os.environ.get("SNS_TOPIC_ARN", "")
    if sns_topic:
        success |= send_sns_notification(
            topic_arn=sns_topic,
            critical=args.critical,
            high=args.high,
            total_fail=args.total_fail,
            environment=args.environment,
            account=args.account,
        )

    if not slack_url and not sns_topic:
        print("⚠️  Bildirim hedefi belirtilmedi (--slack-webhook veya --sns-topic)")
        sys.exit(0)

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
