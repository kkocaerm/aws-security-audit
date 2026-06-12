# 🔒 AWS Security Audit — Terraform + Prowler

Otomatik AWS ortam güvenlik denetimi yapan, misconfiguration'ları tespit eden ve raporlayan tam kapsamlı güvenlik aracı.

## 📋 İçindekiler

- [Özellikler](#-özellikler)
- [Mimari](#-mimari)
- [Gereksinimler](#-gereksinimler)
- [Kurulum](#-kurulum)
- [Kullanım](#-kullanım)
- [Raporlar](#-raporlar)
- [CI/CD](#-cicd)
- [Katkıda Bulunma](#-katkıda-bulunma)

## ✨ Özellikler

- 🏗️ **Terraform** ile AWS kaynaklarını otomatik deploy
- 🔍 **Prowler** ile 300+ güvenlik kontrolü
- 📊 HTML/JSON/CSV formatında detaylı raporlar
- 🚨 Kritik bulgular için Slack/SNS bildirimleri
- 🔄 GitHub Actions ile otomatik CI/CD pipeline
- 📈 Tarihsel trend analizi
- 🏷️ CIS Benchmark, PCI-DSS, GDPR uyumluluk kontrolleri

## 🏛️ Mimari

```
aws-security-audit/
├── terraform/                  # AWS altyapı kodu
│   ├── modules/
│   │   ├── iam/               # IAM roller ve politikaları
│   │   ├── s3/                # Rapor depolama bucket
│   │   ├── ec2/               # Audit EC2 instance
│   │   └── networking/        # VPC, subnet yapılandırması
│   └── environments/
│       ├── dev/
│       ├── staging/
│       └── prod/
├── prowler/                   # Prowler yapılandırması
│   ├── checks/                # Özel güvenlik kontrolleri
│   └── reports/               # Oluşturulan raporlar
├── scripts/                   # Otomasyon scriptleri
│   ├── run_audit.sh           # Ana denetim scripti
│   ├── generate_report.py     # Rapor oluşturucu
│   ├── notify.py              # Bildirim gönderici
│   └── trend_analysis.py      # Trend analizi
└── .github/workflows/         # CI/CD pipeline
```

## 📦 Gereksinimler

| Araç | Versiyon |
|------|----------|
| Terraform | >= 1.5.0 |
| Python | >= 3.10 |
| Prowler | >= 3.0.0 |
| AWS CLI | >= 2.0 |

## 🚀 Kurulum

### 1. Repoyu klonla

```bash
git clone https://github.com/YOUR_USERNAME/aws-security-audit.git
cd aws-security-audit
```

### 2. Bağımlılıkları yükle

```bash
pip install -r requirements.txt
prowler --version  # Prowler kurulu değilse: pip install prowler
```

### 3. AWS kimlik bilgilerini yapılandır

```bash
aws configure
# veya environment variables:
export AWS_ACCESS_KEY_ID="your-key"
export AWS_SECRET_ACCESS_KEY="your-secret"
export AWS_DEFAULT_REGION="eu-west-1"
```

### 4. Terraform altyapısını kur

```bash
cd terraform/environments/dev
terraform init
terraform plan
terraform apply
```

### 5. Denetimi çalıştır

```bash
chmod +x scripts/run_audit.sh
./scripts/run_audit.sh --env dev --output html,json,csv
```

## 📖 Kullanım

### Temel kullanım

```bash
# Tüm kontrolleri çalıştır
./scripts/run_audit.sh

# Belirli servisler için
./scripts/run_audit.sh --services s3,iam,ec2

# Belirli uyumluluk framework
./scripts/run_audit.sh --compliance cis_aws_foundations_benchmark_v1.4

# Ciddiyet filtresi
./scripts/run_audit.sh --severity critical,high

# Birden fazla hesap
./scripts/run_audit.sh --accounts 123456789,987654321
```

### Rapor oluşturma

```bash
# HTML raporu oluştur
python scripts/generate_report.py --input prowler/reports/latest.json --format html

# Trend analizi
python scripts/trend_analysis.py --days 30
```

### Bildirimler

```bash
# Slack bildirimi
export SLACK_WEBHOOK_URL="https://hooks.slack.com/..."
python scripts/notify.py --channel security-alerts

# AWS SNS
python scripts/notify.py --sns-topic arn:aws:sns:eu-west-1:123:security-alerts
```

## 📊 Raporlar

Raporlar `prowler/reports/` klasörüne ve S3 bucket'ına kaydedilir.

### Örnek bulgular

| Servis | Kontrol | Önem | Durum |
|--------|---------|------|-------|
| S3 | Public bucket erişimi | CRITICAL | ❌ FAIL |
| IAM | Root MFA aktif değil | HIGH | ❌ FAIL |
| EC2 | Güvenlik grubu 0.0.0.0/0 | HIGH | ❌ FAIL |
| CloudTrail | Log şifreleme | MEDIUM | ✅ PASS |

## 🔄 CI/CD

GitHub Actions pipeline otomatik olarak:

1. Her `push` ve `pull_request`'te tetiklenir
2. Terraform `validate` ve `plan` çalıştırır
3. Haftalık tam güvenlik denetimi yapar
4. Kritik bulgularda PR'a yorum ekler
5. Raporları artifact olarak saklar

## 🤝 Katkıda Bulunma

1. Fork et
2. Feature branch oluştur (`git checkout -b feature/yeni-kontrol`)
3. Değişiklikleri commit et (`git commit -m 'feat: yeni IAM kontrolü eklendi'`)
4. Branch'i push et (`git push origin feature/yeni-kontrol`)
5. Pull Request aç

## 📄 Lisans

MIT License — detaylar için [LICENSE](LICENSE) dosyasına bakın.
