#!/usr/bin/env bash
# ============================================================================
# GitHub'a Push Script
# Projeyi GitHub'a yükler
# ============================================================================
set -euo pipefail

# ─── Renkler ────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${CYAN}${BOLD}"
echo "╔═══════════════════════════════════════╗"
echo "║     GitHub Push Kurulum Scripti       ║"
echo "╚═══════════════════════════════════════╝"
echo -e "${NC}"

# ─── Değişkenler ─────────────────────────────────────────────────────────────
GITHUB_USERNAME="${GITHUB_USERNAME:-}"
REPO_NAME="aws-security-audit"
VISIBILITY="public"  # public veya private

# ─── GitHub username al ──────────────────────────────────────────────────────
if [ -z "${GITHUB_USERNAME}" ]; then
  echo -e "${YELLOW}GitHub kullanıcı adınızı girin:${NC}"
  read -r GITHUB_USERNAME
fi

echo -e "${BLUE}[INFO]${NC} Kullanıcı: ${GITHUB_USERNAME}"
echo -e "${BLUE}[INFO]${NC} Repo: ${REPO_NAME}"

# ─── Git yapılandırması ───────────────────────────────────────────────────────
echo -e "\n${BLUE}[1/5]${NC} Git deposu başlatılıyor..."

if [ ! -d ".git" ]; then
  git init
  echo -e "${GREEN}[OK]${NC} Git deposu oluşturuldu"
else
  echo -e "${GREEN}[OK]${NC} Git deposu zaten var"
fi

# ─── Git kullanıcı bilgileri ─────────────────────────────────────────────────
git config user.name "${GITHUB_USERNAME}" 2>/dev/null || true
git config user.email "${GITHUB_USERNAME}@users.noreply.github.com" 2>/dev/null || true

# ─── Dosyaları ekle ──────────────────────────────────────────────────────────
echo -e "\n${BLUE}[2/5]${NC} Dosyalar ekleniyor..."
git add -A
git status --short
echo -e "${GREEN}[OK]${NC} Dosyalar eklendi"

# ─── İlk commit ─────────────────────────────────────────────────────────────
echo -e "\n${BLUE}[3/5]${NC} İlk commit oluşturuluyor..."
git commit -m "feat: AWS güvenlik denetim projesi başlangıç yapısı

- Terraform altyapı kodu (IAM, S3, EC2, networking)
- Prowler entegrasyonu ile 300+ güvenlik kontrolü
- Otomatik HTML/JSON/CSV rapor oluşturucu
- Slack ve SNS bildirim desteği
- GitHub Actions CI/CD pipeline
- CIS Benchmark, AWS FSBP uyumluluk kontrolleri"

echo -e "${GREEN}[OK]${NC} Commit oluşturuldu"

# ─── GitHub repo oluştur (gh CLI ile) ───────────────────────────────────────
echo -e "\n${BLUE}[4/5]${NC} GitHub reposu oluşturuluyor..."

if command -v gh &>/dev/null; then
  # GitHub CLI kullan
  gh repo create "${REPO_NAME}" \
    --${VISIBILITY} \
    --description "🔒 AWS ortam güvenlik denetimi — Terraform + Prowler ile otomatik misconfiguration tespiti" \
    --push \
    --source . \
    && echo -e "${GREEN}[OK]${NC} GitHub reposu oluşturuldu ve push edildi" \
    || echo -e "${YELLOW}[WARN]${NC} gh ile oluşturulamadı, manuel adımları izleyin"
else
  # Manuel adımlar
  echo -e "${YELLOW}[WARN]${NC} GitHub CLI (gh) bulunamadı."
  echo ""
  echo -e "${BOLD}Manuel adımlar:${NC}"
  echo ""
  echo "1. GitHub'da yeni repo oluşturun:"
  echo "   https://github.com/new"
  echo "   - İsim: ${REPO_NAME}"
  echo "   - Visibility: ${VISIBILITY^}"
  echo "   - README, .gitignore, license EKLEME (zaten var)"
  echo ""
  echo "2. Remote ekleyin ve push edin:"
  echo -e "   ${CYAN}git remote add origin https://github.com/${GITHUB_USERNAME}/${REPO_NAME}.git${NC}"
  echo -e "   ${CYAN}git branch -M main${NC}"
  echo -e "   ${CYAN}git push -u origin main${NC}"
fi

# ─── GitHub Secrets talimatları ──────────────────────────────────────────────
echo -e "\n${BLUE}[5/5]${NC} GitHub Secrets kurulumu..."
echo ""
echo -e "${BOLD}GitHub Actions için Secrets ekleyin:${NC}"
echo -e "Repo → Settings → Secrets and variables → Actions → New repository secret"
echo ""
printf "${CYAN}%-30s${NC} %s\n" "Secret Adı" "Açıklama"
printf "%-30s %s\n" "──────────────────────────────" "──────────────────────────────────────"
printf "${YELLOW}%-30s${NC} %s\n" "AWS_AUDIT_ROLE_ARN" "arn:aws:iam::ACCOUNT:role/prowler-role"
printf "${YELLOW}%-30s${NC} %s\n" "AWS_REGION" "eu-west-1"
printf "${YELLOW}%-30s${NC} %s\n" "AWS_ACCOUNT_ID" "123456789012"
printf "${YELLOW}%-30s${NC} %s\n" "AUDIT_REPORT_BUCKET" "S3 bucket adı (opsiyonel)"
printf "${YELLOW}%-30s${NC} %s\n" "SLACK_WEBHOOK_URL" "Slack webhook (opsiyonel)"

echo ""
echo -e "${BOLD}OIDC için AWS IAM Identity Provider:${NC}"
echo "1. AWS Console → IAM → Identity Providers → Add Provider"
echo "   - Provider type: OpenID Connect"
echo "   - Provider URL: https://token.actions.githubusercontent.com"
echo "   - Audience: sts.amazonaws.com"
echo ""
echo "2. IAM Role Trust Policy güncelle:"
echo '   "StringLike": {'
echo '     "token.actions.githubusercontent.com:sub":'
echo "       \"repo:${GITHUB_USERNAME}/${REPO_NAME}:*\""
echo '   }'

echo ""
echo -e "${GREEN}${BOLD}✅ Kurulum tamamlandı!${NC}"
echo ""
echo -e "🔗 Repo: ${CYAN}https://github.com/${GITHUB_USERNAME}/${REPO_NAME}${NC}"
echo -e "🔄 Actions: ${CYAN}https://github.com/${GITHUB_USERNAME}/${REPO_NAME}/actions${NC}"
