#!/usr/bin/env bash
# ============================================================================
# AWS Güvenlik Denetimi - Ana Script
# Prowler kullanarak AWS ortamını tarar, misconfiguration'ları bulur ve raporlar
# ============================================================================
set -euo pipefail

# ─── Renkler ────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# ─── Varsayılan değerler ────────────────────────────────────────────────────
ENVIRONMENT="dev"
AWS_REGION="${AWS_DEFAULT_REGION:-eu-west-1}"
OUTPUT_DIR="./prowler/reports"
OUTPUT_FORMATS="html,json,csv"
SERVICES=""
COMPLIANCE=""
SEVERITY="critical,high,medium"
ACCOUNTS=""
PARALLEL_JOBS=4
SEND_NOTIFICATION=false
SLACK_WEBHOOK="${SLACK_WEBHOOK_URL:-}"
SNS_TOPIC="${SNS_TOPIC_ARN:-}"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_PREFIX="security-audit-${TIMESTAMP}"
S3_BUCKET="${AUDIT_REPORT_BUCKET:-}"

# ─── Yardım metni ────────────────────────────────────────────────────────────
usage() {
  cat <<EOF
${BOLD}AWS Güvenlik Denetimi${NC}

Kullanım: $0 [SEÇENEKLER]

${BOLD}Seçenekler:${NC}
  -e, --env           Ortam (dev/staging/prod) [varsayılan: dev]
  -r, --region        AWS bölgesi [varsayılan: eu-west-1]
  -o, --output-dir    Rapor dizini [varsayılan: ./prowler/reports]
  -f, --formats       Çıktı formatları (html,json,csv) [varsayılan: html,json,csv]
  -s, --services      Virgülle ayrılmış servisler (boş = hepsi)
  -c, --compliance    Uyumluluk framework
  --severity          Önem seviyeleri [varsayılan: critical,high,medium]
  --accounts          Denetlenecek hesap ID'leri (virgülle)
  --notify            Bildirim gönder
  --s3-bucket         Raporları yüklenecek S3 bucket
  -h, --help          Bu yardım mesajını göster

${BOLD}Örnekler:${NC}
  # Tüm kontrolleri çalıştır
  $0

  # Yalnızca S3 ve IAM
  $0 --services s3,iam

  # CIS Benchmark uyumluluk kontrolü
  $0 --compliance cis_aws_foundations_benchmark_v1.4

  # Prod ortamı, bildirim ile
  $0 --env prod --notify --severity critical,high

  # Çoklu hesap
  $0 --accounts 123456789012,987654321098
EOF
  exit 0
}

# ─── Argüman ayrıştırma ───────────────────────────────────────────────────────
parse_args() {
  while [[ $# -gt 0 ]]; do
    case $1 in
      -e|--env)       ENVIRONMENT="$2"; shift 2 ;;
      -r|--region)    AWS_REGION="$2"; shift 2 ;;
      -o|--output-dir) OUTPUT_DIR="$2"; shift 2 ;;
      -f|--formats)   OUTPUT_FORMATS="$2"; shift 2 ;;
      -s|--services)  SERVICES="$2"; shift 2 ;;
      -c|--compliance) COMPLIANCE="$2"; shift 2 ;;
      --severity)     SEVERITY="$2"; shift 2 ;;
      --accounts)     ACCOUNTS="$2"; shift 2 ;;
      --notify)       SEND_NOTIFICATION=true; shift ;;
      --s3-bucket)    S3_BUCKET="$2"; shift 2 ;;
      -h|--help)      usage ;;
      *) echo -e "${RED}Bilinmeyen parametre: $1${NC}"; usage ;;
    esac
  done
}

# ─── Log fonksiyonları ────────────────────────────────────────────────────────
log_info()    { echo -e "${BLUE}[INFO]${NC}  $(date '+%H:%M:%S') $*"; }
log_success() { echo -e "${GREEN}[OK]${NC}    $(date '+%H:%M:%S') $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}  $(date '+%H:%M:%S') $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $(date '+%H:%M:%S') $*" >&2; }
log_section() { echo -e "\n${CYAN}${BOLD}══════════════════════════════════════${NC}"; echo -e "${CYAN}${BOLD}  $*${NC}"; echo -e "${CYAN}${BOLD}══════════════════════════════════════${NC}\n"; }

# ─── Bağımlılık kontrolü ─────────────────────────────────────────────────────
check_dependencies() {
  log_section "Bağımlılık Kontrolü"

  local deps=("prowler" "aws" "python3" "jq")
  local missing=()

  for dep in "${deps[@]}"; do
    if command -v "$dep" &>/dev/null; then
      log_success "$dep bulundu: $(command -v "$dep")"
    else
      missing+=("$dep")
      log_error "$dep bulunamadı!"
    fi
  done

  if [[ ${#missing[@]} -gt 0 ]]; then
    log_error "Eksik bağımlılıklar: ${missing[*]}"
    log_info "Kurulum: pip install prowler awscli && apt-get install jq"
    exit 1
  fi

  # Prowler versiyonu
  PROWLER_VERSION=$(prowler --version 2>&1 | grep -oP '\d+\.\d+\.\d+' | head -1)
  log_info "Prowler versiyonu: $PROWLER_VERSION"
}

# ─── AWS bağlantı kontrolü ──────────────────────────────────────────────────
check_aws_connection() {
  log_section "AWS Bağlantı Kontrolü"

  if ! aws sts get-caller-identity &>/dev/null; then
    log_error "AWS kimlik doğrulama başarısız!"
    log_info "AWS CLI yapılandırmasını kontrol edin: aws configure"
    exit 1
  fi

  ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
  ACCOUNT_ALIAS=$(aws iam list-account-aliases --query 'AccountAliases[0]' --output text 2>/dev/null || echo "N/A")
  CALLER_ARN=$(aws sts get-caller-identity --query Arn --output text)

  log_success "AWS Hesabı: ${ACCOUNT_ID} (${ACCOUNT_ALIAS})"
  log_info "Kullanıcı/Rol: ${CALLER_ARN}"
  log_info "Bölge: ${AWS_REGION}"
}

# ─── Rapor dizini oluştur ────────────────────────────────────────────────────
setup_output_dir() {
  mkdir -p "${OUTPUT_DIR}"
  log_info "Rapor dizini: ${OUTPUT_DIR}"
}

# ─── Prowler komutunu oluştur ────────────────────────────────────────────────
build_prowler_command() {
  local cmd="prowler aws"

  # Bölge
  cmd+=" --region ${AWS_REGION}"

  # Çıktı formatları
  IFS=',' read -ra FORMATS <<< "${OUTPUT_FORMATS}"
  for fmt in "${FORMATS[@]}"; do
    cmd+=" -M ${fmt}"
  done

  # Çıktı dizini
  cmd+=" -o ${OUTPUT_DIR} --output-filename ${REPORT_PREFIX}"

  # Belirli servisler
  if [[ -n "${SERVICES}" ]]; then
    IFS=',' read -ra SRVS <<< "${SERVICES}"
    cmd+=" --services ${SRVS[*]}"
  fi

  # Uyumluluk framework
  if [[ -n "${COMPLIANCE}" ]]; then
    cmd+=" --compliance ${COMPLIANCE}"
  fi

  # Önem seviyesi filtresi
  if [[ -n "${SEVERITY}" ]]; then
    IFS=',' read -ra SEVS <<< "${SEVERITY}"
    for sev in "${SEVS[@]}"; do
      cmd+=" --status FAIL"
    done
  fi

  # Çoklu hesap
  if [[ -n "${ACCOUNTS}" ]]; then
    cmd+=" --role arn:aws:iam::ACCOUNT_ID:role/prowler-security-audit-${ENVIRONMENT}"
  fi

  # Paralel işlem
  cmd+=" --jobs ${PARALLEL_JOBS}"

  echo "$cmd"
}

# ─── Prowler denetimini çalıştır ─────────────────────────────────────────────
run_prowler_audit() {
  log_section "Güvenlik Denetimi Başlatılıyor"

  local PROWLER_CMD
  PROWLER_CMD=$(build_prowler_command)

  log_info "Komut: ${PROWLER_CMD}"
  log_info "Bu işlem 10-30 dakika sürebilir..."

  local START_TIME
  START_TIME=$(date +%s)

  # Denetimi çalıştır
  if eval "${PROWLER_CMD}"; then
    local END_TIME
    END_TIME=$(date +%s)
    local DURATION=$(( END_TIME - START_TIME ))
    log_success "Denetim tamamlandı! Süre: ${DURATION} saniye"
  else
    local EXIT_CODE=$?
    # Prowler bazı bulgu durumlarında non-zero exit verir, bu normal
    if [[ $EXIT_CODE -eq 3 ]]; then
      log_warn "Denetim tamamlandı ancak FAIL durumunda bulgular var (exit code: 3)"
    else
      log_error "Denetim başarısız! Exit code: ${EXIT_CODE}"
      exit ${EXIT_CODE}
    fi
  fi
}

# ─── Özet rapor oluştur ──────────────────────────────────────────────────────
generate_summary() {
  log_section "Denetim Özeti"

  local JSON_REPORT="${OUTPUT_DIR}/${REPORT_PREFIX}.json"

  if [[ ! -f "${JSON_REPORT}" ]]; then
    log_warn "JSON raporu bulunamadı: ${JSON_REPORT}"
    return
  fi

  # jq ile özet çıkar
  local TOTAL CRITICAL HIGH MEDIUM LOW PASS FAIL
  TOTAL=$(jq '[.[] ] | length' "${JSON_REPORT}" 2>/dev/null || echo "0")
  CRITICAL=$(jq '[.[] | select(.Severity == "critical" and .Status == "FAIL")] | length' "${JSON_REPORT}" 2>/dev/null || echo "0")
  HIGH=$(jq '[.[] | select(.Severity == "high" and .Status == "FAIL")] | length' "${JSON_REPORT}" 2>/dev/null || echo "0")
  MEDIUM=$(jq '[.[] | select(.Severity == "medium" and .Status == "FAIL")] | length' "${JSON_REPORT}" 2>/dev/null || echo "0")
  LOW=$(jq '[.[] | select(.Severity == "low" and .Status == "FAIL")] | length' "${JSON_REPORT}" 2>/dev/null || echo "0")
  PASS=$(jq '[.[] | select(.Status == "PASS")] | length' "${JSON_REPORT}" 2>/dev/null || echo "0")
  FAIL=$(jq '[.[] | select(.Status == "FAIL")] | length' "${JSON_REPORT}" 2>/dev/null || echo "0")

  cat <<EOF
┌─────────────────────────────────────────┐
│         GÜVENLIK DENETİMİ ÖZETİ         │
├─────────────────────────────────────────┤
│ Hesap     : ${ACCOUNT_ID} (${ENVIRONMENT})
│ Bölge     : ${AWS_REGION}
│ Tarih     : $(date '+%Y-%m-%d %H:%M:%S')
├─────────────────────────────────────────┤
│ Toplam Kontrol  : ${TOTAL}
│ ✅ Başarılı     : ${PASS}
│ ❌ Başarısız    : ${FAIL}
├─────────────────────────────────────────┤
│ Bulgular (FAIL):
│  🔴 KRİTİK   : ${CRITICAL}
│  🟠 YÜKSEK   : ${HIGH}
│  🟡 ORTA     : ${MEDIUM}
│  🔵 DÜŞÜK    : ${LOW}
└─────────────────────────────────────────┘
EOF

  # Kritik bulgular listesi
  if [[ "${CRITICAL}" -gt 0 ]]; then
    echo -e "\n${RED}${BOLD}⚠️  KRİTİK BULGULAR:${NC}"
    jq -r '.[] | select(.Severity == "critical" and .Status == "FAIL") |
      "  [\(.ServiceName)] \(.CheckTitle)\n  Kaynak: \(.ResourceArn // "N/A")\n  Öneri: \(.Remediation.Recommendation.Text // "N/A")\n"' \
      "${JSON_REPORT}" 2>/dev/null | head -50
  fi

  # Rapor dosyaları
  echo -e "\n${GREEN}${BOLD}📄 Oluşturulan Raporlar:${NC}"
  ls -lh "${OUTPUT_DIR}/${REPORT_PREFIX}".* 2>/dev/null || true

  # Özet dosyaya yaz
  cat > "${OUTPUT_DIR}/summary_${TIMESTAMP}.txt" <<SUMMARY
AWS Güvenlik Denetimi Özeti
===========================
Hesap    : ${ACCOUNT_ID}
Ortam    : ${ENVIRONMENT}
Bölge    : ${AWS_REGION}
Tarih    : $(date '+%Y-%m-%d %H:%M:%S')

Toplam Kontrol : ${TOTAL}
Başarılı       : ${PASS}
Başarısız      : ${FAIL}

Bulgular (FAIL):
  KRİTİK : ${CRITICAL}
  YÜKSEK : ${HIGH}
  ORTA   : ${MEDIUM}
  DÜŞÜK  : ${LOW}
SUMMARY

  # Ortam değişkenlerine aktar (CI/CD için)
  export AUDIT_CRITICAL="${CRITICAL}"
  export AUDIT_HIGH="${HIGH}"
  export AUDIT_TOTAL_FAIL="${FAIL}"
}

# ─── S3'e yükle ──────────────────────────────────────────────────────────────
upload_to_s3() {
  if [[ -z "${S3_BUCKET}" ]]; then
    log_info "S3 bucket belirtilmedi, yükleme atlandı"
    return
  fi

  log_section "S3'e Rapor Yükleniyor"

  local S3_PREFIX="reports/${ENVIRONMENT}/${TIMESTAMP}/"

  aws s3 sync "${OUTPUT_DIR}/" "s3://${S3_BUCKET}/${S3_PREFIX}" \
    --include "${REPORT_PREFIX}*" \
    --sse aws:kms \
    --region "${AWS_REGION}"

  log_success "Raporlar S3'e yüklendi: s3://${S3_BUCKET}/${S3_PREFIX}"
}

# ─── Bildirim gönder ─────────────────────────────────────────────────────────
send_notifications() {
  if [[ "${SEND_NOTIFICATION}" != "true" ]]; then
    return
  fi

  log_section "Bildirimler Gönderiliyor"

  python3 scripts/notify.py \
    --summary "${OUTPUT_DIR}/summary_${TIMESTAMP}.txt" \
    --critical "${AUDIT_CRITICAL:-0}" \
    --high "${AUDIT_HIGH:-0}" \
    --total-fail "${AUDIT_TOTAL_FAIL:-0}" \
    --environment "${ENVIRONMENT}" \
    --account "${ACCOUNT_ID}" \
    ${SLACK_WEBHOOK:+--slack-webhook "${SLACK_WEBHOOK}"} \
    ${SNS_TOPIC:+--sns-topic "${SNS_TOPIC}"} \
    && log_success "Bildirimler gönderildi" \
    || log_warn "Bildirim gönderilemedi"
}

# ─── Rapor güncelle (Python ile) ─────────────────────────────────────────────
enhance_report() {
  local JSON_REPORT="${OUTPUT_DIR}/${REPORT_PREFIX}.json"

  if [[ -f "${JSON_REPORT}" ]] && command -v python3 &>/dev/null; then
    log_info "Gelişmiş HTML raporu oluşturuluyor..."
    python3 scripts/generate_report.py \
      --input "${JSON_REPORT}" \
      --output "${OUTPUT_DIR}/${REPORT_PREFIX}_enhanced.html" \
      --environment "${ENVIRONMENT}" \
      --account "${ACCOUNT_ID}" \
      && log_success "Gelişmiş rapor oluşturuldu" \
      || log_warn "Gelişmiş rapor oluşturulamadı"
  fi
}

# ─── Temizlik ─────────────────────────────────────────────────────────────────
cleanup() {
  log_info "Geçici dosyalar temizleniyor..."
  find "${OUTPUT_DIR}" -name "*.tmp" -delete 2>/dev/null || true
}

# ─── CI/CD çıkış kodu ────────────────────────────────────────────────────────
set_exit_code() {
  local CRITICAL="${AUDIT_CRITICAL:-0}"
  local HIGH="${AUDIT_HIGH:-0}"

  if [[ "${CRITICAL}" -gt 0 ]]; then
    log_error "KRİTİK bulgular var (${CRITICAL})! Pipeline durduruluyor."
    exit 2
  elif [[ "${HIGH}" -gt 5 ]]; then
    log_warn "Çok fazla YÜKSEK bulgu (${HIGH})! Dikkat edilmeli."
    exit 1
  else
    log_success "Güvenlik denetimi başarıyla tamamlandı."
    exit 0
  fi
}

# ─── Ana akış ────────────────────────────────────────────────────────────────
main() {
  parse_args "$@"

  echo -e "\n${CYAN}${BOLD}"
  echo "╔════════════════════════════════════════╗"
  echo "║     AWS GÜVENLİK DENETİMİ ARACI       ║"
  echo "║     Terraform + Prowler Integration    ║"
  echo "╚════════════════════════════════════════╝"
  echo -e "${NC}"

  check_dependencies
  check_aws_connection
  setup_output_dir
  run_prowler_audit
  generate_summary
  enhance_report
  upload_to_s3
  send_notifications
  cleanup
  set_exit_code
}

# ─── Trap ─────────────────────────────────────────────────────────────────────
trap 'log_error "Beklenmeyen hata! Satır: $LINENO"' ERR
trap 'cleanup; log_info "Script sonlandırıldı"' EXIT

main "$@"
