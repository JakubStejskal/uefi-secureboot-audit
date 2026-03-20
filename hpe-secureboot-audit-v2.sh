#!/usr/bin/env bash
# ==============================================================================
# hpe-secureboot-audit-v2.sh
#
# Audits HPE Secure Boot UEFI CA 2023 certificates across server fleet.
# Discovers iLO IPs via OneView, authenticates via SSO or manual credentials,
# checks db/KEK certificate enrollment on each server, and optionally resets
# Secure Boot keys to factory defaults if the 2023 CA cert is missing.
#
# Supports:
#   OneView  : 9.x / 10.x / 11.x  (API version auto-detected)
#   iLO gen  : iLO 5 (Gen10/Gen10+) / iLO 6 (Gen11) / iLO 7 (Gen12)
#   Auth     : OneView SSO  (recommended – requires iLO↔OV trust)
#              Manual creds (iLO local / directory account)
#
# Dependencies: curl, jq
#
# Usage:
#   ./hpe-secureboot-audit-v2.sh --ov-host <OV_IP> [OPTIONS]
#
# Options:
#   --ov-host   <IP|hostname>   OneView IP / hostname (required unless --servers)
#   --auth      sso|manual      iLO auth mode (default: sso)
#   --ilo-user  <user>          iLO username  (manual mode; prompted if omitted)
#   --ilo-pass  <pass>          iLO password  (manual mode; prompted if omitted)
#   --reset                     POST ResetAllKeysToDefault where 2023 cert missing
#   --dry-run                   Show reset candidates but do NOT perform reset
#   --servers   <file>          Skip OneView discovery; use file with iLO IPs
#                               (one per line, optionally "name|ip" format)
#   --filter-name <pattern>     Filter server names by pattern (grep -i)
#   --output    <file>          CSV report path (default: secureboot_audit_<ts>.csv)
#   --verbose                   Extra debug output
#   --help                      Show this help
#
# Examples:
#   # Full fleet via OneView, SSO, report only
#   ./hpe-secureboot-audit-v2.sh --ov-host ov.lab.local
#
#   # Manual iLO credentials, auto-reset missing 2023 certs
#   ./hpe-secureboot-audit-v2.sh --ov-host ov.lab.local --auth manual \
#       --ilo-user Administrator --reset
#
#   # Skip OneView, use static list of iLO IPs
#   ./hpe-secureboot-audit-v2.sh --servers ilo_list.txt --auth manual
#
# Notes:
#   iLO 5 SSO: SSOToken from OneView is used directly as X-Auth-Token.
#              LoginToken session POST is NOT supported on iLO 5.
#   iLO 6/7 SSO: LoginToken session POST supported; falls back to direct SSOToken.
# ==============================================================================

set -euo pipefail

# ── Colours ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log()    { echo -e "${CYAN}[*]${NC} $*"; }
ok()     { echo -e "${GREEN}[✓]${NC} $*"; }
warn()   { echo -e "${YELLOW}[!]${NC} $*"; }
err()    { echo -e "${RED}[✗]${NC} $*" >&2; }
dbg()    { [[ "$VERBOSE" == "true" ]] && echo -e "    ${NC}(dbg) $*${NC}" || true; }
banner() { echo -e "\n${BOLD}${CYAN}══ $* ══${NC}"; }

# ── Defaults ───────────────────────────────────────────────────────────────────
OV_HOST=""
OV_TOKEN=""
OV_API_VER=3000
AUTH_MODE="sso"
ILO_USER=""
ILO_PASS=""
RESET=false
DRY_RUN=false
SERVERS_FILE=""
FILTER_NAME=""
VERBOSE=false
REPORT_FILE="secureboot_audit_$(date +%Y%m%d_%H%M%S).csv"

# ── Cert patterns ──────────────────────────────────────────────────────────────
CERT_2023_PATTERN="Microsoft Corporation UEFI CA 2023"
CERT_2023_REGEX="(?i)microsoft.*(uefi|ca).*2023"

# ── Argument parsing ───────────────────────────────────────────────────────────
usage() {
  grep '^#' "$0" | grep -v '^#!/' | sed 's/^# \?//'
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ov-host)     OV_HOST="$2";      shift 2 ;;
    --auth)        AUTH_MODE="$2";    shift 2 ;;
    --ilo-user)    ILO_USER="$2";     shift 2 ;;
    --ilo-pass)    ILO_PASS="$2";     shift 2 ;;
    --reset)       RESET=true;        shift   ;;
    --dry-run)     DRY_RUN=true;      shift   ;;
    --servers)     SERVERS_FILE="$2"; shift 2 ;;
    --filter-name) FILTER_NAME="$2";  shift 2 ;;
    --output)      REPORT_FILE="$2";  shift 2 ;;
    --verbose)     VERBOSE=true;      shift   ;;
    --help|-h)     usage ;;
    *) err "Unknown option: $1"; exit 1 ;;
  esac
done

if [[ -z "$OV_HOST" && -z "$SERVERS_FILE" ]]; then
  err "Either --ov-host or --servers is required."
  echo "Use --help for usage."
  exit 1
fi

# ── Prereq check ───────────────────────────────────────────────────────────────
for cmd in curl jq; do
  command -v "$cmd" &>/dev/null || { err "Required tool not found: $cmd"; exit 1; }
done

# ── curl helpers ───────────────────────────────────────────────────────────────

ilo_get() {
  local url="$1" token="$2"
  curl -s -k -X GET "$url" \
    -H "X-Auth-Token: $token" \
    -H "Content-Type: application/json" \
    -H "OData-Version: 4.0"
}

ilo_get_safe() {
  local url="$1" token="$2"
  local http_code body
  body=$(curl -s -k -X GET "$url" \
    -H "X-Auth-Token: $token" \
    -H "Content-Type: application/json" \
    -H "OData-Version: 4.0" \
    -w '\n__HTTP_CODE__%{http_code}')
  http_code=$(echo "$body" | grep -o '__HTTP_CODE__[0-9]*' | grep -o '[0-9]*')
  body=$(echo "$body" | sed 's/__HTTP_CODE__[0-9]*$//')
  if [[ "$http_code" == "404" || "$http_code" == "400" ]]; then
    echo "null"
  else
    echo "$body"
  fi
}

ilo_post() {
  local url="$1" token="$2" body="$3"
  curl -s -k -X POST "$url" \
    -H "X-Auth-Token: $token" \
    -H "Content-Type: application/json" \
    -H "OData-Version: 4.0" \
    -d "$body"
}

# ==============================================================================
# ── OneView section ────────────────────────────────────────────────────────────
# ==============================================================================

ov_get() {
  local path="$1"
  curl -s -k -X GET "https://${OV_HOST}${path}" \
    -H "X-Auth-Token: $OV_TOKEN" \
    -H "X-API-Version: $OV_API_VER" \
    -H "Content-Type: application/json"
}

detect_ov_api_version() {
  local ver_response max_ver
  ver_response=$(curl -s -k "https://${OV_HOST}/rest/version")
  max_ver=$(echo "$ver_response" | jq -r '.currentVersion // 3000')

  if   [[ "$max_ver" -ge 4200 ]]; then OV_API_VER=4200  # OV 11.x
  elif [[ "$max_ver" -ge 3800 ]]; then OV_API_VER=3800  # OV 10.x
  elif [[ "$max_ver" -ge 3000 ]]; then OV_API_VER=3000  # OV 9.x
  else                                 OV_API_VER=3000
  fi

  log "OneView detected API version: ${max_ver} → using ${OV_API_VER}"
}

login_oneview() {
  local ov_user ov_pass

  echo ""
  read -rp "  OneView username: " ov_user
  read -rsp "  OneView password: " ov_pass
  echo ""

  local response
  response=$(curl -s -k -X POST "https://${OV_HOST}/rest/login-sessions" \
    -H "Content-Type: application/json" \
    -H "X-API-Version: ${OV_API_VER}" \
    -d "{\"userName\":\"${ov_user}\",\"password\":\"${ov_pass}\"}")

  OV_TOKEN=$(echo "$response" | jq -r '.sessionID // empty')

  if [[ -z "$OV_TOKEN" ]]; then
    err "OneView login failed."
    dbg "Response: $response"
    exit 1
  fi
  ok "OneView session established."
}

logout_oneview() {
  [[ -z "$OV_TOKEN" ]] && return
  curl -s -k -X DELETE "https://${OV_HOST}/rest/login-sessions" \
    -H "X-Auth-Token: $OV_TOKEN" \
    -H "X-API-Version: $OV_API_VER" > /dev/null 2>&1 || true
  dbg "OneView session closed."
}

get_servers_from_oneview() {
  local response count
  response=$(ov_get "/rest/server-hardware?count=500&sort=name:asc")
  count=$(echo "$response" | jq '.count // 0')
  log "Found ${count} server(s) in OneView."

  local filter_expr='.'
  if [[ -n "$FILTER_NAME" ]]; then
    log "Applying name filter: $FILTER_NAME"
  fi

  echo "$response" | jq -r '
    .members[]
    | select(.mpHostInfo.mpIpAddresses != null)
    | . as $srv
    | (.mpHostInfo.mpIpAddresses[] | select(.type != "LinkLocal") | .address) as $ip
    | [$srv.name, $ip, ($srv.uri | split("/") | last)]
    | join("|")
  ' | sort -u -t'|' -k1,1 | \
  { [[ -n "$FILTER_NAME" ]] && grep -i "$FILTER_NAME" || cat; }
}

# Get iLO SSO token via OneView.
# iLO 5: SSOToken is used directly as X-Auth-Token (LoginToken POST not supported).
# iLO 6/7: LoginToken session POST attempted first; direct SSOToken as fallback.
get_ilo_sso_token() {
  local server_uuid="$1" ilo_ip="$2"

  local sso_response sso_url sso_token
  sso_response=$(ov_get "/rest/server-hardware/${server_uuid}/iloSsoUrl")
  sso_url=$(echo "$sso_response" | jq -r '.iloSsoUrl // empty')

  if [[ -z "$sso_url" ]]; then
    dbg "OneView returned no iloSsoUrl for $ilo_ip"
    echo ""
    return 1
  fi

  # Extract SSOToken from URL query string
  sso_token=$(echo "$sso_url" | grep -oP 'SSOToken=\K[^&]+' 2>/dev/null || \
              echo "$sso_url" | sed -n 's/.*SSOToken=\([^&]*\).*/\1/p')

  if [[ -z "$sso_token" ]]; then
    dbg "Could not extract SSOToken from SSO URL"
    echo ""
    return 1
  fi

  dbg "SSOToken obtained for $ilo_ip (len: ${#sso_token})"

  # Try LoginToken session POST (iLO 6/7 only)
  local ilo_fw
  ilo_fw=$(curl -s -k "https://${ilo_ip}/redfish/v1/Managers/1" \
    -H "X-Auth-Token: $sso_token" -H "OData-Version: 4.0" 2>/dev/null | \
    jq -r '.FirmwareVersion // ""')

  if echo "$ilo_fw" | grep -qiv "iLO 5"; then
    # iLO 6/7: attempt proper Redfish session via LoginToken
    local session_headers redfish_token
    session_headers=$(mktemp)
    curl -s -k -X POST "https://${ilo_ip}/redfish/v1/SessionService/Sessions" \
      -H "Content-Type: application/json" \
      -H "OData-Version: 4.0" \
      -D "$session_headers" \
      -d "{\"UserName\":\"\",\"Password\":\"\",\"LoginToken\":\"${sso_token}\"}" \
      > /dev/null 2>&1 || true
    redfish_token=$(grep -i "^X-Auth-Token:" "$session_headers" | \
                    awk '{print $2}' | tr -d '\r\n' || true)
    rm -f "$session_headers"
    if [[ -n "$redfish_token" ]]; then
      dbg "LoginToken session created for $ilo_ip (iLO 6/7)"
      echo "$redfish_token"
      return 0
    fi
    dbg "LoginToken POST failed for $ilo_ip — falling back to direct SSOToken"
  else
    dbg "iLO 5 detected — using SSOToken directly as X-Auth-Token"
  fi

  # iLO 5 (and iLO 6/7 fallback): SSOToken used directly as X-Auth-Token
  echo "$sso_token"
}

# ==============================================================================
# ── iLO section ────────────────────────────────────────────────────────────────
# ==============================================================================

create_ilo_session_manual() {
  local ilo_ip="$1" user="$2" pass="$3"
  local headers
  headers=$(mktemp)

  curl -s -k -X POST "https://${ilo_ip}/redfish/v1/SessionService/Sessions" \
    -H "Content-Type: application/json" \
    -H "OData-Version: 4.0" \
    -D "$headers" \
    -d "{\"UserName\":\"${user}\",\"Password\":\"${pass}\"}" \
    > /dev/null 2>&1 || true

  local token
  token=$(grep -i "^X-Auth-Token:" "$headers" | awk '{print $2}' | tr -d '\r\n' || true)
  rm -f "$headers"
  echo "$token"
}

detect_ilo_gen() {
  local ilo_ip="$1" token="$2"
  local fw
  fw=$(curl -s -k "https://${ilo_ip}/redfish/v1/Managers/1" \
    -H "X-Auth-Token: $token" \
    -H "OData-Version: 4.0" 2>/dev/null | \
    jq -r '.FirmwareVersion // ""')

  dbg "iLO FW: $fw"

  if   echo "$fw" | grep -qi "iLO 7"; then echo "iLO7"
  elif echo "$fw" | grep -qi "iLO 6"; then echo "iLO6"
  elif echo "$fw" | grep -qi "iLO 5"; then echo "iLO5"
  else echo "Unknown"
  fi
}

resolve_cert_subject() {
  local cert_json="$1"
  local subj
  subj=$(echo "$cert_json" | jq -r '
    .Subject.CommonName //
    .Subject.DisplayString //
    .Subject.Organization //
    .Subject //
    ""
  ' 2>/dev/null | grep -v "^null$" | head -1)

  if [[ -z "$subj" || "$subj" == "null" ]]; then
    subj=$(echo "$cert_json" | jq -r '.SubjectAltName // .Issuer.CommonName // ""' 2>/dev/null)
  fi

  echo "$subj"
}

get_db_cert_subjects() {
  local ilo_ip="$1" token="$2" db_url="$3"

  local db certs_link certs_response
  db=$(ilo_get_safe "$db_url" "$token")

  if [[ "$db" == "null" ]]; then
    echo ""
    return
  fi

  certs_link=$(echo "$db" | jq -r '.Certificates["@odata.id"] // empty')

  if [[ -z "$certs_link" ]]; then
    echo ""
    return
  fi

  local full_certs_url="https://${ilo_ip}${certs_link}"
  dbg "Certs URL: ${full_certs_url}"

  # Try $expand (iLO 6/7)
  certs_response=$(curl -s -k -X GET "${full_certs_url}?\$expand=." \
    -H "X-Auth-Token: $token" \
    -H "Content-Type: application/json" 2>/dev/null)

  local member_count
  member_count=$(echo "$certs_response" | jq '.Members | length // 0')
  dbg "Cert members in ${db_url##*/}: $member_count"

  if [[ "$member_count" -eq 0 ]]; then
    # $expand not supported (iLO 5) — iterate members
    local member_links
    member_links=$(ilo_get_safe "$full_certs_url" "$token" | jq -r '.Members[]."@odata.id" // empty')

    local subjects=()
    while IFS= read -r link; do
      [[ -z "$link" ]] && continue
      local cert_json
      cert_json=$(ilo_get_safe "https://${ilo_ip}${link}" "$token")
      local subj
      subj=$(resolve_cert_subject "$cert_json")
      [[ -n "$subj" && "$subj" != "null" ]] && subjects+=("$subj")
    done <<< "$member_links"

    printf '%s\n' "${subjects[@]}"
    return
  fi

  echo "$certs_response" | jq -r '
    .Members[] |
    (.Subject.CommonName //
     .Subject.DisplayString //
     .Subject.Organization //
     .Subject //
     "") | select(. != "" and . != null)
  '
}

get_secureboot_db_members() {
  local ilo_ip="$1" token="$2" system_path="$3"

  local sb_obj
  sb_obj=$(ilo_get_safe "https://${ilo_ip}${system_path}/SecureBoot" "$token")

  local db_col_link
  db_col_link=$(echo "$sb_obj" | jq -r '.SecureBootDatabases["@odata.id"] // empty')

  if [[ -z "$db_col_link" ]]; then
    db_col_link="${system_path}/SecureBoot/SecureBootDatabases"
  fi

  local db_col
  db_col=$(ilo_get_safe "https://${ilo_ip}${db_col_link}" "$token")

  if [[ "$db_col" == "null" ]]; then
    echo ""
    return
  fi

  echo "$db_col" | jq -r '.Members[]."@odata.id" // empty'
}

reset_secureboot_keys() {
  local ilo_ip="$1" token="$2" system_path="$3"
  local action_url="https://${ilo_ip}${system_path}/SecureBoot/Actions/SecureBoot.ResetKeys"

  if [[ "$DRY_RUN" == "true" ]]; then
    warn "  [DRY-RUN] Would POST ResetAllKeysToDefault → $action_url"
    return
  fi

  local response http_code
  response=$(curl -s -k -X POST "$action_url" \
    -H "X-Auth-Token: $token" \
    -H "Content-Type: application/json" \
    -H "OData-Version: 4.0" \
    -w '\n__HTTP_CODE__%{http_code}' \
    -d '{"ResetKeysType":"ResetAllKeysToDefault"}')

  http_code=$(echo "$response" | grep -o '__HTTP_CODE__[0-9]*' | grep -o '[0-9]*')

  if [[ "$http_code" =~ ^2 ]]; then
    ok "  Keys reset to default. A cold reboot is required to apply."
  else
    err "  Reset failed (HTTP $http_code): $(echo "$response" | sed 's/__HTTP_CODE__[0-9]*//')"
  fi
}

# ==============================================================================
# ── Per-server audit logic ─────────────────────────────────────────────────────
# ==============================================================================

audit_server() {
  local server_name="$1" ilo_ip="$2" server_uuid="${3:-}"

  banner "$server_name ($ilo_ip)"

  local token="" ilo_gen="" auth_source=""

  # ── Authenticate ─────────────────────────────────────────────────────────────
  if [[ "$AUTH_MODE" == "sso" && -n "$server_uuid" && -n "$OV_HOST" ]]; then
    log "Attempting OneView SSO for $ilo_ip..."
    token=$(get_ilo_sso_token "$server_uuid" "$ilo_ip" 2>/dev/null || true)
    if [[ -n "$token" ]]; then
      auth_source="SSO"
      ok "SSO token obtained."
    else
      warn "SSO failed — falling back to manual credentials."
    fi
  fi

  if [[ -z "$token" ]]; then
    if [[ -z "$ILO_USER" ]]; then
      read -rp "  iLO username for ${ilo_ip}: " ILO_USER
    fi
    if [[ -z "$ILO_PASS" ]]; then
      read -rsp "  iLO password for ${ilo_ip}: " ILO_PASS
      echo ""
    fi

    token=$(create_ilo_session_manual "$ilo_ip" "$ILO_USER" "$ILO_PASS")
    auth_source="Manual"

    if [[ -z "$token" ]]; then
      err "Cannot authenticate to $ilo_ip — skipping."
      write_csv_row "$server_name" "$ilo_ip" "N/A" "AUTH_FAILED" "" "" "" "" "" "Authentication failed"
      return
    fi
    ok "Manual session established."
  fi

  # ── iLO generation ────────────────────────────────────────────────────────────
  ilo_gen=$(detect_ilo_gen "$ilo_ip" "$token")
  log "iLO generation: $ilo_gen"

  # ── Find Systems path ─────────────────────────────────────────────────────────
  local system_path
  system_path=$(curl -s -k "https://${ilo_ip}/redfish/v1/Systems" \
    -H "X-Auth-Token: $token" 2>/dev/null | \
    jq -r '.Members[0]."@odata.id" // "/redfish/v1/Systems/1"')
  dbg "System path: $system_path"

  # ── SecureBoot status ─────────────────────────────────────────────────────────
  local sb_obj sb_enabled sb_mode
  sb_obj=$(ilo_get_safe "https://${ilo_ip}${system_path}/SecureBoot" "$token")

  if [[ "$sb_obj" == "null" ]]; then
    err "SecureBoot endpoint unavailable on $ilo_ip"
    write_csv_row "$server_name" "$ilo_ip" "$ilo_gen" "SB_UNAVAILABLE" "" "" "" "" "" "SecureBoot endpoint missing"
    return
  fi

  sb_enabled=$(echo "$sb_obj" | jq -r '.SecureBootEnable // "unknown"')
  sb_mode=$(echo   "$sb_obj" | jq -r '.SecureBootMode    // "unknown"')
  log "Secure Boot: enabled=$sb_enabled  mode=$sb_mode"

  # ── SecureBootDatabases availability ──────────────────────────────────────────
  local db_members db_available="false"
  mapfile -t db_members < <(get_secureboot_db_members "$ilo_ip" "$token" "$system_path")

  if [[ ${#db_members[@]} -gt 0 && -n "${db_members[0]}" ]]; then
    db_available="true"
    dbg "DB members: ${db_members[*]}"
  else
    warn "SecureBootDatabases not available (iLO 5 with older ROM — update BIOS first)."
  fi

  # ── Cert extraction ───────────────────────────────────────────────────────────
  local db_subjects=() kek_subjects=()
  local db_has_2023="N/A" kek_has_2023="N/A"

  if [[ "$db_available" == "true" ]]; then
    # FIX: correct path extraction (was corrupted in v1)
    local db_path kek_path
    db_path=$(printf '%s\n'  "${db_members[@]}" | grep -i '/db'  | head -1)
    kek_path=$(printf '%s\n' "${db_members[@]}" | grep -i '/kek' | head -1)

    dbg "db path:  ${db_path:-none}"
    dbg "kek path: ${kek_path:-none}"

    if [[ -n "$db_path" ]]; then
      mapfile -t db_subjects < <(get_db_cert_subjects "$ilo_ip" "$token" "https://${ilo_ip}${db_path}")
      log "db certs (${#db_subjects[@]}):"
      for s in "${db_subjects[@]}"; do echo "    $s"; done
    fi

    if [[ -n "$kek_path" ]]; then
      mapfile -t kek_subjects < <(get_db_cert_subjects "$ilo_ip" "$token" "https://${ilo_ip}${kek_path}")
      log "KEK certs (${#kek_subjects[@]}):"
      for s in "${kek_subjects[@]}"; do echo "    $s"; done
    fi

    db_has_2023="false"
    kek_has_2023="false"

    for s in "${db_subjects[@]}";  do
      if echo "$s" | grep -qiP "$CERT_2023_REGEX"; then db_has_2023="true"; fi
    done
    for s in "${kek_subjects[@]}"; do
      if echo "$s" | grep -qiP "$CERT_2023_REGEX"; then kek_has_2023="true"; fi
    done

    if [[ "$db_has_2023" == "true" ]]; then
      ok "db  → ${CERT_2023_PATTERN} ✓ PRESENT"
    else
      warn "db  → ${CERT_2023_PATTERN} ✗ MISSING"
    fi

    if [[ "$kek_has_2023" == "true" ]]; then
      ok "KEK → ${CERT_2023_PATTERN} ✓ PRESENT"
    else
      warn "KEK → ${CERT_2023_PATTERN} ✗ MISSING"
    fi

    if [[ "$RESET" == "true" && ("$db_has_2023" == "false" || "$kek_has_2023" == "false") ]]; then
      warn "Triggering ResetAllKeysToDefault on $ilo_ip..."
      reset_secureboot_keys "$ilo_ip" "$token" "$system_path"
    fi
  fi

  local db_joined kek_joined
  db_joined=$(IFS=';'; echo "${db_subjects[*]}")
  kek_joined=$(IFS=';'; echo "${kek_subjects[*]}")

  write_csv_row \
    "$server_name" "$ilo_ip" "$ilo_gen" "$auth_source" \
    "$sb_enabled" "$sb_mode" \
    "$db_has_2023" "$kek_has_2023" \
    "$db_joined" "$kek_joined" ""
}

# ==============================================================================
# ── CSV reporting ──────────────────────────────────────────────────────────────
# ==============================================================================

init_csv() {
  echo "ServerName,iLO_IP,iLO_Generation,AuthSource,SecureBootEnabled,SecureBootMode,\
db_Has2023Cert,KEK_Has2023Cert,db_Subjects,KEK_Subjects,Error" > "$REPORT_FILE"
}

write_csv_row() {
  local name="$1" ip="$2" gen="$3" auth="$4" sb_en="$5" sb_mode="$6" \
        db23="$7" kek23="$8" db_subj="${9:-}" kek_subj="${10:-}" error="${11:-}"
  printf '"%s","%s","%s","%s","%s","%s","%s","%s","%s","%s","%s"\n' \
    "$name" "$ip" "$gen" "$auth" "$sb_en" "$sb_mode" \
    "$db23" "$kek23" \
    "$(echo "$db_subj"  | tr '"' "'")" \
    "$(echo "$kek_subj" | tr '"' "'")" \
    "$(echo "$error"    | tr '"' "'")" >> "$REPORT_FILE"
}

# ==============================================================================
# ── Main ───────────────────────────────────────────────────────────────────────
# ==============================================================================

main() {
  echo ""
  echo -e "${BOLD}${CYAN}HPE Secure Boot UEFI CA 2023 Audit v2${NC}"
  echo -e "${CYAN}OneView + iLO 5/6/7 | $(date)${NC}"
  echo ""

  init_csv

  if [[ "$AUTH_MODE" == "manual" ]]; then
    if [[ -z "$ILO_USER" ]]; then read -rp "iLO username (for all hosts): " ILO_USER; fi
    if [[ -z "$ILO_PASS" ]]; then read -rsp "iLO password: " ILO_PASS; echo ""; fi
  fi

  declare -a SERVER_LINES=()

  if [[ -n "$SERVERS_FILE" ]]; then
    log "Loading servers from file: $SERVERS_FILE"
    while IFS= read -r line || [[ -n "$line" ]]; do
      [[ -z "$line" || "$line" =~ ^# ]] && continue
      if [[ "$line" == *"|"* ]]; then
        SERVER_LINES+=("$line")
      else
        SERVER_LINES+=("${line}|${line}")
      fi
    done < "$SERVERS_FILE"
    log "Loaded ${#SERVER_LINES[@]} server(s)."

  else
    banner "OneView Discovery"
    detect_ov_api_version
    login_oneview
    trap 'logout_oneview' EXIT

    log "Fetching server inventory..."
    while IFS= read -r line || [[ -n "$line" ]]; do
      [[ -z "$line" ]] && continue
      SERVER_LINES+=("$line")
    done < <(get_servers_from_oneview)
    log "Discovered ${#SERVER_LINES[@]} server(s)."
  fi

  if [[ ${#SERVER_LINES[@]} -eq 0 ]]; then
    err "No servers found. Exiting."
    exit 1
  fi

  banner "Starting Audit  (${#SERVER_LINES[@]} servers)"

  for line in "${SERVER_LINES[@]}"; do
    IFS='|' read -r srv_name ilo_ip srv_uuid <<< "$line"
    srv_uuid="${srv_uuid:-}"
    audit_server "$srv_name" "$ilo_ip" "$srv_uuid" || true
    echo ""
  done

  banner "Summary"

  local total missing_db missing_kek
  total=$(tail -n +2 "$REPORT_FILE" | wc -l)
  missing_db=$(tail  -n +2 "$REPORT_FILE" | awk -F',' '{print $7}' | grep -c '"false"' || true)
  missing_kek=$(tail -n +2 "$REPORT_FILE" | awk -F',' '{print $8}' | grep -c '"false"' || true)

  echo -e "  Total servers audited  : ${BOLD}$total${NC}"
  echo -e "  Missing 2023 cert (db) : ${RED}${BOLD}$missing_db${NC}"
  echo -e "  Missing 2023 cert (KEK): ${RED}${BOLD}$missing_kek${NC}"
  echo ""

  if [[ "$RESET" == "true" && "$DRY_RUN" == "false" ]]; then
    warn "ResetAllKeysToDefault was applied where certs were missing."
    warn "Cold reboot of affected servers is required to complete key enrollment."
  elif [[ "$DRY_RUN" == "true" ]]; then
    warn "Dry-run mode — no resets were performed."
  fi

  ok "Report saved: ${BOLD}$REPORT_FILE${NC}"
}

main "$@"
