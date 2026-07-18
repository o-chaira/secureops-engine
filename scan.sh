#!/usr/bin/env bash
# SecureOps Native Scanner. 

set -uo pipefail

readonly DOCKERFILE="Dockerfile"
readonly MAX_FILE_SIZE=$((5 * 1024 * 1024)) # 5MB limit to prevent DoS attacks

findings=0
errors=0

sanitize_field() {
  # Strip newlines, carriage returns, pipes, and dangerous ANSI/escape characters
  # This prevents Log Injection and Terminal Emulator Exploits (CVE-related mitigations)
  local value="${1:-}"
  value="${value//$'\n'/ }"
  value="${value//$'\r'/ }"
  value="${value//|/\/}"
  # Safely strip non-printable characters (excluding spaces)
  value=$(printf '%s' "$value" | tr -cd '\11\12\15\40-\176')
  printf '%s' "$value"
}

emit_finding() {
  local rule=$1 severity=$2 subject=$3 message=$4
  printf 'FINDING|%s|%s|%s|%s\n' \
    "$(sanitize_field "$rule")" \
    "$(sanitize_field "$severity")" \
    "$(sanitize_field "$subject")" \
    "$(sanitize_field "$message")"
  findings=$((findings + 1))
}

emit_status() {
  printf 'STATUS|%s|%s\n' "$(sanitize_field "$1")" "$(sanitize_field "$2")"
}

file_mode() {
  # GNU coreutils (Linux) first, then BSD/macOS stat. 
  # Use '--' to prevent command injection via files starting with '-'
  stat -c '%a' -- "$1" 2>/dev/null || stat -f '%Lp' -- "$1" 2>/dev/null
}

check_file_safe() {
  local target_file="$1"
  if [[ ! -f "$target_file" ]]; then
    return 1
  fi
  
  local size
  size=$(wc -c < "$target_file")
  if (( size > MAX_FILE_SIZE )); then
    emit_status "file_too_large" "Skipping $target_file (exceeds 5MB DoS limit)"
    errors=$((errors + 1))
    return 1
  fi
  return 0
}

scan_dockerfile() {
  if ! check_file_safe "$DOCKERFILE"; then
    emit_status dockerfile absent_or_unsafe
    return
  fi

  emit_status dockerfile present

  # 1. Hadolint External Scanner
  if command -v hadolint >/dev/null 2>&1; then
    local hadolint_output
    if hadolint_output=$(hadolint "$DOCKERFILE" 2>&1); then
      emit_status hadolint clean
    else
      local line
      while IFS= read -r line || [[ -n "$line" ]]; do
        [[ -z "$line" ]] && continue
        emit_finding dockerfile.hadolint MEDIUM "$DOCKERFILE" "$line"
      done <<< "$hadolint_output"
    fi
  else
    emit_status hadolint unavailable
  fi

  # 2. Native Awk Heuristics (Fallback & Enhanced)
  # Extracts User, tags, and insecure commands safely.
  local awk_results
  awk_results=$(awk '
    BEGIN { IGNORECASE = 1 }
    /^[[:space:]]*FROM[[:space:]]+.*:latest\b/ { print "LATEST_TAG|" $0 }
    /^[[:space:]]*ADD[[:space:]]+/ { print "ADD_CMD|" $0 }
    /^[[:space:]]*USER[[:space:]]+/ {
      line = $0
      sub(/^[[:space:]]*[Uu][Ss][Ee][Rr][[:space:]]+/, "", line)
      sub(/[[:space:]]+#.*/, "", line)
      user = line
      print "USER_CMD|" user
    }
  ' "$DOCKERFILE")

  local final_user=""
  while IFS='|' read -r type data || [[ -n "$type" ]]; do
    case "$type" in
      "LATEST_TAG")
        emit_finding dockerfile.latest-tag MEDIUM "$DOCKERFILE" "Avoid using ':latest' tag for predictable builds. Line: $data"
        ;;
      "ADD_CMD")
        emit_finding dockerfile.use-copy LOW "$DOCKERFILE" "Use COPY instead of ADD to prevent remote URL fetching/tar bomb risks. Line: $data"
        ;;
      "USER_CMD")
        final_user="$data"
        ;;
    esac
  done <<< "$awk_results"

  if [[ -z "$final_user" ]]; then
    emit_finding dockerfile.root-user HIGH "$DOCKERFILE" "No USER instruction found; the image will run as root by default."
  elif [[ "$final_user" =~ ^(root|0)(:|$) ]]; then
    emit_finding dockerfile.root-user HIGH "$DOCKERFILE" "Final USER instruction runs the image as root: $final_user"
  else
    emit_status dockerfile.user "non-root ($final_user)"
  fi
}

scan_sensitive_file_permissions() {
  local sec_file mode
  
  # Hunts for .env, .pem, .key, and SSH keys. 
  # -print0 ensures files with spaces or newlines in names don't break the loop.
  while IFS= read -r -d '' sec_file; do
    if ! check_file_safe "$sec_file"; then continue; fi

    if ! mode=$(file_mode "$sec_file"); then
      emit_finding env.permissions MEDIUM "$sec_file" "Unable to determine file permissions."
      errors=$((errors + 1))
      continue
    fi

    if [[ "$mode" != "600" && "$mode" != "400" ]]; then
      emit_finding secrets.permissions HIGH "$sec_file" "Permissions are $mode; secret-bearing files MUST be 600 or 400."
    else
      emit_status secrets.permissions "$sec_file is adequately protected ($mode)"
    fi
  done < <(find . -type f \( -name '.env' -o -name '*.pem' -o -name '*.key' -o -name 'id_rsa*' -o -name 'id_ed25519*' \) -print0 2>/dev/null)
}

scan_shell_scripts() {
  # Integrates ShellCheck if available on the system
  if command -v shellcheck >/dev/null 2>&1; then
    local sh_file
    while IFS= read -r -d '' sh_file; do
      if ! check_file_safe "$sh_file"; then continue; fi
      
      if ! shellcheck -f gcc "$sh_file" >/dev/null 2>&1; then
         emit_finding bash.shellcheck MEDIUM "$sh_file" "ShellCheck detected potential bash vulnerabilities. Manual review recommended."
      fi
    done < <(find . -type f -name '*.sh' -print0 2>/dev/null)
  fi
}

main() {
  printf 'SECUREOPS_SCAN|1\n'
  emit_status scanner started

  scan_dockerfile
  scan_sensitive_file_permissions
  scan_shell_scripts

  printf 'SUMMARY|findings=%d|errors=%d\n' "$findings" "$errors"
}

main "$@"
