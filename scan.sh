#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# QubitAC - PQC Crypto-BOM Scanner
# https://qubitac.com
# =============================================================================

# Temp file registry for cleanup on exit
_TMPFILES=()
_register_tmp() { _TMPFILES+=("$@"); }
_cleanup_tmp() {
  [[ ${#_TMPFILES[@]} -eq 0 ]] && return 0
  local f
  for f in "${_TMPFILES[@]}"; do
    [[ -n "$f" ]] && rm -f "$f" 2>/dev/null || true
  done
}
trap _cleanup_tmp EXIT

# Configuration
SCAN_PORTS="${SCAN_PORTS:-443}"
SCAN_TIMEOUT="${SCAN_TIMEOUT:-10}"
VERBOSE="${VERBOSE:-0}"
# Resolve to absolute path so scripts are found correctly when run as "bash scan.sh"
SCRIPT_DIR="${SCRIPT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"

# SSH port list (ports that should be scanned with ssh-audit, not httpx/TLS)
SSH_PORT_LIST="22,2222,2200,22222,8022,222,3022,4022,8222,10022"

# Non-HTTP ports that are neither SSH nor TLS — httpx cannot probe these.
# They are accepted via --database/--directory/--vpn presets but skipped in web scanning.
NON_HTTP_PORT_LIST="3306,5432,27017,6379,389,1194,1723"

# Scan mode flags (computed after argument parsing)
HAS_WEB_PORTS=0
HAS_SSH_PORTS=0
WEB_PORTS=""
SSH_PORTS_RESOLVED=""

# SSH scan counters
SSH_TOTAL=0
SSH_OPEN=0
SSH_FILTERED=0
SSH_FILTERED_HOSTS=0   # unique hosts with at least one filtered port
SSH_CLOSED=0
SSH_PQC_READY=0
SSH_SCANNED=0

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
DIM='\033[2m'
NC='\033[0m' # No Color
CLEAR_LINE='\033[K'

# Progress bar characters
BAR_FILLED="█"
BAR_EMPTY="░"
BAR_WIDTH=40

# Helper functions
verbose() {
  [[ "$VERBOSE" == "1" ]] && printf '%b\n' "${DIM}[VERBOSE] $*${NC}" >&2 || true
}

count_lines() {
  local file="$1"
  [[ -f "$file" ]] && [[ -s "$file" ]] || { echo 0; return; }
  local n
  n=$(wc -l < "$file" | tr -d ' ')
  [[ "$n" -eq 0 ]] && n=1
  echo "$n"
}

# Portable timestamp formatter — works on Linux (date -d) and macOS (date -jf)
format_epoch() {
  local epoch="$1"
  local result
  result=$(date -d "@$epoch" 2>/dev/null) \
    || result=$(date -jf "%s" "$epoch" 2>/dev/null) \
    || result="epoch:$epoch"
  echo "$result"
}

# Print banner
print_banner() {
  printf '%b\n' "${CYAN}"
  echo "╔════════════════════════════════════════════════════════════╗"
  echo "║                                                            ║"
  echo "║    ██████  ██    ██ ██████  ██ ████████  █████   ██████    ║"
  echo "║   ██    ██ ██    ██ ██   ██ ██    ██    ██   ██ ██         ║"
  echo "║   ██    ██ ██    ██ ██████  ██    ██    ███████ ██         ║"
  echo "║   ██ ▄▄ ██ ██    ██ ██   ██ ██    ██    ██   ██ ██         ║"
  echo "║    ██████   ██████  ██████  ██    ██    ██   ██  ██████    ║"
  echo "║       ▀▀                                                   ║"
  echo "║                                                            ║"
  echo "║    Post-Quantum Cryptography Scanner                       ║"
  echo "║    https://qubitac.com                                     ║"
  echo "║                                                            ║"
  echo "╚════════════════════════════════════════════════════════════╝"
  printf '%b\n' "${NC}"
}

# Print progress bar
# Usage: progress_bar <current> <total> <label>
progress_bar() {
  local current=$1
  local total=$2
  local label="$3"
  
  local percent
  if [[ $total -eq 0 ]]; then
    percent=100
  else
    percent=$((current * 100 / total))
  fi
  
  local filled=$((percent * BAR_WIDTH / 100))
  local empty=$((BAR_WIDTH - filled))
  
  # Build the bar
  local bar="" i
  for ((i=0; i<filled; i++)); do bar+="${BAR_FILLED}"; done
  for ((i=0; i<empty; i++)); do bar+="${BAR_EMPTY}"; done
  
  # Print with carriage return for live update (clear line first)
  printf "\r${CLEAR_LINE}  ${CYAN}${bar}${NC} ${WHITE}%3d%%${NC} ${DIM}%s${NC}" "$percent" "$label"
}

# Complete progress bar
progress_complete() {
  local label=$1
  local count=$2
  
  local bar="" i
  for ((i=0; i<BAR_WIDTH; i++)); do bar+="${BAR_FILLED}"; done
  
  printf "\r${CLEAR_LINE}  ${GREEN}${bar}${NC} ${WHITE}100%%${NC} ${GREEN}✓${NC} %s ${DIM}(%d)${NC}\n" "$label" "$count"
}

# Failed progress bar
progress_failed() {
  local label=$1
  
  local bar="" i
  for ((i=0; i<BAR_WIDTH; i++)); do bar+="${BAR_EMPTY}"; done
  
  printf "\r${CLEAR_LINE}  ${RED}${bar}${NC} ${RED}  0%%${NC} ${RED}✗${NC} %s ${DIM}(failed)${NC}\n" "$label"
}

# Check dependencies
check_dependencies() {
  printf '%b\n' "${WHITE}Checking dependencies...${NC}"
  echo ""
  
  verbose "Checking for required tools: subfinder, dnsx, httpx, jq, python3, openssl, ssh-audit, dig, timeout"
  
  local missing_tools=()
  local tools=("subfinder" "dnsx" "httpx" "jq" "python3" "openssl" "ssh-audit" "dig" "timeout")
  local version=""
  local cmd=""
  local script=""
  local still_missing=false
  
  for cmd in "${tools[@]}"; do
    if command -v "$cmd" &> /dev/null; then
      version=""
      case "$cmd" in
        openssl) version=$(openssl version 2>/dev/null | cut -d' ' -f2) || true ;;
        python3) version=$(python3 --version 2>/dev/null | cut -d' ' -f2) || true ;;
        jq) version=$(jq --version 2>/dev/null | sed 's/jq-//') || true ;;

        ssh-audit) version=$(ssh-audit -h 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1) || true ;;
        timeout) version=$(timeout --version 2>/dev/null | head -1 | awk '{print $NF}') || true ;;
        dig) version=$(dig -v 2>&1 | head -1 | awk '{print $NF}') || true ;;
        *) version=$(command -v "$cmd" | xargs -I{} basename {}) || true ;;
      esac
      printf '%b\n' "  ${GREEN}✓${NC} $cmd ${DIM}($version)${NC}"
      verbose "Found $cmd at $(command -v "$cmd") version $version"
    else
      printf '%b\n' "  ${RED}✗${NC} $cmd ${RED}(not found)${NC}"
      verbose "Missing required tool: $cmd"
      missing_tools+=("$cmd")
    fi
  done
  
  echo ""
  
  # Check Python scripts
  local scripts=("openssl_scanner.py" "ssh_scanner.py" "pqc_cbom.py")
  local scripts_ok=true
  
  verbose "Checking for Python scripts in SCRIPT_DIR=$SCRIPT_DIR"
  
  for script in "${scripts[@]}"; do
    if [[ -f "$SCRIPT_DIR/$script" ]]; then
      printf '%b\n' "  ${GREEN}✓${NC} $script"
      verbose "Found $script at $SCRIPT_DIR/$script"
    elif [[ -f "$script" ]]; then
      printf '%b\n' "  ${GREEN}✓${NC} $script"
      verbose "Found $script in current directory"
    else
      printf '%b\n' "  ${RED}✗${NC} $script ${RED}(not found)${NC}"
      verbose "Missing Python script: $script"
      scripts_ok=false
    fi
  done
  
  echo ""
  
  # If there are missing tools, offer to install them
  if [[ ${#missing_tools[@]} -gt 0 ]]; then
    printf '%b\n' "${YELLOW}Missing tools: ${missing_tools[*]}${NC}"
    echo ""
    
    # Ask user if they want to auto-install
    local REPLY
    read -p "Would you like to install missing dependencies automatically? [y/N] " -n 1 -r
    echo ""
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
      install_dependencies "${missing_tools[@]}"
      
      # Re-check after installation
      echo ""
      printf '%b\n' "${WHITE}Re-checking dependencies...${NC}"
      still_missing=false
      for cmd in "${missing_tools[@]}"; do
        if command -v "$cmd" &> /dev/null; then
          printf '%b\n' "  ${GREEN}✓${NC} $cmd installed successfully"
        else
          printf '%b\n' "  ${RED}✗${NC} $cmd still not found"
          still_missing=true
        fi
      done
      
      if [[ "$still_missing" == "true" ]]; then
        echo ""
        printf '%b\n' "${RED}Error: Some dependencies could not be installed.${NC}"
        printf '%b\n' "${DIM}Please install them manually and try again.${NC}"
        exit 1
      fi
    else
      echo ""
      printf '%b\n' "${RED}Error: Missing required dependencies.${NC}"
      show_install_instructions
      exit 1
    fi
  fi
  
  if [[ "$scripts_ok" == "false" ]]; then
    printf '%b\n' "${RED}Error: Required Python scripts are missing.${NC}"
    printf '%b\n' "${DIM}All three scripts (openssl_scanner.py, ssh_scanner.py, pqc_cbom.py)${NC}"
    printf '%b\n' "${DIM}must be present alongside scan.sh. Cannot continue.${NC}"
    echo ""
    exit 1
  fi

  # ── Minimum version checks ────────────────────────────────────────────────
  printf '%b\n' "${WHITE}Checking minimum versions...${NC}"
  echo ""

  local version_ok=true
  local outdated_tools=()

  # Helper: returns 0 (true) if version $1 >= $2
  version_gte() {
    [ "$(printf '%s\n%s' "$1" "$2" | sort -V | head -1)" = "$2" ]
  }

  # Helper: check a tool version
  check_version() {
    local tool="$1"
    local actual="$2"
    local minimum="$3"
    local fix_cmd="$4"

    if [[ -z "$actual" ]]; then
      return
    fi

    if version_gte "$actual" "$minimum"; then
      printf '%b\n' "  ${GREEN}✓${NC} $tool v${actual} ${DIM}(>= $minimum)${NC}"
    else
      printf '%b\n' "  ${RED}✗${NC} $tool v${actual} ${RED}too old — need >= $minimum${NC}"
      outdated_tools+=("$tool:$fix_cmd")
      version_ok=false
    fi
  }

  # httpx >= 1.9.0
  local httpx_ver
  if command -v httpx &> /dev/null; then
    httpx_ver=$(httpx -version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    check_version "httpx" "$httpx_ver" "1.9.0" "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
  fi

  # subfinder >= 2.11.0
  local subfinder_ver
  if command -v subfinder &> /dev/null; then
    subfinder_ver=$(subfinder -version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    check_version "subfinder" "$subfinder_ver" "2.11.0" "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  fi

  # dnsx >= 1.2.3
  local dnsx_ver
  if command -v dnsx &> /dev/null; then
    dnsx_ver=$(dnsx -version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    check_version "dnsx" "$dnsx_ver" "1.2.3" "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
  fi

  # ssh-audit >= 3.3.0 (use -h not --version)
  local sshaudit_ver
  if command -v ssh-audit &> /dev/null; then
    sshaudit_ver=$(ssh-audit -h 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    check_version "ssh-audit" "$sshaudit_ver" "3.3.0" "pip3 install --upgrade ssh-audit"
  fi

  # jq >= 1.8
  local jq_ver
  if command -v jq &> /dev/null; then
    jq_ver=$(jq --version 2>&1 | grep -oE '[0-9]+\.[0-9]+' | head -1)
    check_version "jq" "${jq_ver}.0" "1.8.0" "brew upgrade jq"
  fi

  # openssl >= 3.6.1
  local openssl_ver
  if command -v openssl &> /dev/null; then
    openssl_ver=$(openssl version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    check_version "openssl" "$openssl_ver" "3.6.1" "brew upgrade openssl"
  fi

  # python3 >= 3.10.4
  local python_ver
  if command -v python3 &> /dev/null; then
    python_ver=$(python3 --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    check_version "python3" "$python_ver" "3.10.4" "brew upgrade python3"
  fi

  echo ""

  # If any tools are outdated offer to auto-update
  if [[ "$version_ok" == "false" ]]; then
    printf '%b\n' "${YELLOW}Outdated tools detected.${NC}"
    echo ""

    local REPLY
    read -p "Would you like to update outdated tools automatically? [y/N] " -n 1 -r
    echo ""

    if [[ $REPLY =~ ^[Yy]$ ]]; then
      printf '%b\n' "${WHITE}Updating outdated tools...${NC}"
      echo ""

      local tool_entry tool_name fix_cmd still_outdated=false
      for tool_entry in "${outdated_tools[@]}"; do
        tool_name="${tool_entry%%:*}"
        fix_cmd="${tool_entry##*:}"
        printf '%b\n' "${CYAN}Updating $tool_name...${NC}"
        if eval "$fix_cmd"; then
          printf '%b\n' "  ${GREEN}✓${NC} $tool_name updated successfully"
          if [[ "$fix_cmd" == go\ install* ]]; then
            export PATH="$(go env GOPATH)/bin:$PATH"
          fi
        else
          printf '%b\n' "  ${RED}✗${NC} $tool_name update failed"
          still_outdated=true
        fi
      done

      echo ""

      if [[ "$still_outdated" == "true" ]]; then
        printf '%b\n' "${RED}Error: Some tools could not be updated. Please update them manually.${NC}"
        exit 1
      else
        printf '%b\n' "${GREEN}✓ All tools updated successfully${NC}"
      fi
    else
      echo ""
      printf '%b\n' "${RED}Error: Some tools are below minimum required versions.${NC}"
      printf '%b\n' "${DIM}Please update them manually and try again.${NC}"
      echo ""
      exit 1
    fi
  fi

  if [[ ${#missing_tools[@]} -eq 0 ]] && [[ "$scripts_ok" == "true" ]]; then
    printf '%b\n' "${GREEN}✓ All dependencies found and versions verified${NC}"
  fi
  echo ""
}

# Detect OS
detect_os() {
  if [[ "$OSTYPE" == "darwin"* ]]; then
    echo "macos"
  elif [[ -f /etc/debian_version ]]; then
    echo "debian"
  elif [[ -f /etc/redhat-release ]]; then
    echo "redhat"
  elif [[ -f /etc/arch-release ]]; then
    echo "arch"
  elif grep -q Microsoft /proc/version 2>/dev/null; then
    echo "wsl"
  else
    echo "linux"
  fi
}

# Install dependencies based on OS
install_dependencies() {
  local tools=("$@")
  local os tool
  os=$(detect_os)
  
  echo ""
  printf '%b\n' "${WHITE}Detected OS: ${CYAN}$os${NC}"
  printf '%b\n' "${WHITE}Installing: ${CYAN}${tools[*]}${NC}"
  echo ""
  
  case "$os" in
    macos)
      # Check if Homebrew is installed
      if ! command -v brew &> /dev/null; then
        printf '%b\n' "${YELLOW}Homebrew not found. Installing Homebrew first...${NC}"
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
      fi
      
      for tool in "${tools[@]}"; do
        printf '%b\n' "${CYAN}Installing $tool...${NC}"
        case "$tool" in
          subfinder|dnsx|httpx)
            brew install "$tool" 2>/dev/null || brew install projectdiscovery/tap/"$tool"
            ;;
          dig)
            brew install bind 2>/dev/null || true
            ;;
          timeout)
            # 'timeout' on macOS comes from GNU coreutils
            brew install coreutils 2>/dev/null || true
            ;;
          ssh-audit)
            pip3 install ssh-audit --break-system-packages 2>/dev/null || pip3 install ssh-audit 2>/dev/null || true
            ;;
          *)
            brew install "$tool"
            ;;
        esac
      done
      ;;
      
    debian|wsl)
      printf '%b\n' "${CYAN}Updating package list...${NC}"
      sudo apt update
      
      for tool in "${tools[@]}"; do
        printf '%b\n' "${CYAN}Installing $tool...${NC}"
        case "$tool" in
          jq|python3|openssl)
            sudo apt install -y "$tool"
            ;;
          timeout)
            # 'timeout' is part of coreutils, which is installed by default on most systems
            sudo apt install -y coreutils 2>/dev/null || true
            ;;
          dig)
            sudo apt install -y dnsutils
            ;;
          ssh-audit)
            pip3 install ssh-audit --break-system-packages 2>/dev/null || pip3 install ssh-audit 2>/dev/null || sudo apt install -y ssh-audit
            ;;
          subfinder)
            # Try apt first, then Go
            if ! sudo apt install -y subfinder 2>/dev/null; then
              install_go_tool "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
            fi
            ;;
          dnsx)
            if ! sudo apt install -y dnsx 2>/dev/null; then
              install_go_tool "github.com/projectdiscovery/dnsx/cmd/dnsx"
            fi
            ;;
          httpx)
            if ! sudo apt install -y httpx 2>/dev/null; then
              install_go_tool "github.com/projectdiscovery/httpx/cmd/httpx"
            fi
            ;;
        esac
      done
      ;;
      
    redhat)
      for tool in "${tools[@]}"; do
        printf '%b\n' "${CYAN}Installing $tool...${NC}"
        case "$tool" in
          jq|python3|openssl)
            sudo yum install -y "$tool" || sudo dnf install -y "$tool"
            ;;
          timeout)
            sudo yum install -y coreutils 2>/dev/null || sudo dnf install -y coreutils 2>/dev/null || true
            ;;
          dig)
            sudo yum install -y bind-utils 2>/dev/null || sudo dnf install -y bind-utils
            ;;
          ssh-audit)
            pip3 install ssh-audit --break-system-packages 2>/dev/null || pip3 install ssh-audit 2>/dev/null || true
            ;;
          subfinder|dnsx|httpx)
            case "$tool" in
              subfinder) install_go_tool "github.com/projectdiscovery/subfinder/v2/cmd/subfinder" ;;
              *) install_go_tool "github.com/projectdiscovery/$tool/cmd/$tool" ;;
            esac
            ;;
        esac
      done
      ;;
      
    arch)
      for tool in "${tools[@]}"; do
        printf '%b\n' "${CYAN}Installing $tool...${NC}"
        case "$tool" in
          jq|python3|openssl)
            sudo pacman -S --noconfirm "$tool"
            ;;
          timeout)
            sudo pacman -S --noconfirm coreutils 2>/dev/null || true
            ;;
          dig)
            sudo pacman -S --noconfirm bind
            ;;
          ssh-audit)
            pip3 install ssh-audit --break-system-packages 2>/dev/null || pip3 install ssh-audit 2>/dev/null || true
            ;;
          subfinder|dnsx|httpx)
            # Try AUR or Go
            if command -v yay &> /dev/null; then
              yay -S --noconfirm "$tool" 2>/dev/null || {
                case "$tool" in
                  subfinder) install_go_tool "github.com/projectdiscovery/subfinder/v2/cmd/subfinder" ;;
                  *) install_go_tool "github.com/projectdiscovery/$tool/cmd/$tool" ;;
                esac
              }
            else
              case "$tool" in
                subfinder) install_go_tool "github.com/projectdiscovery/subfinder/v2/cmd/subfinder" ;;
                *) install_go_tool "github.com/projectdiscovery/$tool/cmd/$tool" ;;
              esac
            fi
            ;;
        esac
      done
      ;;
      
    *)
      printf '%b\n' "${YELLOW}Unknown OS. Attempting generic installation...${NC}"
      for tool in "${tools[@]}"; do
        case "$tool" in
          subfinder|dnsx|httpx)
            case "$tool" in
              subfinder) install_go_tool "github.com/projectdiscovery/subfinder/v2/cmd/subfinder" ;;
              *) install_go_tool "github.com/projectdiscovery/$tool/cmd/$tool" ;;
            esac
            ;;
          *)
            printf '%b\n' "${RED}Please install $tool manually${NC}"
            ;;
        esac
      done
      ;;
  esac
}

# Install Go tool
install_go_tool() {
  local package="$1"
  local tool_name
  tool_name=$(basename "$package")
  
  # Check if Go is installed
  if ! command -v go &> /dev/null; then
    printf '%b\n' "${YELLOW}Go not found. Installing Go first...${NC}"
    install_go
  fi
  
  printf '%b\n' "${CYAN}Installing $tool_name via Go...${NC}"
  go install -v "$package@latest"
  
  # Add Go bin to PATH for current session
  export PATH="$PATH:$(go env GOPATH)/bin"
  
  # Remind user to add to PATH permanently
  if ! command -v "$tool_name" &> /dev/null; then
    printf '%b\n' "${YELLOW}Note: Add this to your ~/.bashrc or ~/.zshrc:${NC}"
    printf '%b\n' "  export PATH=\$PATH:\$(go env GOPATH)/bin"
  fi
}

# Install Go
install_go() {
  local os
  os=$(detect_os)
  
  case "$os" in
    macos)
      brew install go
      ;;
    debian|wsl)
      sudo apt install -y golang-go
      ;;
    redhat)
      sudo yum install -y golang || sudo dnf install -y golang
      ;;
    arch)
      sudo pacman -S --noconfirm go
      ;;
    *)
      printf '%b\n' "${RED}Please install Go manually from https://golang.org/dl/${NC}"
      exit 1
      ;;
  esac
}

# Show manual installation instructions
show_install_instructions() {
  echo ""
  printf '%b\n' "${WHITE}Installation Instructions:${NC}"
  echo ""
  printf '%b\n' "${CYAN}macOS (Homebrew):${NC}"
  echo "  brew install subfinder dnsx httpx jq python3 openssl bind coreutils"
  echo "  pip3 install ssh-audit"
  echo ""
  printf '%b\n' "${CYAN}Linux (Ubuntu/Debian):${NC}"
  echo "  sudo apt update && sudo apt install -y jq python3 openssl dnsutils"
  echo "  pip3 install ssh-audit"
  echo "  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  echo "  go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
  echo "  go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
  echo ""
  printf '%b\n' "${CYAN}Windows (WSL):${NC}"
  echo "  Follow Linux instructions inside WSL"
  echo ""
  printf '%b\n' "${CYAN}Go tools path:${NC}"
  echo "  Add to ~/.bashrc or ~/.zshrc:"
  echo "  export PATH=\$PATH:\$(go env GOPATH)/bin"
  echo ""
}

# ═══════════════════════════════════════════════════════════════════════════════
# Port Classification — separate SSH ports from Web/TLS ports
# ═══════════════════════════════════════════════════════════════════════════════

# Check if a port is an SSH port
is_ssh_port() {
  local port="$1"
  echo ",$SSH_PORT_LIST," | grep -q ",$port,"
}

# Check if a port is a non-HTTP/non-SSH port (DB, LDAP, VPN etc.)
is_non_http_port() {
  local port="$1"
  echo ",$NON_HTTP_PORT_LIST," | grep -q ",$port,"
}

# Classify SCAN_PORTS into SSH vs Web categories
classify_ports() {
  local web_list=""
  local ssh_list=""
  local p
  local -a ALL_PORTS
  IFS=',' read -ra ALL_PORTS <<< "$SCAN_PORTS"
  for p in "${ALL_PORTS[@]}"; do
    p=$(echo "$p" | xargs)
    [[ -z "$p" ]] && continue
    if is_ssh_port "$p"; then
      [[ -n "$ssh_list" ]] && ssh_list="$ssh_list,$p" || ssh_list="$p"
    elif is_non_http_port "$p"; then
      verbose "Port $p is a non-HTTP protocol port (DB/LDAP/VPN) — skipping httpx/TLS scan for this port"
    else
      [[ -n "$web_list" ]] && web_list="$web_list,$p" || web_list="$p"
    fi
  done

  WEB_PORTS="$web_list"
  SSH_PORTS_RESOLVED="$ssh_list"

  [[ -n "$WEB_PORTS" ]] && HAS_WEB_PORTS=1
  [[ -n "$SSH_PORTS_RESOLVED" ]] && HAS_SSH_PORTS=1

  verbose "Port classification: WEB=[$WEB_PORTS] SSH=[$SSH_PORTS_RESOLVED]"
  verbose "Scan mode: HAS_WEB_PORTS=$HAS_WEB_PORTS HAS_SSH_PORTS=$HAS_SSH_PORTS"
}

# ═══════════════════════════════════════════════════════════════════════════════
# SSH scan orchestrator — delegates to ssh_scanner.py
# ═══════════════════════════════════════════════════════════════════════════════
run_ssh_scan() {
  local domain="$1"

  if [[ "$HAS_SSH_PORTS" -eq 0 ]]; then
    printf '%b\n' "${WHITE}[5/6] SSH Service Scan${NC}"
    printf '%b\n' "  ${DIM}Skipped — no SSH ports requested${NC}"
    progress_complete "Skipped (no SSH ports)" 0
    verbose "No SSH ports to scan"
    return
  fi

  printf '%b\n' "${WHITE}[5/6] SSH Service Scan${NC}"
  verbose "Starting SSH scan on ports: $SSH_PORTS_RESOLVED"

  # Locate ssh_scanner.py
  local SSH_SCANNER=""
  [[ -f "$SCRIPT_DIR/ssh_scanner.py" ]] && SSH_SCANNER="$SCRIPT_DIR/ssh_scanner.py"
  [[ -z "$SSH_SCANNER" ]] && [[ -f "ssh_scanner.py" ]] && SSH_SCANNER="ssh_scanner.py"

  if [[ -z "$SSH_SCANNER" ]]; then
    printf '%b\n' "  ${RED}✗ ssh_scanner.py not found — skipping SSH scan${NC}"
    progress_complete "Skipped (ssh_scanner.py not found)" 0
    return
  fi

  if [[ ! -s live/domains.txt ]]; then
    verbose "No live domains for SSH scan"
    progress_complete "Skipped (no live domains)" 0
    return
  fi

  # Build hosts file with port suffixes for each SSH port
  local ssh_hosts_file
  ssh_hosts_file=$(mktemp)
  _register_tmp "$ssh_hosts_file"

  local -a SSH_PORT_ARR
  IFS=',' read -ra SSH_PORT_ARR <<< "$SSH_PORTS_RESOLVED"
  local total_hosts
  total_hosts=$(count_lines live/domains.txt)
  local total_combinations
  total_combinations=$(( total_hosts * ${#SSH_PORT_ARR[@]} )) || true
  SSH_TOTAL=$total_combinations

  while IFS= read -r h; do
    for p in "${SSH_PORT_ARR[@]}"; do
      p=$(echo "$p" | xargs)
      [[ -n "$p" ]] && echo "${h}:${p}" >> "$ssh_hosts_file"
    done
  done < live/domains.txt

  printf '%b\n' "  ${DIM}Scanning $total_hosts hosts × ${#SSH_PORT_ARR[@]} SSH port(s) = $total_combinations targets${NC}"

  > crypto/ssh.jsonl

  # Delegate entirely to ssh_scanner.py
  local ssh_total_timeout=$(( SCAN_TIMEOUT * total_combinations + 60 ))
  verbose "SSH scan total timeout: ${ssh_total_timeout}s (${SCAN_TIMEOUT}s × ${total_combinations} targets + 60s buffer)"
  # Run SSH scanner in background so we can show spinner with timer
  timeout "$ssh_total_timeout" env SCAN_TIMEOUT="$SCAN_TIMEOUT" python3 "$SSH_SCANNER" scan "$ssh_hosts_file" crypto/ssh.jsonl 2>/dev/null &
  local SSH_SCAN_PID=$!

  # Show spinner with timer while waiting
  start_time=$(date +%s)
  i=0
  while kill -0 $SSH_SCAN_PID 2>/dev/null; do
    current_time=$(date +%s)
    elapsed=$(( current_time - start_time ))
    mins=$(( elapsed / 60 ))
    secs=$(( elapsed % 60 ))
    char_index=$(( i % ${#spinner_chars[@]} ))
    spinner="${spinner_chars[$char_index]}"
    printf "\r${CLEAR_LINE}  ${CYAN}%s${NC} ${DIM}Scanning SSH... (%dm %02ds)${NC}" "$spinner" "$mins" "$secs"
    i=$(( i + 1 ))
    sleep 0.3
  done

  # Collect exit code
  local ssh_exit=0
  wait $SSH_SCAN_PID || ssh_exit=$?
  printf "\r${CLEAR_LINE}"

  if [[ $ssh_exit -eq 124 ]]; then
    printf '%b\n' "  ${YELLOW}⚠ SSH scan timed out after ${ssh_total_timeout}s${NC}"
    verbose "SSH scan timed out (exit code 124)"
  elif [[ $ssh_exit -ne 0 ]]; then
    printf '%b\n' "  ${YELLOW}⚠ SSH scan exited with code $ssh_exit — results may be incomplete${NC}"
    verbose "SSH scan failed with exit code $ssh_exit"
  fi

  # Parse counters from output file
  if [[ -s crypto/ssh.jsonl ]]; then
    SSH_OPEN=$(jq -rs '[.[] | select(.probe_status == "success")] | length' crypto/ssh.jsonl 2>/dev/null || echo 0)
    SSH_FILTERED=$(jq -rs '[.[] | select(.probe_status == "filtered")] | length' crypto/ssh.jsonl 2>/dev/null || echo 0)
    SSH_CLOSED=$(jq -rs '[.[] | select(.probe_status == "closed")] | length' crypto/ssh.jsonl 2>/dev/null || echo 0)
    SSH_SCANNED=$SSH_OPEN
    SSH_PQC_READY=$(jq -rs '[.[] | select(.pqc_ready == true)] | length' crypto/ssh.jsonl 2>/dev/null || echo 0)
    SSH_FILTERED_HOSTS=$(jq -r 'select(.probe_status == "filtered") | .host' crypto/ssh.jsonl 2>/dev/null | sort -u | wc -l | tr -d ' ' || echo 0)

    # Copy filtered entries to ssh_filtered.jsonl for dashboard
    jq -c 'select(.probe_status == "filtered")' crypto/ssh.jsonl > crypto/ssh_filtered.jsonl 2>/dev/null || true

    # Append SSH results to main crypto file
    cat crypto/ssh.jsonl >> crypto/tls.jsonl
    verbose "Appended SSH results to crypto/tls.jsonl"
  else
    touch crypto/ssh_filtered.jsonl
  fi

  # Summary
  printf '%b\n' "  ${DIM}├─ SSH open:     ${GREEN}$SSH_OPEN${NC}"
  printf '%b\n' "  ${DIM}├─ SSH filtered: ${YELLOW}$SSH_FILTERED${NC}"
  printf '%b\n' "  ${DIM}├─ SSH closed:   ${DIM}$SSH_CLOSED${NC}"
  printf '%b\n' "  ${DIM}└─ PQC ready:    ${CYAN}$SSH_PQC_READY${NC}"

  if [[ "$SSH_FILTERED" -gt 0 ]]; then
    printf '%b\n' ""
    printf '%b\n' "  ${YELLOW}ℹ ${SSH_FILTERED} port(s) across ${SSH_FILTERED_HOSTS} host(s) had SSH filtered (firewall/CDN).${NC}"
    printf '%b\n' "  ${DIM}  These appear on the dashboard as 'SSH Filtered'.${NC}"
    printf '%b\n' "  ${DIM}  Try scanning the origin IP directly if behind a CDN.${NC}"
  fi

  progress_complete "SSH scanned" "$SSH_SCANNED"
}


# Validate domain input — strips whitespace, rejects dangerous chars, checks format/length
validate_domain() {
  local domain="$1"

  verbose "Validating domain input: '$domain'"

  # Remove whitespace
  domain=$(echo "$domain" | xargs)
  verbose "After whitespace removal: '$domain'"

  # Check for dangerous characters
  if [[ "$domain" == *[';&<>(){}'\''|$']* ]]; then
    printf '%b\n' "${RED}Error: Invalid characters in domain name.${NC}"
    verbose "Domain contains dangerous characters"
    exit 1
  fi
  verbose "Passed dangerous character check"

  # Basic format validation
  if [[ ! "$domain" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$ ]] && [[ ! "$domain" =~ ^[a-zA-Z0-9]$ ]]; then
    printf '%b\n' "${RED}Error: Invalid domain format.${NC}"
    verbose "Domain failed format validation regex"
    exit 1
  fi
  verbose "Passed format validation"

  # Length check
  if [[ ${#domain} -gt 253 ]]; then
    printf '%b\n' "${RED}Error: Domain name too long (max 253 characters).${NC}"
    verbose "Domain length ${#domain} exceeds maximum of 253"
    exit 1
  fi
  verbose "Passed length check (${#domain} characters)"

  verbose "Domain validation successful: $domain"
  echo "$domain"
}

# Main scan function
run_scan() {
  local domain="$1"
  
  # Shared spinner/timing variables used across multiple steps
  local -a spinner_chars=("⠋" "⠙" "⠹" "⠸" "⠼" "⠴" "⠦" "⠧" "⠇" "⠏")
  local start_time i=0 current_time elapsed mins secs char_index spinner count current_count
  # PIDs and temp file paths
  local SUBFINDER_PID SUBFINDER_ERRORS SUBFINDER_EXIT
  local DNSX_PID DNSX_ERRORS DNSX_EXIT
  local HTTPX_PID
  # Script paths
  local SCANNER_SCRIPT CBOM_SCRIPT TLS_INPUT=""
  # Port/scan locals
  local -a PORT_ARRAY PORTS
  local PORT_COUNT TOTAL_COMBINATIONS tls_ports fb_port d p
  local host_port total_hosts scanned TLS_SCAN_OUTPUT host_port_file EXIT_CODE
  local scheme host port status_code title webserver content_length line
  local safe_port safe_status safe_length
  # Scan result counters (local so run_scan is re-entrant and doesn't pollute global scope)
  local SCAN_START_TIME SCAN_END_TIME SCAN_DURATION SCAN_MINUTES SCAN_SECONDS
  local SUBDOMAIN_COUNT=0 LIVE_COUNT=0 HTTP_COUNT=0
  local HTTPS_COUNT=0 HTTP_SERVICE_COUNT=0 BOTH_COUNT=0 TRUE_HTTP_ONLY=0
  local TLS_COUNT=0 TLS_SCANNED=0 TLS_SUCCESS=0


  verbose "Starting scan for domain: $domain"
  verbose "Configuration: SCAN_PORTS=$SCAN_PORTS, SCAN_TIMEOUT=$SCAN_TIMEOUT"

  # ── Timestamped output directory ─────────────────────────────────────────────
  # Structure: <domain>/<YYYY-MM-DD_HH-MM-SS>/  (sits alongside scan.sh)
  # Running the same domain twice on the same day produces two separate folders
  # that can be compared side-by-side.
  local SCAN_TIMESTAMP OUTPUT_DIR
  SCAN_TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
  OUTPUT_DIR="${SCRIPT_DIR}/${domain}/${SCAN_TIMESTAMP}"

  mkdir -p "$OUTPUT_DIR"
  cd "$OUTPUT_DIR" || { printf '%b\n' "${RED}Error: cannot enter output directory: $OUTPUT_DIR${NC}"; exit 1; }

  local scanner_dir
  scanner_dir=$(basename "$SCRIPT_DIR")
  local short_output_dir="${OUTPUT_DIR#"$SCRIPT_DIR/"}"
  printf '%b\n' "${WHITE}Output dir:${NC} ${CYAN}${short_output_dir}${NC}"
  echo ""
  verbose "Created and entered output directory: $OUTPUT_DIR"

  # Create subdirectories inside the timestamped run folder
  verbose "Creating output directories: seeds, raw, live, services, crypto, reports, cbom"
  mkdir -p seeds raw live services crypto reports cbom

  echo "$domain" > seeds/domains.txt
  verbose "Wrote seed domain to seeds/domains.txt"
  
  SCAN_START_TIME=$(date +%s)
  verbose "Scan start time: $(format_epoch "$SCAN_START_TIME")"
  
  # ════════════════════════════════════════════════════════════════════════════
  # Step 1: Subdomain Discovery
  # ════════════════════════════════════════════════════════════════════════════
  printf '%b\n' "${WHITE}[1/6] Subdomain Discovery${NC}"
  verbose "Running subfinder with -all flag for comprehensive subdomain enumeration"
  
  printf '%b\n' "  ${DIM}This may take several minutes for large domains...${NC}"
  
  # Run subfinder in background with real-time output to file
  > raw/subdomains.txt
  SUBFINDER_ERRORS=$(mktemp)
  _register_tmp "$SUBFINDER_ERRORS"
  
  # Start subfinder - pipe stdout to file in real-time (no -o flag, use redirect instead)
  subfinder -all -silent -d "$domain" 2>"$SUBFINDER_ERRORS" >> raw/subdomains.txt &
  SUBFINDER_PID=$!
  
  # Show spinner while running
  start_time=$(date +%s)
  i=0
  
  while kill -0 $SUBFINDER_PID 2>/dev/null; do
    current_time=$(date +%s)
    elapsed=$((current_time - start_time))
    mins=$((elapsed / 60))
    secs=$((elapsed % 60))
    
    # Get spinner character
    char_index=$(( i % ${#spinner_chars[@]}))
    spinner="${spinner_chars[$char_index]}"
    
    printf "\r${CLEAR_LINE}  ${CYAN}%s${NC} ${DIM}Discovering subdomains... (%dm %02ds)${NC}" "$spinner" "$mins" "$secs"
    
    i=$(( i + 1 ))
    sleep 0.3
  done
  
  # Wait for subfinder to finish and get exit code
  SUBFINDER_EXIT=0
  wait $SUBFINDER_PID || SUBFINDER_EXIT=$?
  
  printf "\r${CLEAR_LINE}"  # Clear spinner line
  
  if [[ $SUBFINDER_EXIT -eq 0 ]]; then
    SUBDOMAIN_COUNT=$(count_lines raw/subdomains.txt)
    verbose "subfinder completed successfully, found $SUBDOMAIN_COUNT subdomains"
  else
    touch raw/subdomains.txt
    SUBDOMAIN_COUNT=$(count_lines raw/subdomains.txt)
    verbose "subfinder exited with code $SUBFINDER_EXIT, found $SUBDOMAIN_COUNT subdomains"
    [[ -s "$SUBFINDER_ERRORS" ]] && verbose "subfinder stderr: $(cat "$SUBFINDER_ERRORS")"
  fi
  rm -f "$SUBFINDER_ERRORS"
  
  if [[ "$SUBDOMAIN_COUNT" -eq 0 ]]; then
    echo "$domain" > raw/subdomains.txt
    SUBDOMAIN_COUNT=1
    verbose "No subdomains found, using root domain only"
  else
    # Always ensure root domain is included even when subdomains are found
    if ! grep -qx "$domain" raw/subdomains.txt; then
      echo "$domain" >> raw/subdomains.txt
      SUBDOMAIN_COUNT=$(( SUBDOMAIN_COUNT + 1 )) || true
      verbose "Added root domain $domain to subdomain list"
    fi
  fi
  
  verbose "Subdomains saved to raw/subdomains.txt"
  progress_complete "Subdomains found" "$SUBDOMAIN_COUNT"
  
  # ════════════════════════════════════════════════════════════════════════════
  # Step 2: DNS Resolution
  # ════════════════════════════════════════════════════════════════════════════
  printf '%b\n' "${WHITE}[2/6] DNS Resolution${NC}"
  verbose "Running dnsx for DNS resolution on $SUBDOMAIN_COUNT subdomains"
  
  printf '%b\n' "  ${DIM}Resolving $SUBDOMAIN_COUNT subdomains...${NC}"
  
  # Run dnsx in background with real-time output to file
  > live/domains_resolved.jsonl
  DNSX_ERRORS=$(mktemp)
  _register_tmp "$DNSX_ERRORS"
  
  # Start dnsx - pipe stdout to file in real-time (no -o flag, use redirect instead)
  dnsx -silent -l raw/subdomains.txt -json 2>"$DNSX_ERRORS" >> live/domains_resolved.jsonl &
  DNSX_PID=$!
  
  # Show spinner while running (reuses function-scoped spinner vars)
  start_time=$(date +%s)
  i=0

  while kill -0 $DNSX_PID 2>/dev/null; do
    current_time=$(date +%s)
    elapsed=$((current_time - start_time))
    mins=$((elapsed / 60))
    secs=$((elapsed % 60))
    
    # Get spinner character
    char_index=$(( i % ${#spinner_chars[@]}))
    spinner="${spinner_chars[$char_index]}"
    
    # Get current count
    count=0
    [[ -f live/domains_resolved.jsonl ]] && count=$(wc -l < live/domains_resolved.jsonl 2>/dev/null | tr -d ' ' || echo 0)
    
    printf "\r${CLEAR_LINE}  ${CYAN}%s${NC} ${DIM}Resolving DNS... (%dm %02ds) - Found %s live${NC}" "$spinner" "$mins" "$secs" "$count"
    
    i=$(( i + 1 ))
    sleep 0.3
  done
  
  # Wait for dnsx to finish
  DNSX_EXIT=0
  wait $DNSX_PID || DNSX_EXIT=$?
  
  printf "\r${CLEAR_LINE}"  # Clear spinner line
  
  if [[ $DNSX_EXIT -eq 0 ]] || [[ -s live/domains_resolved.jsonl ]]; then
    verbose "dnsx completed, processing results"
    if [[ -f live/domains_resolved.jsonl ]] && [[ -s live/domains_resolved.jsonl ]]; then
      jq -r 'select(.status_code != "NXDOMAIN") | .host // empty' live/domains_resolved.jsonl 2>/dev/null | sort -u > live/domains.txt 2>/dev/null || true
      [[ -f live/domains.txt ]] || touch live/domains.txt
      verbose "Extracted unique hosts from dnsx JSON output"
    else
      touch live/domains.txt
      verbose "dnsx output file is empty"
    fi
    LIVE_COUNT=$(count_lines live/domains.txt)
    verbose "Found $LIVE_COUNT live domains"
  else
    touch live/domains_resolved.jsonl live/domains.txt
    LIVE_COUNT=0
    verbose "dnsx failed with exit code $DNSX_EXIT"
    [[ -s "$DNSX_ERRORS" ]] && verbose "dnsx stderr: $(cat "$DNSX_ERRORS")"
  fi
  rm -f "$DNSX_ERRORS"
  
  verbose "Live domains saved to live/domains.txt"
  progress_complete "Live domains" "$LIVE_COUNT"
  if [[ "$LIVE_COUNT" -eq 0 ]]; then
    printf '%b\n' "${YELLOW}  No live domains found — skipping all scan steps.${NC}"
    echo ""
    touch services/http.jsonl
    touch crypto/tls.jsonl
    HTTP_COUNT=0
    HTTPS_COUNT=0
    HTTP_SERVICE_COUNT=0
    BOTH_COUNT=0
    TRUE_HTTP_ONLY=0
    TLS_COUNT=0
    TLS_SCANNED=0
    TLS_INPUT="crypto/tls.jsonl"
    echo '{"cbom_version":"1.0","total_assets":0,"assets":[]}' > cbom/crypto-bom.json
    echo "# No data available" > cbom/summary.md
  else


  # ════════════════════════════════════════════════════════════════════════════
  # Step 3: Web Service Detection (skip if SSH-only)
  # ════════════════════════════════════════════════════════════════════════════
  if [[ "$HAS_WEB_PORTS" -eq 1 ]]; then
    printf '%b\n' "${WHITE}[3/6] Web Service Detection${NC}"
    verbose "Running httpx for web service detection on web ports: $WEB_PORTS"
  
    if [[ -s live/domains.txt ]]; then
      verbose "Input file live/domains.txt has $LIVE_COUNT domains"
    
      # Calculate total combinations (domains × WEB ports only)
      IFS=',' read -ra PORT_ARRAY <<< "$WEB_PORTS"
      PORT_COUNT=${#PORT_ARRAY[@]}
      TOTAL_COMBINATIONS=$(( LIVE_COUNT * PORT_COUNT )) || true
    
      printf '%b\n' "  ${DIM}Scanning $LIVE_COUNT domains × $PORT_COUNT web ports = $TOTAL_COMBINATIONS combinations${NC}"
    
      > services/http.jsonl
    
      # Build httpx probe list: use https:// for TLS ports, http:// for HTTP ports
      # This prevents httpx from probing http://host:443 which inflates HTTP counts
      local httpx_targets
      httpx_targets=$(mktemp)
      _register_tmp "$httpx_targets"
      tls_ports="443,8443,9443,465,587,993,995,636"
      IFS=',' read -ra PORTS <<< "$WEB_PORTS"
      while IFS= read -r d; do
        for p in "${PORTS[@]}"; do
          p=$(echo "$p" | xargs)
          [[ -z "$p" ]] && continue
          if echo ",$tls_ports," | grep -q ",$p,"; then
            echo "https://${d}:${p}" >> "$httpx_targets"
          else
            echo "http://${d}:${p}" >> "$httpx_targets"
          fi
        done
      done < live/domains.txt
    
      # Run httpx with explicit URL targets instead of -ports (avoids double http/https probing)
      httpx -silent -l "$httpx_targets" -timeout "$SCAN_TIMEOUT" -json 2>/dev/null >> services/http.jsonl &
      HTTPX_PID=$!
      
      # Monitor progress with spinner
      start_time=$(date +%s)
      i=0
      
      while kill -0 $HTTPX_PID 2>/dev/null; do
        current_time=$(date +%s)
        elapsed=$((current_time - start_time))
        mins=$((elapsed / 60))
        secs=$((elapsed % 60))
        
        # Get spinner character
        char_index=$(( i % ${#spinner_chars[@]}))
        spinner="${spinner_chars[$char_index]}"
        
        # Get current count
        current_count=0
        [[ -f services/http.jsonl ]] && current_count=$(wc -l < services/http.jsonl 2>/dev/null | tr -d ' ' || echo 0)
        
        printf "\r${CLEAR_LINE}  ${CYAN}%s${NC} ${DIM}Scanning... (%dm %02ds) - Found %s services${NC}" "$spinner" "$mins" "$secs" "$current_count"
        
        i=$(( i + 1 ))
        sleep 0.3
      done
      
      # Wait for httpx to finish and check exit code
      local httpx_exit=0
      wait $HTTPX_PID || httpx_exit=$?
      printf "\r${CLEAR_LINE}"  # Clear spinner line
      if [[ $httpx_exit -ne 0 ]]; then
        printf '%b\n' "  ${YELLOW}⚠ httpx exited with code $httpx_exit — results may be incomplete${NC}"
        verbose "httpx failed with exit code $httpx_exit"
      fi
      # Temp file cleaned up by EXIT trap

      HTTP_COUNT=$(count_lines services/http.jsonl)
      verbose "httpx completed (exit=$httpx_exit), found $HTTP_COUNT web services"
    else
      touch services/http.jsonl
      HTTP_COUNT=0
      verbose "Skipping httpx - no live domains to scan"
    fi
  
    verbose "Web services saved to services/http.jsonl"
    progress_complete "Web services" "$HTTP_COUNT"

  else
    # SSH-only mode — skip httpx entirely
    printf '%b\n' "${WHITE}[3/6] Web Service Detection${NC}"
    if [[ "$HAS_SSH_PORTS" -eq 1 ]]; then
      printf '%b\n' "  ${DIM}Skipped — SSH-only scan (no web ports)${NC}"
    else
      printf '%b\n' "  ${DIM}Skipped — no web or SSH ports in port list${NC}"
    fi
    touch services/http.jsonl
    HTTP_COUNT=0
    HTTPS_COUNT=0
    HTTP_SERVICE_COUNT=0
    BOTH_COUNT=0
    TRUE_HTTP_ONLY=0
    progress_complete "Skipped (SSH-only)" 0
  fi
  
  # ════════════════════════════════════════════════════════════════════════════
  # Step 4: TLS/Crypto Analysis (skip if SSH-only)
  # ════════════════════════════════════════════════════════════════════════════
  if [[ "$HAS_WEB_PORTS" -eq 1 ]]; then
    printf '%b\n' "${WHITE}[4/6] TLS/Crypto Analysis${NC}"
    verbose "Preparing TLS/Crypto analysis"
  
  # Create host:port combinations from HTTPS services only
  # Use httpx output to determine which host:port combinations actually have HTTPS
  > live/hosts_ports.txt
  > live/http_only.jsonl
  
  if [[ -f services/http.jsonl ]] && [[ -s services/http.jsonl ]]; then
    verbose "Extracting HTTPS hosts from httpx output"
    
    # Extract HTTPS hosts (scheme = https) and HTTP hosts with status codes
    while IFS= read -r line; do
      scheme=$(echo "$line" | jq -r '.scheme // empty' 2>/dev/null)
      host=$(echo "$line" | jq -r '.host // empty' 2>/dev/null)
      port=$(echo "$line" | jq -r '.port // empty' 2>/dev/null)
      status_code=$(echo "$line" | jq -r '.status_code // empty' 2>/dev/null)
      title=$(echo "$line" | jq -r '.title // empty' 2>/dev/null)
      webserver=$(echo "$line" | jq -r '.webserver // empty' 2>/dev/null)
      content_length=$(echo "$line" | jq -r '.content_length // empty' 2>/dev/null)
      
      if [[ -n "$host" ]] && [[ -n "$port" ]]; then
        if [[ "$scheme" == "https" ]]; then
          echo "${host}:${port}" >> live/hosts_ports.txt
          verbose "HTTPS: ${host}:${port} (status: ${status_code:-unknown})"
        else
          # Store HTTP-only hosts with their status info — use jq to safely build JSON
          safe_port="${port:-0}"; [[ "$safe_port" =~ ^[0-9]+$ ]] || safe_port=0
          safe_status="${status_code:-null}"; [[ "$safe_status" =~ ^[0-9]+$ ]] || safe_status=null
          safe_length="${content_length:-null}"; [[ "$safe_length" =~ ^[0-9]+$ ]] || safe_length=null
          jq -cn \
            --arg host "$host" \
            --argjson port "$safe_port" \
            --arg scheme "${scheme:-http}" \
            --argjson status_code "$safe_status" \
            --arg title "${title}" \
            --arg webserver "${webserver}" \
            --argjson content_length "$safe_length" \
            '{host:$host,port:$port,scheme:$scheme,status_code:$status_code,title:$title,webserver:$webserver,content_length:$content_length}' \
            >> live/http_only.jsonl
          verbose "HTTP only: ${host}:${port} (status: ${status_code:-unknown})"
        fi
      fi
    done < services/http.jsonl
    
    # Remove duplicates from HTTPS list
    sort -u live/hosts_ports.txt -o live/hosts_ports.txt
    
    HTTPS_COUNT=$(count_lines live/hosts_ports.txt)
    HTTP_SERVICE_COUNT=$(count_lines live/http_only.jsonl)
    
    # Calculate hosts with both HTTP and HTTPS
    BOTH_COUNT=0
    if [[ -s live/http_only.jsonl ]] && [[ -s live/hosts_ports.txt ]]; then
      # Get unique HTTP hosts
      local http_hosts_tmp https_hosts_tmp
      http_hosts_tmp=$(mktemp)
      https_hosts_tmp=$(mktemp)
      _register_tmp "$http_hosts_tmp" "$https_hosts_tmp"
      jq -r '.host' live/http_only.jsonl 2>/dev/null | sort -u > "$http_hosts_tmp"
      # Get unique HTTPS hosts
      # Extract hostname robustly — handles IPv6 [addr]:port format as well as host:port
      sed 's/:\([0-9]*\)$//' live/hosts_ports.txt | sort -u > "$https_hosts_tmp"
      # Count hosts in common
      BOTH_COUNT=$(comm -12 "$http_hosts_tmp" "$https_hosts_tmp" | wc -l | tr -d ' ')
      rm -f "$http_hosts_tmp" "$https_hosts_tmp"
    fi
    
    # Calculate true HTTP-only (hosts with NO HTTPS)
    TRUE_HTTP_ONLY=$((HTTP_SERVICE_COUNT - BOTH_COUNT))
    [[ $TRUE_HTTP_ONLY -lt 0 ]] && TRUE_HTTP_ONLY=0
    
    verbose "Found $HTTPS_COUNT HTTPS services, $HTTP_SERVICE_COUNT HTTP services, $BOTH_COUNT hosts with both"
    
    # Display breakdown
    printf '%b\n' "  ${DIM}├─ HTTPS services: $HTTPS_COUNT${NC}"
    printf '%b\n' "  ${DIM}├─ HTTP services:  $HTTP_SERVICE_COUNT${NC}"
    if [[ $BOTH_COUNT -gt 0 ]]; then
      printf '%b\n' "  ${DIM}├─ Hosts with both: $BOTH_COUNT (HTTP redirects to HTTPS)${NC}"
    fi
    if [[ $TRUE_HTTP_ONLY -gt 0 ]]; then
      printf '%b\n' "  ${DIM}└─ HTTP-only hosts: $TRUE_HTTP_ONLY (no HTTPS available)${NC}"
    fi
  else
    # Fallback: If no httpx output, create host:port from domains (original behavior)
    verbose "No httpx output, falling back to port-based scanning"
    HTTPS_COUNT=0
    HTTP_SERVICE_COUNT=0
    BOTH_COUNT=0
    TRUE_HTTP_ONLY=0
    if [[ -f live/domains.txt ]] && [[ -s live/domains.txt ]]; then
      IFS=',' read -ra PORTS <<< "$WEB_PORTS"
      verbose "Generating host:port combinations for web ports: ${PORTS[*]}"
      for fb_port in "${PORTS[@]}"; do
        fb_port=$(echo "$fb_port" | xargs)
        [[ -n "$fb_port" ]] && awk -v p="$fb_port" '{print $0":"p}' live/domains.txt >> live/hosts_ports.txt 2>/dev/null
      done
      HTTPS_COUNT=$(count_lines live/hosts_ports.txt)
      HTTP_COUNT=$HTTPS_COUNT
      verbose "Generated $HTTPS_COUNT host:port combinations"
    fi
  fi
  
  # Find scanner script
  SCANNER_SCRIPT=""
  [[ -f "$SCRIPT_DIR/openssl_scanner.py" ]] && SCANNER_SCRIPT="$SCRIPT_DIR/openssl_scanner.py"
  [[ -z "$SCANNER_SCRIPT" ]] && [[ -f "openssl_scanner.py" ]] && SCANNER_SCRIPT="openssl_scanner.py"
  
  if [[ -n "$SCANNER_SCRIPT" ]]; then
    verbose "Found scanner script: $SCANNER_SCRIPT"
  else
    verbose "Scanner script openssl_scanner.py not found"
  fi


  # Run scanner with progress updates
  # Always create tls.jsonl clean at the start
  > crypto/tls.jsonl

  if [[ -s live/hosts_ports.txt ]] && [[ -n "$SCANNER_SCRIPT" ]]; then
    total_hosts=$(count_lines live/hosts_ports.txt)
    scanned=0
    local tls_success=0
    local tls_timeout=0
    > crypto/tls_timeouts.txt
    verbose "Starting TLS scan of $total_hosts HTTPS hosts"

    while IFS= read -r host_port; do
      scanned=$(( scanned + 1 ))
      verbose "Scanning [$scanned/$total_hosts]: $host_port"

      # Scan individual host with timeout
      TLS_SCAN_OUTPUT=$(mktemp)
      host_port_file=$(mktemp)
      printf '%s\n' "$host_port" > "$host_port_file"

      # Run scan in background so we can show spinner with timer
      timeout "$SCAN_TIMEOUT" env SCAN_TIMEOUT="$SCAN_TIMEOUT" python3 "$SCANNER_SCRIPT" scan "$host_port_file" /dev/stdout > "$TLS_SCAN_OUTPUT" 2>/dev/null &
      local TLS_SCAN_PID=$!

      # Show spinner with timer while waiting
      start_time=$(date +%s)
      i=0
      while kill -0 $TLS_SCAN_PID 2>/dev/null; do
        current_time=$(date +%s)
        elapsed=$(( current_time - start_time ))
        mins=$(( elapsed / 60 ))
        secs=$(( elapsed % 60 ))
        char_index=$(( i % ${#spinner_chars[@]} ))
        spinner="${spinner_chars[$char_index]}"
        printf "\r${CLEAR_LINE}  ${CYAN}%s${NC} ${DIM}[%d/%d] Scanning %s (%dm %02ds)${NC}" \
          "$spinner" "$scanned" "$total_hosts" "$host_port" "$mins" "$secs"
        i=$(( i + 1 ))
        sleep 0.3
      done

      # Collect exit code
      local tls_exit=0
      wait $TLS_SCAN_PID || tls_exit=$?
      printf "\r${CLEAR_LINE}"

      if [[ $tls_exit -eq 0 ]]; then
        cat "$TLS_SCAN_OUTPUT" >> crypto/tls.jsonl
        tls_success=$(( tls_success + 1 )) || true
        verbose "Successfully scanned $host_port"
      else
        if [[ $tls_exit -eq 124 ]]; then
          tls_timeout=$(( tls_timeout + 1 )) || true
          echo "$host_port" >> crypto/tls_timeouts.txt
          verbose "Timeout scanning $host_port (exit code 124) - timeout: ${SCAN_TIMEOUT}s"
        else
          verbose "Failed to scan $host_port (exit code $EXIT_CODE)"
        fi
      fi
      rm -f "$TLS_SCAN_OUTPUT" "$host_port_file"

    done < live/hosts_ports.txt

    TLS_SCANNED=${HTTPS_COUNT:-0}
    TLS_SUCCESS=$tls_success
    printf "\r${CLEAR_LINE}"
    verbose "TLS scan complete: $TLS_SUCCESS/$TLS_SCANNED HTTPS scanned successfully"
    if [[ "$TLS_SUCCESS" -eq 0 ]] && [[ "$TLS_SCANNED" -gt 0 ]]; then
      progress_complete "HTTPS scanned — all timed out, try -t $((SCAN_TIMEOUT * 3)) or higher." 0
    elif [[ "$TLS_SUCCESS" -lt "$TLS_SCANNED" ]]; then
      progress_complete "HTTPS scanned — $TLS_SUCCESS of $TLS_SCANNED succeeded" "$TLS_SUCCESS"
    else
      progress_complete "HTTPS scanned" "$TLS_SCANNED"
    fi

    if [[ "$tls_timeout" -gt 0 ]]; then
      printf '%b\n' "  ${YELLOW}⚠ $tls_timeout host(s) timed out — see: ${CYAN}crypto/tls_timeouts.txt${NC}"
    fi
  else
    TLS_SCANNED=0
    verbose "Skipping TLS scan - no HTTPS hosts or scanner script not found"
    progress_complete "Skipped (no HTTPS hosts)" 0
  fi

  # Add HTTP-only hosts to tls.jsonl — outside TLS gate, inside HAS_WEB_PORTS
  # Only runs when HAS_WEB_PORTS=1, only writes when http_only.jsonl has data
  if [[ -s live/http_only.jsonl ]]; then
    verbose "Adding $HTTP_SERVICE_COUNT HTTP services as no_tls entries"
    while IFS= read -r line; do
      host=$(echo "$line" | jq -r '.host // empty' 2>/dev/null)
      port=$(echo "$line" | jq -r '.port // empty' 2>/dev/null)
      status_code=$(echo "$line" | jq -r '.status_code // empty' 2>/dev/null)
      title=$(echo "$line" | jq -r '.title // empty' 2>/dev/null)
      webserver=$(echo "$line" | jq -r '.webserver // empty' 2>/dev/null)
      
      safe_port="${port:-0}"; [[ "$safe_port" =~ ^[0-9]+$ ]] || safe_port=0
      safe_status="${status_code:-null}"; [[ "$safe_status" =~ ^[0-9]+$ ]] || safe_status=null
      jq -cn \
        --arg host "$host" \
        --argjson port "$safe_port" \
        --argjson http_status "$safe_status" \
        --arg http_title "${title}" \
        --arg http_server "${webserver}" \
        '{host:$host,port:$port,tls_enabled:false,probe_status:"no_tls",tls_version:"",cipher:"",probe_errors:["http_only"],http_status:$http_status,http_title:$http_title,http_server:$http_server}' \
        >> crypto/tls.jsonl
    done < live/http_only.jsonl
  fi

  TLS_COUNT=$(count_lines crypto/tls.jsonl)
  verbose "Total TLS entries (HTTPS + HTTP): $TLS_COUNT"

  TLS_INPUT="crypto/tls.jsonl"

  else
    # SSH-only (or no scannable ports) mode — skip TLS scanning entirely
    printf '%b\n' "${WHITE}[4/6] TLS/Crypto Analysis${NC}"
    if [[ "$HAS_SSH_PORTS" -eq 1 ]]; then
      printf '%b\n' "  ${DIM}Skipped — SSH-only scan (no web ports)${NC}"
    else
      printf '%b\n' "  ${DIM}Skipped — no web or SSH ports in port list${NC}"
    fi
    touch crypto/tls.jsonl
    TLS_COUNT=0
    TLS_SCANNED=0
    HTTPS_COUNT=0
    HTTP_SERVICE_COUNT=0
    BOTH_COUNT=0
    TRUE_HTTP_ONLY=0
    progress_complete "Skipped (SSH-only)" 0
    TLS_INPUT="crypto/tls.jsonl"
  fi

  # ════════════════════════════════════════════════════════════════════════════
  # Step 5: SSH Service Scan (runs when SSH ports are requested)
  # ════════════════════════════════════════════════════════════════════════════
  run_ssh_scan "$domain"


  # ════════════════════════════════════════════════════════════════════════════
  # ════════════════════════════════════════════════════════════════════════════
  # Step 6: Generate CBOM
  # ════════════════════════════════════════════════════════════════════════════
  printf '%b\n' "${WHITE}[6/6] Generating CBOM${NC}"
  verbose "Starting CBOM (Cryptographic Bill of Materials) generation"
  
  progress_bar 50 100 "Building CBOM..."
  # printf '\n'
  
  CBOM_SCRIPT=""
  [[ -f "$SCRIPT_DIR/pqc_cbom.py" ]] && CBOM_SCRIPT="$SCRIPT_DIR/pqc_cbom.py"
  [[ -z "$CBOM_SCRIPT" ]] && [[ -f "pqc_cbom.py" ]] && CBOM_SCRIPT="pqc_cbom.py"
  
  if [[ -n "$CBOM_SCRIPT" ]]; then
    verbose "Found CBOM script: $CBOM_SCRIPT"
  else
    verbose "CBOM script pqc_cbom.py not found"
  fi
  
  if [[ -n "$CBOM_SCRIPT" ]] && [[ -f "$TLS_INPUT" ]]; then
    if [[ ! -s "$TLS_INPUT" ]]; then
      printf '\r%b' "${CLEAR_LINE}"
      printf '%b\n' "${YELLOW}WARNING: TLS input file is empty, skipping CBOM generation${NC}"
      printf '%b\n' "${DIM}  This usually means all TLS scans timed out. Try increasing the timeout with -t flag.${NC}"
      printf '%b\n' "${DIM}  Example: ./scan.sh $domain -p $SCAN_PORTS -t $((SCAN_TIMEOUT * 3))${NC}"
      verbose "Skipping CBOM generation - TLS input file is empty"
      echo '{"cbom_version":"1.0","total_assets":0,"assets":[]}' > cbom/crypto-bom.json
      echo "# No data available" > cbom/summary.md
      progress_complete "CBOM skipped — no TLS data" 0
    else
      verbose "Running pqc_cbom.py on $TLS_INPUT"
      local cbom_errors
      cbom_errors=$(mktemp)
      _register_tmp "$cbom_errors"
      if python3 "$CBOM_SCRIPT" "$TLS_INPUT" cbom/crypto-bom.json cbom/summary.md > /dev/null 2>"$cbom_errors"; then
        verbose "CBOM generation successful"
        printf '\r%b' "${CLEAR_LINE}"
        progress_complete "CBOM generated" 1
      else
        verbose "CBOM generation failed, creating error placeholder"
        if [[ -s "$cbom_errors" ]]; then
          printf '%b\n' "  ${RED}CBOM error details:${NC}"
          while IFS= read -r err_line; do
            printf '%b\n' "    ${DIM}$err_line${NC}"
          done < "$cbom_errors"
          verbose "CBOM stderr: $(cat "$cbom_errors")"
        fi
        echo '{"cbom_version":"1.0","error":"Generation failed","total_assets":0,"assets":[]}' > cbom/crypto-bom.json
        echo "# CBOM Generation Failed" > cbom/summary.md
        progress_failed "CBOM generation"
      fi
    fi
  else
    verbose "Skipping CBOM generation - no TLS data or script not found"
    echo '{"cbom_version":"1.0","total_assets":0,"assets":[]}' > cbom/crypto-bom.json
    echo "# No data available" > cbom/summary.md
    printf '\r%b' "${CLEAR_LINE}"
    progress_complete "CBOM skipped — no data" 0
  fi
  
  verbose "CBOM saved to cbom/crypto-bom.json and cbom/summary.md"

  fi
  
  # ════════════════════════════════════════════════════════════════════════════
  # Summary
  # ════════════════════════════════════════════════════════════════════════════
  echo ""
  printf '%b\n' "${CYAN}═══════════════════════════════════════════════════════════${NC}"
  printf '%b\n' "${GREEN}Scan Complete!${NC}"
  printf '%b\n' "${CYAN}═══════════════════════════════════════════════════════════${NC}"
  echo ""
  
  # Calculate duration
  SCAN_END_TIME=$(date +%s)
  SCAN_DURATION=$((SCAN_END_TIME - SCAN_START_TIME))
  SCAN_MINUTES=$((SCAN_DURATION / 60))
  SCAN_SECONDS=$((SCAN_DURATION % 60))
  
  verbose "Scan end time: $(format_epoch "$SCAN_END_TIME")"
  verbose "Total duration: ${SCAN_DURATION}s (${SCAN_MINUTES}m ${SCAN_SECONDS}s)"
  
  # Stats
  printf '%b\n' "${WHITE}Statistics:${NC}"
  printf '%b\n' "  Subdomains:        ${CYAN}$SUBDOMAIN_COUNT${NC}"
  printf '%b\n' "  Live domains:      ${CYAN}$LIVE_COUNT${NC}"
  if [[ "$HAS_WEB_PORTS" -eq 1 ]]; then
    printf '%b\n' "  Web services:      ${CYAN}$HTTP_COUNT${NC}"
    if [[ -n "$HTTPS_COUNT" ]] && [[ -n "$HTTP_SERVICE_COUNT" ]]; then
      printf '%b\n' "    ├─ HTTPS:        ${GREEN}$HTTPS_COUNT${NC}"
      if [[ -n "$BOTH_COUNT" ]] && [[ "$BOTH_COUNT" -gt 0 ]]; then
        # Show detailed breakdown only when there are hosts with both
        printf '%b\n' "    ├─ HTTP:         ${YELLOW}$HTTP_SERVICE_COUNT${NC}"
        printf '%b\n' "    ├─ Both:         ${DIM}$BOTH_COUNT (same host, different ports)${NC}"
        if [[ "$TRUE_HTTP_ONLY" -gt 0 ]]; then
          printf '%b\n' "    └─ HTTP-only:    ${RED}$TRUE_HTTP_ONLY (no HTTPS available)${NC}"
        else
          printf '%b\n' "    └─ HTTP-only:    ${DIM}0${NC}"
        fi
      elif [[ "$HTTP_SERVICE_COUNT" -gt 0 ]]; then
        # All HTTP services are HTTP-only
        printf '%b\n' "    └─ HTTP-only:    ${YELLOW}$HTTP_SERVICE_COUNT${NC} (no HTTPS available)"
      fi
    fi
    if [[ "$TLS_SUCCESS" -eq 0 ]] && [[ "$TLS_SCANNED" -gt 0 ]]; then
      printf '%b\n' "  TLS scanned:       ${YELLOW}0 of $TLS_SCANNED (all timed out)${NC}"
    elif [[ "$TLS_SUCCESS" -lt "$TLS_SCANNED" ]]; then
      printf '%b\n' "  TLS scanned:       ${YELLOW}$TLS_SUCCESS of $TLS_SCANNED${NC}"
    else
      printf '%b\n' "  TLS scanned:       ${CYAN}${TLS_SCANNED:-$TLS_COUNT}${NC}"
    fi
  fi
  if [[ "$HAS_SSH_PORTS" -eq 1 ]]; then
    printf '%b\n' "  SSH endpoints:     ${CYAN}$SSH_TOTAL${NC}"
    printf '%b\n' "    ├─ Open:         ${GREEN}$SSH_OPEN${NC}"
    printf '%b\n' "    ├─ Filtered:     ${YELLOW}$SSH_FILTERED${NC}"
    printf '%b\n' "    ├─ Closed:       ${DIM}$SSH_CLOSED${NC}"
    printf '%b\n' "    └─ PQC ready:    ${CYAN}$SSH_PQC_READY${NC}"
  fi
  printf '%b\n' "  Duration:          ${CYAN}${SCAN_MINUTES}m ${SCAN_SECONDS}s${NC}"
  echo ""
  
  # Generate stats JSON using jq for safety
  verbose "Generating scan statistics JSON"
  jq -n \
    --arg domain "$domain" \
    --argjson duration "$SCAN_DURATION" \
    --arg ports "$SCAN_PORTS" \
    --argjson subdomains "$SUBDOMAIN_COUNT" \
    --argjson live "$LIVE_COUNT" \
    --argjson http "$HTTP_COUNT" \
    --argjson https "${HTTPS_COUNT:-0}" \
    --argjson http_services "${HTTP_SERVICE_COUNT:-0}" \
    --argjson both_http_https "${BOTH_COUNT:-0}" \
    --argjson http_only "${TRUE_HTTP_ONLY:-0}" \
    --argjson tls "${TLS_SUCCESS:-0}" \
    --argjson tls_attempted "${TLS_SCANNED:-0}" \
    --argjson ssh_total "$SSH_TOTAL" \
    --argjson ssh_open "$SSH_OPEN" \
    --argjson ssh_filtered "$SSH_FILTERED" \
    --argjson ssh_filtered_hosts "$SSH_FILTERED_HOSTS" \
    --argjson ssh_closed "$SSH_CLOSED" \
    --argjson ssh_pqc_ready "$SSH_PQC_READY" \
    --argjson ssh_scanned "$SSH_SCANNED" \
    '{
      scan_info: {
        domain: $domain,
        duration_seconds: $duration,
        scan_ports: $ports
      },
      statistics: {
        subdomains: $subdomains,
        live_domains: $live,
        web_services: $http,
        https_services: $https,
        http_services: $http_services,
        hosts_with_both: $both_http_https,
        http_only_hosts: $http_only,
        tls_scanned: $tls,
        tls_attempted: $tls_attempted,
        ssh_total: $ssh_total,
        ssh_open: $ssh_open,
        ssh_filtered: $ssh_filtered,
        ssh_filtered_hosts: $ssh_filtered_hosts,
        ssh_closed: $ssh_closed,
        ssh_pqc_ready: $ssh_pqc_ready,
        ssh_scanned: $ssh_scanned
      }
    }' > reports/scan_stats.json
  verbose "Statistics saved to reports/scan_stats.json"
  
  # Output files
  printf '%b\n' "${WHITE}Output Files:${NC}"
  printf '%b\n' "  ${GREEN}→${NC} ${short_output_dir}/cbom/crypto-bom.json"
  printf '%b\n' "     ${DIM}CBOM for dashboard${NC}"
  printf '%b\n' "  ${GREEN}→${NC} ${short_output_dir}/cbom/summary.md"
  printf '%b\n' "     ${DIM}Scan summary${NC}"
  printf '%b\n' "  ${GREEN}→${NC} ${short_output_dir}/reports/scan_stats.json"
  printf '%b\n' "     ${DIM}Scan statistics${NC}"
  if [[ -s crypto/tls_timeouts.txt ]]; then
    printf '%b\n' "  ${YELLOW}→${NC} ${short_output_dir}/crypto/tls_timeouts.txt"
    printf '%b\n' "     ${DIM}Timed-out hosts — rescan with: ./scan.sh $domain -p $SCAN_PORTS -t $((SCAN_TIMEOUT * 2))${NC}"
  fi
  echo ""

  # Show all scans for this domain so runs can be compared
  local domain_scan_dir="${SCRIPT_DIR}/${domain}"
  local scan_count
  scan_count=$(find "$domain_scan_dir" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l | tr -d ' ')
  if [[ "$scan_count" -gt 1 ]]; then
    printf '%b\n' "${WHITE}All scans for ${CYAN}${domain}${WHITE} (newest last):${NC}"
    find "$domain_scan_dir" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort | while IFS= read -r scan_dir; do
      local short_dir="${scan_dir#"$SCRIPT_DIR/"}"
      if [[ "$scan_dir" == "$OUTPUT_DIR" ]]; then
        printf '%b\n' "  ${GREEN}▶${NC} ${CYAN}${short_dir}${NC}  ${DIM}← this scan${NC}"
      else
        printf '%b\n' "  ${DIM}  ${short_dir}${NC}"
      fi
    done
    echo ""
    verbose "  ${DIM}To compare: diff ${domain_scan_dir}/<timestamp1>/cbom/summary.md \\"
    verbose "             ${DIM}              ${domain_scan_dir}/<timestamp2>/cbom/summary.md${NC}"
    echo ""
  fi

  # Next steps
  printf '%b\n' "${WHITE}Next Steps:${NC}"
  printf '%b\n' "  1. View summary:     ${CYAN}cat ${short_output_dir}/cbom/summary.md${NC}"
  printf '%b\n' "  2. Open dashboard:   ${CYAN}https://qubitac.com/dashboard.html${NC}"
  printf '%b\n' "     Upload:           ${YELLOW}${short_output_dir}/cbom/crypto-bom.json${NC}"
  echo ""
  
  verbose "Scan completed successfully"
}

# ═══════════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════════

# Show help
show_help() {
  printf '%b\n' "${WHITE}Usage:${NC} $0 ${CYAN}<domain>${NC} [options]"
  echo ""
  printf '%b\n' "${WHITE}Examples:${NC}"
  echo "  $0 example.com"
  echo "  $0 example.com -p 443,8443"
  echo "  $0 example.com --web"
  echo "  $0 example.com --web --email"
  echo "  $0 example.com --all -t 30 -v"
  echo ""
  printf '%b\n' "${WHITE}Options:${NC}"
  echo "  -p, --port <ports>     Ports to scan, comma-separated (default: 443)"
  echo "  -t, --timeout <secs>   Timeout in seconds (default: 10)"
  echo "  -v, --verbose          Enable verbose output"
  echo "  -h, --help             Show this help message"
  echo "  --version              Show version information"
  echo ""
  printf '%b\n' "${WHITE}Presets:${NC}"
  echo "  --web                  Web ports: 80,443,8080,8443,9443"
  echo "  --email                Email ports: 465,587,993,995"
  echo "  --database             Database ports: 3306,5432,27017,6379"
  echo "  --directory            Directory ports: 636,389"
  echo "                         (Note: 636=LDAPS scanned via TLS; 389=plain LDAP skipped by httpx/TLS)"
  echo "  --vpn                  VPN ports: 1194,443"
  echo "  --ssh                  SSH ports: 22,2222"
  echo "  --all                  All of the above"
  echo ""
  printf '%b\n' "${WHITE}Platform Support:${NC}"
  echo "  Linux                  Supported (run directly)"
  echo "  Mac                    Supported (run directly)"
  echo "  Windows (WSL)          Supported (run inside WSL)"
  echo "  Windows (Git Bash)     Supported (run: bash $0)"
  echo "  Windows (native)       Not supported"
  echo ""
  printf '%b\n' "${WHITE}Windows Setup:${NC}"
  echo "  1. Open PowerShell as Administrator"
  echo "  2. Run: wsl --install"
  echo "  3. Restart your computer"
  echo "  4. Open 'Ubuntu' from Start menu"
  echo "  5. Run: ./scan.sh example.com"
  echo ""
}

# Show version
show_version() {
  printf '%b\n' "${CYAN}QubitAC PQC Crypto-BOM Scanner${NC}"
  printf '%b\n' "Version: ${WHITE}1.0.0${NC}"
  printf '%b\n' "https://qubitac.com"
  echo ""
}

# Parse arguments
DOMAIN=""
PRESET_PORTS=""
SCAN_PORTS_EXPLICIT=0  # set to 1 when -p/--port is explicitly used

# Function to add ports (avoids duplicates)
add_ports() {
  local new_ports="$1"
  if [[ -z "$PRESET_PORTS" ]]; then
    PRESET_PORTS="$new_ports"
  else
    PRESET_PORTS="$PRESET_PORTS,$new_ports"
  fi
  # Deduplicate: split by comma, sort -u, rejoin
  PRESET_PORTS=$(echo "$PRESET_PORTS" | tr ',' '\n' | sort -un | tr '\n' ',' | sed 's/,$//')
}

print_banner

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      show_help
      exit 0
      ;;
    --version)
      show_version
      exit 0
      ;;
    -p|--port)
      if [[ -z "${2:-}" ]]; then
        printf '%b\n' "${RED}Error: --port requires a value${NC}"
        exit 1
      fi
      SCAN_PORTS="$2"
      SCAN_PORTS_EXPLICIT=1
      shift 2
      ;;
    --web)
      add_ports "80,443,8080,8443,9443"
      shift
      ;;
    --email)
      add_ports "465,587,993,995"
      shift
      ;;
    --database)
      add_ports "3306,5432,27017,6379"
      shift
      ;;
    --directory)
      add_ports "636,389"
      shift
      ;;
    --vpn)
      add_ports "1194,443"
      shift
      ;;
    --ssh)
      add_ports "22,2222"
      shift
      ;;
    --all)
      add_ports "80,443,8080,8443,9443,465,587,993,995,3306,5432,27017,6379,636,389,1194,22,2222"
      shift
      ;;
    -t|--timeout)
      if [[ -z "${2:-}" ]]; then
        printf '%b\n' "${RED}Error: --timeout requires a value${NC}"
        exit 1
      fi
      SCAN_TIMEOUT="$2"
      shift 2
      ;;
    -v|--verbose)
      VERBOSE=1
      shift
      ;;
    -*)
      printf '%b\n' "${RED}Error: Unknown option '${1}'${NC}"
      echo ""
      show_help
      exit 1
      ;;
    *)
      if [[ -z "$DOMAIN" ]]; then
        DOMAIN="$1"
      else
        printf '%b\n' "${RED}Error: Unexpected argument '${1}'${NC}"
        echo ""
        show_help
        exit 1
      fi
      shift
      ;;
  esac
done

# If presets were used, apply them (unless -p was explicitly set by the user)
if [[ -n "$PRESET_PORTS" && "$SCAN_PORTS_EXPLICIT" -eq 0 ]]; then
  SCAN_PORTS="$PRESET_PORTS"
elif [[ -n "$PRESET_PORTS" && "$SCAN_PORTS_EXPLICIT" -eq 1 ]]; then
  printf '%b\n' "${YELLOW}Warning: --port/-p overrides preset flags (--web/--ssh/etc). Preset ports ignored.${NC}"
  printf '%b\n' "${DIM}  Using explicit ports: $SCAN_PORTS${NC}"
  echo ""
fi

# Check if domain is provided
if [[ -z "$DOMAIN" ]]; then
  show_help
  exit 1
fi

# Classify ports into SSH vs Web categories (after domain confirmed present)
classify_ports

# Validate and run
verbose "Script started with domain: $DOMAIN"
verbose "SCRIPT_DIR=$SCRIPT_DIR"

ROOT_DOMAIN=$(validate_domain "$DOMAIN")

printf '%b\n' "${WHITE}Target:${NC}  ${CYAN}$ROOT_DOMAIN${NC}"
printf '%b\n' "${WHITE}Ports:${NC}   ${CYAN}$SCAN_PORTS${NC}"
if [[ "$HAS_WEB_PORTS" -eq 1 ]] && [[ "$HAS_SSH_PORTS" -eq 1 ]]; then
  printf '%b\n' "${WHITE}Mode:${NC}    ${CYAN}Web + SSH${NC} ${DIM}(web:$WEB_PORTS | ssh:$SSH_PORTS_RESOLVED)${NC}"
elif [[ "$HAS_SSH_PORTS" -eq 1 ]]; then
  printf '%b\n' "${WHITE}Mode:${NC}    ${CYAN}SSH-only${NC} ${DIM}(httpx/TLS scan skipped)${NC}"
elif [[ "$HAS_WEB_PORTS" -eq 1 ]]; then
  printf '%b\n' "${WHITE}Mode:${NC}    ${CYAN}Web/TLS${NC}"
else
  printf '%b\n' "${WHITE}Mode:${NC}    ${YELLOW}No scannable ports${NC} ${DIM}(all ports are DB/VPN/LDAP — nothing to scan)${NC}"
fi
printf '%b\n' "${WHITE}Timeout:${NC} ${CYAN}${SCAN_TIMEOUT}s${NC}"
echo ""

check_dependencies
run_scan "$ROOT_DOMAIN"

printf '%b\n' "${GREEN}Done.${NC}"
verbose "Script finished"
