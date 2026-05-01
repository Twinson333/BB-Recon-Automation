#!/usr/bin/env bash
set -euo pipefail

echo "[*] Starting bug bounty recon tool installation..."

# -----------------------------
# Helpers
# -----------------------------
need_cmd() {
  command -v "$1" >/dev/null 2>&1
}

append_path_if_missing() {
  local shell_rc="$1"
  local line='export PATH="$PATH:$HOME/go/bin"'

  if [ -f "$shell_rc" ]; then
    if ! grep -Fq "$line" "$shell_rc"; then
      echo "$line" >> "$shell_rc"
      echo "[+] Added ~/go/bin to PATH in $shell_rc"
    fi
  else
    echo "$line" >> "$shell_rc"
    echo "[+] Created $shell_rc and added ~/go/bin to PATH"
  fi
}

install_go() {
  echo "[*] Go not found. Installing Go..."

  local GO_VERSION="1.24.2"
  local GO_TARBALL="go${GO_VERSION}.linux-amd64.tar.gz"
  local GO_URL="https://go.dev/dl/${GO_TARBALL}"

  cd /tmp
  curl -LO "$GO_URL"
  sudo rm -rf /usr/local/go
  sudo tar -C /usr/local -xzf "$GO_TARBALL"
  rm -f "$GO_TARBALL"

  export PATH="$PATH:/usr/local/go/bin"
  echo "[+] Go installed: $(go version)"
}

install_pkg() {
  local name="$1"
  local pkg="$2"

  echo "[*] Installing $name ..."
  if go install -v "$pkg"; then
    echo "[+] Installed $name"
  else
    echo "[!] Failed to install $name"
  fi
}

# -----------------------------
# Basic OS packages
# -----------------------------
if need_cmd apt-get; then
  echo "[*] Installing required system packages with apt..."
  sudo apt-get update
  sudo apt-get install -y curl wget git unzip tar build-essential python3 python3-pip jq
else
  echo "[!] apt-get not found. Install curl, git, unzip, tar, jq manually if missing."
fi

# -----------------------------
# Install Go if missing
# -----------------------------
if ! need_cmd go; then
  install_go
else
  echo "[+] Go already installed: $(go version)"
fi

export PATH="$PATH:$HOME/go/bin:/usr/local/go/bin"

# -----------------------------
# Persist PATH
# -----------------------------
append_path_if_missing "$HOME/.bashrc"
append_path_if_missing "$HOME/.zshrc"

# -----------------------------
# Install recon tools
# -----------------------------
install_pkg "subfinder"   "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
install_pkg "httpx"       "github.com/projectdiscovery/httpx/cmd/httpx@latest"
install_pkg "katana"      "github.com/projectdiscovery/katana/cmd/katana@latest"
install_pkg "naabu"       "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
install_pkg "dnsx"        "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
install_pkg "nuclei"      "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
install_pkg "assetfinder" "github.com/tomnomnom/assetfinder@latest"
install_pkg "waybackurls" "github.com/tomnomnom/waybackurls@latest"
install_pkg "gau"         "github.com/lc/gau/v2/cmd/gau@latest"
install_pkg "gauplus"     "github.com/bp0lr/gauplus@latest"
install_pkg "hakrawler"   "github.com/hakluke/hakrawler@latest"
install_pkg "gowitness"   "github.com/sensepost/gowitness@latest"

# -----------------------------
# Non-Go tools guidance
# -----------------------------
echo
echo "[*] Some tools may require separate installation:"
echo "    - amass"
echo "    - findomain"
echo "    - chaos"
echo "    - arjun"
echo
echo "[*] Installing Python-based Arjun..."
if need_cmd pip3; then
  pip3 install --user arjun || echo "[!] Failed to install Arjun via pip3"
else
  echo "[!] pip3 not found, skipping Arjun"
fi

# -----------------------------
# Optional: install amass via snap if available
# -----------------------------
if ! need_cmd amass; then
  if need_cmd snap; then
    echo "[*] Trying to install amass via snap..."
    sudo snap install amass || echo "[!] Failed to install amass via snap"
  else
    echo "[!] snap not found. Install amass manually."
  fi
fi

# -----------------------------
# Optional: nuclei templates update
# -----------------------------
if need_cmd nuclei; then
  echo "[*] Updating nuclei templates..."
  nuclei -update-templates || echo "[!] Failed to update nuclei templates"
fi

# -----------------------------
# Final check
# -----------------------------
echo
echo "[*] Final tool check:"
TOOLS=(
  subfinder assetfinder amass findomain chaos
  httpx waybackurls gau gauplus katana arjun
  naabu dnsx gowitness hakrawler nuclei
)

for tool in "${TOOLS[@]}"; do
  if need_cmd "$tool"; then
    echo "[+] $tool"
  else
    echo "[-] $tool"
  fi
done

echo
echo "[+] Installation phase complete."
echo "[*] Restart your shell or run:"
echo '    source ~/.bashrc'
echo
echo "[*] Your Go binaries should be in:"
echo "    $HOME/go/bin"