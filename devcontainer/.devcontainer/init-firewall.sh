#!/usr/bin/env bash
# Default-deny egress firewall: only DNS, loopback, and the hosts below on 443.
set -euo pipefail
IFS=$'\n\t'

ALLOWED_DOMAINS=(
  # GitHub Copilot CLI (https://docs.github.com/en/copilot/reference/copilot-allowlist-reference)
  api.githubcopilot.com
  api.individual.githubcopilot.com
  api.business.githubcopilot.com
  api.enterprise.githubcopilot.com
  telemetry.individual.githubcopilot.com
  copilot-proxy.githubusercontent.com
  origin-tracker.githubusercontent.com
  copilot-telemetry.githubusercontent.com
  github.githubassets.com
  avatars.githubusercontent.com
  default.exp-tas.com
  # NuGet restore
  api.nuget.org
  globalcdn.nuget.org
  # VS Code server and extensions
  update.code.visualstudio.com
  marketplace.visualstudio.com
  vscode.blob.core.windows.net
)

fail() {
  echo "init-firewall: $*" >&2
  exit 1
}

add_cidr() {
  [[ "$1" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?$ ]] || fail "invalid IPv4 range '$1'"
  ipset add -exist allowed-domains "$1"
}

reset_rules() {
  iptables -P INPUT ACCEPT
  iptables -P OUTPUT ACCEPT
  iptables -P FORWARD ACCEPT
  iptables -F
  iptables -X
  ipset destroy allowed-domains 2>/dev/null || true
  ipset create allowed-domains hash:net
}

allow_github_ranges() {
  local meta
  meta=$(curl -fsS --max-time 15 https://api.github.com/meta) ||
    fail "could not fetch https://api.github.com/meta; check network access"
  local cidr
  while read -r cidr; do
    add_cidr "$cidr"
  done < <(jq -r '(.web + .api + .git)[] | select(contains(":") | not)' <<<"$meta" | sort -u)
}

allow_domains() {
  local domain ip ips
  for domain in "${ALLOWED_DOMAINS[@]}"; do
    ips=$(dig +short +time=5 +tries=2 A "$domain" | grep -E '^[0-9.]+$' || true)
    if [[ -z "$ips" ]]; then
      echo "init-firewall: warning: no A records for '$domain', not allowlisted" >&2
      continue
    fi
    while read -r ip; do
      add_cidr "$ip"
    done <<<"$ips"
  done
}

apply_policy() {
  local resolver
  iptables -A INPUT -i lo -j ACCEPT
  iptables -A OUTPUT -o lo -j ACCEPT
  iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
  iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
  while read -r resolver; do
    iptables -A OUTPUT -d "$resolver" -p udp --dport 53 -j ACCEPT
    iptables -A OUTPUT -d "$resolver" -p tcp --dport 53 -j ACCEPT
  done < <(awk '/^nameserver/ && $2 ~ /^[0-9.]+$/ {print $2}' /etc/resolv.conf)
  iptables -A OUTPUT -p tcp --dport 443 -m set --match-set allowed-domains dst -j ACCEPT
  iptables -A OUTPUT -j REJECT --reject-with icmp-admin-prohibited
  iptables -P INPUT DROP
  iptables -P FORWARD DROP
  iptables -P OUTPUT DROP

  if ip6tables -L >/dev/null 2>&1; then
    ip6tables -F
    ip6tables -A INPUT -i lo -j ACCEPT
    ip6tables -A OUTPUT -o lo -j ACCEPT
    ip6tables -P INPUT DROP
    ip6tables -P FORWARD DROP
    ip6tables -P OUTPUT DROP
  else
    echo "init-firewall: warning: ip6tables unavailable; IPv6 egress not filtered" >&2
  fi
}

verify() {
  if curl -fsS --max-time 5 https://example.com >/dev/null 2>&1; then
    fail "verification failed: https://example.com is reachable"
  fi
  curl -fsS --max-time 10 https://api.github.com/zen >/dev/null ||
    fail "verification failed: https://api.github.com is unreachable"
  echo "init-firewall: egress restricted to allowlist"
}

main() {
  [[ $EUID -eq 0 ]] || fail "must run as root (sudo /usr/local/bin/init-firewall.sh)"
  reset_rules
  allow_github_ranges
  allow_domains
  apply_policy
  verify
}

main "$@"
