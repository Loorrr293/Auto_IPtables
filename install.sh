#!/usr/bin/env bash
set -euo pipefail

LIST_URL="https://raw.githubusercontent.com/Loorrr293/blocklist/main/blocklist.txt"

apt-get update -y
apt-get install -y nftables curl

cat > /usr/local/sbin/update-blocklist-nft.sh <<'SH'
#!/usr/bin/env bash
set -euo pipefail
URL="${1:?Usage: update-blocklist-nft.sh <URL>}"

nft add table inet blocklist 2>/dev/null || true
nft add set inet blocklist v4 '{ type ipv4_addr; flags interval; }' 2>/dev/null || true
nft add set inet blocklist v6 '{ type ipv6_addr; flags interval; }' 2>/dev/null || true
nft add chain inet blocklist input '{ type filter hook input priority -300; policy accept; }' 2>/dev/null || true
nft list chain inet blocklist input | grep -q '@v4' || nft add rule inet blocklist input ip saddr @v4 drop
nft list chain inet blocklist input | grep -q '@v6' || nft add rule inet blocklist input ip6 saddr @v6 drop

tmp="$(mktemp)"; cleaned="$(mktemp)"; v4="$(mktemp)"; v6="$(mktemp)"; nf="$(mktemp)"
trap 'rm -f "$tmp" "$cleaned" "$v4" "$v6" "$nf"' EXIT

curl -fsSL "$URL" > "$tmp"
sed 's/#.*//g' "$tmp" | tr -s ' \t\r' '\n' | sed '/^$/d' | sort -u > "$cleaned"
grep -v ':' "$cleaned" > "$v4" || true
grep ':' "$cleaned"   > "$v6" || true

{
  echo "flush set inet blocklist v4"
  echo "flush set inet blocklist v6"
  if [[ -s "$v4" ]]; then echo -n "add element inet blocklist v4 { "; paste -sd, "$v4"; echo " }"; fi
  if [[ -s "$v6" ]]; then echo -n "add element inet blocklist v6 { "; paste -sd, "$v6"; echo " }"; fi
} > "$nf"

nft -f "$nf"
SH

chmod +x /usr/local/sbin/update-blocklist-nft.sh

cat > /etc/systemd/system/blocklist-update.service <<UNIT
[Unit]
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/update-blocklist-nft.sh ${LIST_URL}
UNIT

cat > /etc/systemd/system/blocklist-update.timer <<'TIMER'
[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
TIMER

systemctl daemon-reload
systemctl enable --now blocklist-update.service
systemctl enable --now blocklist-update.timer

nft list table inet blocklist >/dev/null
echo OK
