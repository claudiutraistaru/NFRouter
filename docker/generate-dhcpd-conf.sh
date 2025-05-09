#!/usr/bin/env bash

DEFAULT_ROUTE='default'
DEFAULT_DNS_IPS=("8.8.8.8" "8.8.4.4")

DHCP_CONF_TEMPLATE='
start %s
end   %s

# avoid dhcpd complaining that we have
# too many addresses
max_leases 2

interface %s

option dns      %s
option router   %s
option subnet   %s
option hostname %s

# Static IP assignments
static_lease %s %s
static_lease %s %s
'

default_route() {
  routes=$(ip -json route)
  echo "$routes" | jq -c '.[] | select(.dst == "'$DEFAULT_ROUTE'")'
}

addr_of() {
  local dev="$1"
  addrs=$(ip -json addr)
  
  addr=$(echo "$addrs" | jq -c '.[] | select(.ifname == "'$dev'")')
  if [ -z "$addr" ]; then
    echo "Error: Device $dev not found" >&2
    exit 1
  fi
  
  addr_info=$(echo "$addr" | jq -c '.addr_info[0]')
  if [ -z "$addr_info" ]; then
    echo "Error: No address info for device $dev" >&2
    exit 1
  fi
  
  local_addr=$(echo "$addr_info" | jq -r '.local')
  prefixlen=$(echo "$addr_info" | jq -r '.prefixlen')
  
  echo "$local_addr/$prefixlen"
}

generate_conf() {
  local intf_name="$1"
  local dns_ips=("$2")
  local ip_address="$3"
  
  droute=$(default_route)
  
  if [ -z "$droute" ]; then
    echo "Error: No default route found" >&2
    exit 1
  fi

  gateway=$(echo "$droute" | jq -r '.gateway')
  dev=$(echo "$droute" | jq -r '.dev')

  host_addr=$(addr_of "$dev")
  host_ip=$(echo "$host_addr" | cut -d '/' -f1)
  subnet=$(ipcalc -n "$host_addr" | grep Netmask | awk '{ print $2 }')

  printf "$DHCP_CONF_TEMPLATE" "$host_ip" "$host_ip" "$intf_name" "${dns_ips[*]}" "$gateway" "$subnet" "$(hostname)" \
    "52:54:00:12:34:56" "192.168.10.10" \
    "52:54:00:12:34:57" "192.168.10.11"
}

intf_name="$1"
dns_ips=("${@:2}")
ip_address=${QEMU_IP}
if [ -z "$intf_name" ]; then
  echo "Usage: $0 <interface> [dns_ips...]" >&2
  exit 1
fi

if [ ${#dns_ips[@]} -eq 0 ]; then
  dns_ips=("${DEFAULT_DNS_IPS[@]}")
fi

generate_conf "$intf_name" "${dns_ips[@]}" "$ip_address"