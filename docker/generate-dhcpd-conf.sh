#!/usr/bin/env bash

DEFAULT_ROUTE='default'
DEFAULT_DNS_IPS=("8.8.8.8" "8.8.4.4")


DHCP_CONF_TEMPLATE='
start %s
end   %s

# avoid dhcpd complaining that we have
# too many addresses
max_leases 1

interface %s

option dns      %s
option router   %s
option subnet   %s
option hostname %s
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

# Function to generate the DHCP configuration
generate_conf() {
  local intf_name="$1"
  local dns_ips=("$2")
  
  # Get the default route
  droute=$(default_route)
  """
  Generate a DHCP configuration based on the provided interface name and DNS IPs.
  
  This script uses the `ip` command to get the default route, and then extracts the gateway IP address and device name from it. It then uses these values to generate a DHCP configuration template using Jinja-style formatting.
  
  Parameters:
    intf_name (str): The name of the network interface to configure.
    dns_ips (list): A list of DNS server IPs to include in the configuration.
  
  Returns:
    str: The generated DHCP configuration as a string.
  """
  
  if [ -z "$droute" ]; then
    echo "Error: No default route found" >&2
    exit 1
  fi

  gateway=$(echo "$droute" | jq -r '.gateway')
  dev=$(echo "$droute" | jq -r '.dev')

    host_addr=$(addr_of "$dev")
  host_ip=$(echo "$host_addr" | cut -d '/' -f1)
  subnet=$(ipcalc -n "$host_addr" | grep Netmask | awk '{ print $2 }')

  printf "$DHCP_CONF_TEMPLATE" "$host_ip" "$host_ip" "$intf_name" "${dns_ips[*]}" "$gateway" "$subnet" "$(hostname)"
}


intf_name="$1"
dns_ips=("${@:2}")

if [ -z "$intf_name" ]; then
  echo "Usage: $0 <interface> [dns_ips...]" >&2
  exit 1
fi

if [ ${#dns_ips[@]} -eq 0 ]; then
  dns_ips=("${DEFAULT_DNS_IPS[@]}")
fi

generate_conf "$intf_name" "${dns_ips[@]}"
