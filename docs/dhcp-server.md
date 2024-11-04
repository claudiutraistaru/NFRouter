# Setting up a DHCP Server

This guide provides the necessary commands to configure a DHCP server on a custom router, with IP range and DNS settings specific to a LAN network on subnet `10.0.0.0/24`.

## Prerequisites

- Ensure you have access to the router`s shell interface.
- Verify that interface `eth1` is the intended LAN interface.

## Configuration Steps

### Step 1: Configure DHCP Server for LAN Subnet

1. **Set the DHCP Server for `lan` subnet**  
   Define the LAN subnet `10.0.0.0/24` for the DHCP server configuration.

   ```shell
   set service dhcp-server shared-network-name lan subnet 10.0.0.0/24
   ```

2. **Configure the Default Router IP**  
   Set the default gateway (router) for clients on the LAN subnet to `10.0.0.1`.

   ```shell
   set service dhcp-server shared-network-name lan subnet 10.0.0.0/24 default-router 10.0.0.1
   ```

3. **Set the DNS Server**  
   Configure `8.8.8.8` as the DNS server for DHCP clients.

   ```shell
   set service dhcp-server shared-network-name lan subnet 10.0.0.0/24 dns-server 8.8.8.8
   ```

4. **Define the Lease Time**  
   Specify a lease time of `86400` seconds (24 hours) for IP addresses.

   ```shell
   set service dhcp-server shared-network-name lan subnet 10.0.0.0/24 lease 86400
   ```

5. **Specify DHCP IP Range**  
   Set the start and stop IP addresses for DHCP allocation within the subnet.

   - Start: `10.0.0.10`
   - Stop: `10.0.0.50`

   ```shell
   set service dhcp-server shared-network-name lan subnet 10.0.0.0/24 start 10.0.0.10
   set service dhcp-server shared-network-name lan subnet 10.0.0.0/24 stop 10.0.0.50
   ```

### Step 2: Enable the DHCP Server

Enable the DHCP server service globally to make it active.

```shell
set service dhcp-server enabled
```

### Step 3: Configure Interface IP Address

Assign the IP address `10.0.0.1/24` to interface `eth1` to match the DHCP subnet configuration.

```shell
set interface eth1 address 10.0.0.1/24
```
