# Configuring Firewall Rules and DNAT on Custom Router

This guide provides the necessary commands to configure firewall rules and DNAT (Destination Network Address Translation) on a custom router, along with an explanation of each command used.

## Configuration Steps

### Configure Firewall Rules for Interface `eth0`

** Enable ip forwarfing
```shell
set system ipforwarding enabled
```

**Attach Firewall Rule Set to Interface**  
Attach the firewall rule set `test-rule-set` to the `in` direction of interface `eth0`.

```shell
set interface eth0 firewall in test-rule-set
```

**Define Firewall Rules**

- Accept TCP traffic from source `192.168.0.1` to destination `192.168.0.2` on port `80`.

  ```shell
  set firewall test-rule-set action accept source 192.168.0.1 destination 192.168.0.2 protocol tcp port 80
  ```

- Accept TCP traffic to destination `192.168.0.2` on port `443`.

  ```shell
  set firewall test-rule-set action accept destination 192.168.0.2 protocol tcp port 443
  ```

- Accept UDP traffic from source `192.168.0.3` on port `53`.

  ```shell
  set firewall test-rule-set action accept source 192.168.0.3 protocol udp port 53
  ```

- Accept all traffic from source `10.0.0.22`.

  ```shell
  set firewall test-rule-set action accept source 10.0.0.22
  ```

- Accept ICMP traffic from source `192.168.0.4` to destination `192.168.0.5`.

  ```shell
  set firewall test-rule-set action accept source 192.168.0.4 destination 192.168.0.5 protocol icmp
  ```

- Accept TCP traffic on port `22` (SSH).

  ```shell
  set firewall test-rule-set action accept protocol tcp port 22
  ```

- Accept all traffic from source `192.168.0.6`.

  ```shell
  set firewall test-rule-set action accept source 192.168.0.6
  ```

- Accept all traffic to destination `192.168.0.7`.

  ```shell
  set firewall test-rule-set action accept destination 192.168.0.7
  ```

**Set Default Policy to Drop**  
Set the default policy for the firewall rule set to `drop`, ensuring that any traffic not explicitly allowed by the rules above is denied.

```shell
set firewall test-rule-set default-policy drop
```

### Configure DNAT with Firewall Rules

**Attach Interface to Zone**  
Attach the interface to a zone. This is essential for configuring NAT rules within specific network zones.

```shell
set interface <interface> zone <zonename>
```

**Enable NAT Masquerade**  
Enable NAT type `MASQUERADE` from a source zone to a destination zone to allow outbound connections.

```shell
set nat masquerade from <zonename> to <zonename>
```

**Configure Source NAT (SNAT)**

- **SNAT for Zone to Public IP**  
  Enable Source NAT (SNAT) from a zone to a public IP to translate private IP addresses to the public address.

  ```shell
  set nat snat from zone <zonename> to <public_ip>
  ```

- **SNAT for Specific Private IP to Public IP**  
  Enable Source NAT (SNAT) for a specific private IP in a zone to a public IP.

  ```shell
  set nat snat from zone <zonename> <private_ip> to <public_ip>
  ```

**Configure Destination NAT (DNAT)**

Enable Destination NAT (DNAT) to forward traffic from a public IP and port to a private IP and port. This is useful for forwarding incoming requests to internal services.

```shell
set nat dnat from <public_ip> <public_port> to <private_ip> <private_port>
```

Example:

- Forward TCP traffic from public IP `100.100.100.2` on port `2000` to private IP `10.1.0.46` on port `2000`.

  ```shell
  set nat dnat from 100.100.100.2 2000 to 10.1.0.46 2000
  ```

**Define Additional Firewall Rules for DNAT**

- Reject TCP traffic from any source (`0.0.0.0/0`) to destination `10.1.0.46` on port `2000`.

  ```shell
  set firewall test action reject source 0.0.0.0/0 destination 10.1.0.46 protocol tcp port 2000
  ```

**Set Default Policy for Firewall**  
Set the default policy for the firewall rule set to `accept`, ensuring any traffic not explicitly blocked is allowed.

```shell
set firewall test default-policy accept
```
