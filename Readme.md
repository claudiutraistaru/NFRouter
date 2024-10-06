# NFRouter (alpha version)
![image](docs/images/NFRouter.png)

## Table of Contents
1. [Provisional Roadmap](#provisional-roadmap)
2. [What is NFRouter](#what-is-NFRouter)
3. [How to install](#how-to-install)
4. [Command Reference](#command-reference)
   - [Firewall Commands](#firewall-commands)
   - [Interface Commands](#interface-commands)
   - [NAT Commands](#nat-commands)
   - [Routing Commands](#routing-commands)
   - [DHCP Server Commands](#dhcp-server-commands)
   - [IP Forwarding Commands](#ip-forwarding-commands)
5. [Scenario: Router-on-a-Stick with Firewall to Allow ICMP](#scenario-setting-up-router-on-a-stick-with-firewall-to-allow-icmp)


---

> [!WARNING]
> Please keep in mind that NFRouter is still an Alpha version and under active development and therefore full backward compatibility  is not guaranteed before reaching v1.0.0.

## Provisional Roadmap

- [x] Current Configuration Saving
- [x] Current Configuration Load at Startup
- [x] Very Basic Interface Setup Options
- [x] Very Basic Firewall Setup Options
- [x] Very Basic Network Address Translation (NAT) Options
- [x] Very Basic VLAN Support
- [ ] Add Contribution Guidelines , pull requests will be handled
- [ ] Cleanup code (debug will be handled how it should be :))
- [ ] Automated testing for commands and config, without being executed on Linux (in progress)
- [ ] Write proper documentation
- [ ] Improve command line help and auto-complete
- [ ] Advanced Interface Setup Options
- [ ] Advanced Firewall Setup Options
- [ ] Advanced Network Address Translation (NAT) Options
- [ ] Advanced VLAN Support
- [ ] ISO Automated Build Process (in progress)
- [ ] Docker-Based Integration Testing (in progress)
- [ ] VPN Setup (e.g., OpenVPN, WireGuard)
- [ ] VPN-Based Firewall Rules
- [ ] Dynamic Routing Protocols (FRRouting)
- [ ] Role-Based Access Control (RBAC)
- [ ] High Availability (HA) and Redundancy
- [ ] Monitoring and Logging (e.g., syslog, nftables logs)
- [ ] Optional Web-Based Management UI
- [ ] All that was not added in the roadmap :)

## What is NFRouter  
NFRouter is an open-source network routing application in RUST designed to simplify network configuration and management. It is available both as a single executable file and as a ready-to-install ISO image (the ISO image will be available) for x86 and ARM architectures. 
NFRouter runs on Alpine Linux, which serves as the underlying system layer, using Linux's robust networking capabilities for routing and network management but providing a unified configuration console.

Its main features include:

**Command line suggestions and auto-complete**: NFRouter main component is the command line utility which tries to mimic other vendors capabilities like advanced help, auto-complete and next word suggestions.

**Multiple Installation Options**: Use NFRouter as a standalone executable requiring no complex installation, at the moment only Alpine Linux is supported, or install it via the provided ISO image suitable for both x86 and ARM systems.

**Command-Line Interface (CLI)**: Operated through a CLI that supports only predefined configuration commands, making it straightforward to use and reducing the potential for errors.

**Easy Upgrades**: Upgrading in our vision will be a simple—just replace the existing executable with the new version, minimizing downtime.

**JSON Configuration Files**: Configurations are saved in JSON format, making them easily reproducible and portable. This facilitates straightforward backups and sharing.

**Unified Configuration**: All settings are consolidated into a single configuration file, simplifying management and ensuring consistency.

Being open-source, NFRouter encourages community contributions and allows users to customize the application to fit their specific needs.

## How to install
There are 2 ways to download and install it:

1. Direct download of the applciation , which is one executable only , the testst are made on Alpine Linux :
- install required packages (at the moment is not handled in the application) frr and dnsmasq
manually create a /config folder

2. Use the prebuilt iso, which is an Alpine linux version with a custom install script (At the moment there is no offline method of install, some alpine packages need to be downloaded from the internet)
- login as root (no password)
- start /media/cdrom/install_nfrouter.sh
- follow the prompts
- reboot
- remove cdrom
- make sur you booted from hdd
- start nfrouter command line (./nfrouter in shell after login), the settings that are in the config folder are applied at boot automattically

## Command Reference

### Firewall Commands

- **Set Default Firewall Policy**
  
  ```
  set firewall <rule-set-name> default-policy <accept|drop|reject>
  ```
  Sets the default policy for a firewall rule set.

  Example:
  ```
  set firewall lan default-policy drop
  ```

- **Add Firewall Rule**

  ```
  set firewall <rule-set-name> <rule-number> action <accept|drop|reject> source <ip-address> destination <ip-address> protocol <tcp|udp|icmp> port <port-number>
  ```
  Adds a rule to the firewall with specified parameters.

  Example:
  ```
  set firewall lan 10 action accept source 192.168.1.0/24 destination 10.0.0.1 protocol tcp port 80
  ```

- **Insert Firewall Rule Before or After an Existing Rule**

  ```
  set firewall <rule-set-name> insert-before <rule-number> action <accept|drop|reject> source <ip-address> destination <ip-address> protocol <tcp|udp|icmp> port <port-number>
  ```

  ```
  set firewall <rule-set-name> insert-after <rule-number> action <accept|drop|reject> source <ip-address> destination <ip-address> protocol <tcp|udp|icmp> port <port-number>
  ```

  Example:
  ```
  set firewall lan insert-before 15 action drop source 192.168.2.0/24 destination 10.0.0.2
  ```

- **Apply Firewall to an Interface**

  ```
  set interface <interface> firewall <in|out> <rule-set-name>
  ```

  Example:
  ```
  set interface eth0 firewall in lan
  ```

---

### Interface Commands

- **Set IP Address**

  - Static IP:
    
    ```
    set interface <interface> address <ip_address>
    ```

    Example:
    ```
    set interface eth0 address 192.168.1.10/24
    ```

  - DHCP:
    
    ```
    set interface <interface> address dhcp
    ```

    Example:
    ```
    set interface eth0 address dhcp
    ```

- **Set Interface Speed, MTU, and Duplex Mode**

  - Speed:
    
    ```
    set interface <interface> options speed <speed>
    ```

  - MTU:
    
    ```
    set interface <interface> options mtu <mtu>
    ```

  - Duplex Mode:
    
    ```
    set interface <interface> options duplex <full|half|auto>
    ```

  Example:
  ```
  set interface eth0 options speed 1000
  set interface eth0 options mtu 1500
  set interface eth0 options duplex full
  ```

---

### NAT Commands

- **Assign interface to zone**
    ```
    set interface eth0 zone <zonename>
    ```

    Example:
    ```
    set interface eth0 zone external
    set interface eth1 zone internal
    ```
- **Enable NAT Masquerade**

  ```
  set nat masquerade from <zonename> to <zonename>
  ```

  Example:
  ```
  set nat masquerade from internal to external
  ```

---

### Routing Commands

- **Add or Modify Routes**

  ```
  set routes <destination> via <gateway|interface>
  ```

  Example:
  ```
  set routes 0.0.0.0/0 via 192.168.1.1
  ```

---

### DHCP Server Commands

- **Enable DHCP Server**

  ```
  set service dhcp-server enabled
  ```

- **Configure DHCP Server Options**

  ```
  set service dhcp-server shared-network-name <network-name> subnet <subnet-ip>/<prefix-length> start <start-ip> stop <end-ip> default-router <gateway-ip> dns-server <dns-server-ip> domain-name <domain-name> lease <lease-time>
  ```

  Example:
  ```
  set service dhcp-server shared-network-name lan subnet 192.168.1.0/24 start 192.168.1.100 stop 192.168.1.200 default-router 192.168.1.1 dns-server 8.8.8.8 lease 86400
  ```

---

### IP Forwarding Commands

- **Enable IP Forwarding**

  ```
  set system ipforwarding <enabled|disabled>
  ```

  Example:
  ```
  set system ipforwarding enabled
  ```

---


### Scenario: Setting Up Router-on-a-Stick with Firewall to Allow ICMP

This scenario demonstrates how to configure a Router-on-a-Stick setup using VLANs, and apply firewall rules to allow only ICMP (ping) traffic between VLANs. 

#### Network Topology:
- Router Interface: `eth0`
- VLANs: 
  - VLAN 10 (`192.168.10.0/24`) for subnet A
  - VLAN 20 (`192.168.20.0/24`) for subnet B
- Goal: 
  - Set up inter-VLAN routing
  - Create firewall rules to allow only ICMP traffic between the two VLANs

---

### Step 1: Set Up VLAN Interfaces on the Router (Router-on-a-Stick)

Create VLAN interfaces `eth0.10` and `eth0.20` on the physical interface `eth0` to represent the two VLANs.

```bash
set interface eth0 vlan 10 ip 192.168.10.1/24
set interface eth0 vlan 20 ip 192.168.20.1/24
```

- This configures `VLAN 10` with an IP address of `192.168.10.1` and `VLAN 20` with an IP address of `192.168.20.1`.

---

### Step 2: Enable IP Forwarding

To allow routing between VLANs, enable IP forwarding on the router:

```bash
set system ip forwarding enabled
```

This ensures that traffic between VLANs is forwarded by the router.

---

### Step 3: Configure Firewall Rule Set for VLAN Traffic

Create a firewall rule set named `vlan-firewall` to manage traffic between VLANs. Initially, set the default policy to `drop` for security, then allow ICMP traffic specifically.

#### Step 3.1: Create a Rule Set and Set Default Policy

```bash
set firewall vlan-firewall default-policy drop
```

This sets the default behavior to drop all traffic that doesn't explicitly match a rule.

---

#### Step 3.2: Allow ICMP Traffic Between VLAN 10 and VLAN 20

Add a firewall rule to allow ICMP traffic between the VLANs.

```bash
set firewall vlan-firewall 10 action accept source 192.168.10.0/24 destination 192.168.20.0/24 protocol icmp
```

This rule allows ICMP traffic (ping) from `VLAN 10` to `VLAN 20`.

Add a reciprocal rule for ICMP traffic from `VLAN 20` to `VLAN 10`:

```bash
set firewall vlan-firewall 20 action accept source 192.168.20.0/24 destination 192.168.10.0/24 protocol icmp
```

---

### Step 4: Apply Firewall Rule Set to the Interfaces

Apply the `vlan-firewall` rule set to the VLAN interfaces `eth0.10` and `eth0.20`.

#### Step 4.1: Apply Firewall to VLAN 10 Interface

```bash
set interface eth0.10 firewall in vlan-firewall
```

#### Step 4.2: Apply Firewall to VLAN 20 Interface

```bash
set interface eth0.20 firewall in vlan-firewall
```

---

### Step 5: Verify Configuration

After configuring the VLAN interfaces and applying firewall rules, verify that the setup works as expected.

#### Step 5.1: Check Inter-VLAN ICMP Connectivity

Ping from a device in VLAN 10 (e.g., `192.168.10.2`) to a device in VLAN 20 (e.g., `192.168.20.2`). The ICMP traffic should be allowed, and you should receive ping replies.

```bash
ping 192.168.20.2
```

#### Step 5.2: Verify Other Traffic is Blocked

Try using a different protocol (e.g., TCP or UDP) between the VLANs. It should be blocked by the firewall due to the default `drop` policy.
