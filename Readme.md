# NFRouter (alpha version)
<p style="text-align:center;">Made with :heart: from Romania.</p>

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
5. Configuration examples
- [Router-on-a-Stick with Firewall to Allow ICMP](/docs/router-on-a-stick-and-icmp-allow.md)
- [Create a custom firewall and attach it to a interface](/docs/custom-firewall.md)
- [Create a dhcp server](/docs/dhcp-server.md)
- [Create a nat and a dnat with a custom firwall cu drop or accept connections](/docs/dnat-with-nat-and-firewall.md)


---

> [!WARNING]
> Please keep in mind that NFRouter is still an Alpha version and under active development and therefore full backward compatibility  is not guaranteed before reaching v1.0.0.

- [x] Save Current Configuration
- [x] Load Current Configuration at Startup
- [x] Basic Interface Setup Options
- [x] Basic Firewall Setup Options
- [x] Basic Network Address Translation (NAT) Options
- [x] Basic VLAN Support
- [ ] Add documentation for implemented commands until now
- [ ] Release Basic Image for GNS3 with Application Template
- [ ] Add Contribution Guidelines and Handle Pull Requests
- [ ] Perform Code Cleanup (Proper Debug Handling)
- [ ] Develop Automated Testing for Commands and Configurations (without Execution on Linux) (in progress)
- [ ] Write Comprehensive Documentation
- [ ] Enhance Command Line Help and Auto-Complete Features
- [ ] Advanced Interface Setup Options
- [ ] Advanced Firewall Setup Options
- [ ] Advanced Network Address Translation (NAT) Options
- [ ] Advanced VLAN Support
- [ ] Implement ISO Automated Build Process (in progress)
- [ ] Conduct Docker-Based Integration Testing
- [ ] Implement VPN Configuration (e.g., OpenVPN, WireGuard)
- [ ] Configure VPN-Based Firewall Rules
- [x] Basic RIP Support
- [ ] OSPF Support
- [ ] BGP support
- [ ] Implement Role-Based Access Control (RBAC)
- [ ] Enable High Availability (HA) and Redundancy Features
- [ ] Set Up Monitoring and Logging (e.g., syslog, nftables logs)
- [ ] Develop Optional Web-Based Management UI
- [ ] Address Remaining Items Not Included in the Roadmap

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
