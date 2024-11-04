Router-on-a-Stick with Firewall to Allow ICMP

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
