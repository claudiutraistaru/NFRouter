Configure Firewall Rules for Interface `eth0`

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

**Attach Firewall Rule Set to Interface**  
   Attach the firewall rule set `test-rule-set` to the `in` direction of interface `eth0`.

   ```shell
   set interface eth0 firewall in test-rule-set
   ```
