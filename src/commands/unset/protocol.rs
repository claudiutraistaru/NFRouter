pub fn help_commands() -> Vec<(&'static str, &'static str)> {
    vec![
        ("unset protocol rip", "Disable the RIP routing protocol."),
        (
            "unset protocol rip network <network-ip/prefix>",
            "Remove a network from the RIP routing protocol.",
        ),
        (
            "unset protocol rip version",
            "Reset RIP version to the default.",
        ),
        (
            "unset protocol rip passive-interface <interface-name>",
            "Remove passive interface from RIP.",
        ),
        (
            "unset protocol rip redistribute static",
            "Stop redistributing static routes into RIP.",
        ),
        (
            "unset protocol rip redistribute connected",
            "Stop redistributing connected routes into RIP.",
        ),
        (
            "unset protocol rip redistribute ospf",
            "Stop redistributing OSPF routes into RIP.",
        ),
        (
            "unset protocol rip redistribute bgp",
            "Stop redistributing BGP routes into RIP.",
        ),
        (
            "unset protocol rip distance",
            "Reset the administrative distance for RIP routes to default.",
        ),
        (
            "unset protocol rip default-information originate",
            "Stop advertising the default route in RIP.",
        ),
    ]
}
