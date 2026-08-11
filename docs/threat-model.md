# Threat model and limitations

The harness records traffic crossing the monitored gateway and attempted traffic blocked at that boundary. It cannot observe cellular, secondary Wi-Fi, Bluetooth, other radios, physical interfaces, or side channels. It cannot determine encrypted payload semantics, prove ownership or final recipient from a hostname/IP/ASN, defeat a DUT that detects the test environment, or guarantee detection of behavior delayed beyond the observation window.

The correct conclusion is: “Within the defined network boundary, scenarios, and observation period, the harness records and attributes observed network behavior.” It does not establish that a device is secure.

