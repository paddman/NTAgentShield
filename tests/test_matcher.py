from ntshield.engine.matcher import matches


def test_matcher_supports_nested_and_numeric_operators() -> None:
    event = {
        "event_type": "network.connect",
        "process": {"name": "PowerShell.EXE", "command_line": "powershell -enc abc"},
        "network": {"destination_ip": "203.0.113.7", "destination_port": 443},
        "tags": ["first-seen", "external"],
    }
    assert matches(
        event,
        {
            "event_type": "network.connect",
            "process.name|in": ["powershell.exe", "cmd.exe"],
            "process.command_line|icontains": "-ENC",
            "network.destination_port|gte": 443,
            "tags|contains": "external",
        },
    )


def test_matcher_handles_network_ranges() -> None:
    event = {"network": {"destination_ip": "10.42.1.9"}}
    assert matches(event, {"network.destination_ip|cidr": ["10.0.0.0/8"]})
    assert matches(event, {"network.destination_ip|not_cidr": ["192.168.0.0/16"]})
