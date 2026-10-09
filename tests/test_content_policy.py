"""Content policy: every form below must be withheld. One test per form."""

from __future__ import annotations

import pytest

from handover.content import REDACTED, clean, name_suggests_secret

LEAK_FORMS = [
    "Password: Hunter2!",
    "password is Hunter2!",
    "Password - Hunter2!",
    "temp password set to Hunter2! for jdoe",
    "Admin pw Hunter2!",
    "pwd=Hunter2!",
    "pass: Hunter2!",
    "creds admin / Hunter2!",
    "Local admin: Administrator / Hunter2!",
    "PSK Hunter2!",
    "wifi key: Hunter2!",
    "Wi-Fi key - Hunter2!",
    "passcode: 4471",
    "PIN 4471",
    "Door code: 4471",
    "MFA backup code 123-456",
    "token: Hunter2!",
    "API key = Hunter2!",
    "client secret: Hunter2!",
    "credentials Hunter2!",
    "sshpass -p Hunter2! ssh admin@host",
    "net user jdoe Hunter2! /add",
    "Mot de passe : Hunter2!",
]


@pytest.mark.parametrize("line", LEAK_FORMS)
def test_labelled_secret_line_is_withheld(line):
    c = clean(f"Context before.\n{line}\nContext after.", 600)
    assert c.redacted
    assert c.text.splitlines() == ["Context before.", REDACTED, "Context after."]


@pytest.mark.parametrize("label", ["Password:", "Password", "Wi-Fi key -", "passcode =", "PIN:", "Admin password is"])
def test_label_then_value_on_the_next_line(label):
    c = clean(f"Router notes\n{label}\n\n   Hunter2!\nVLAN 30 for printers", 600)
    assert "Hunter2" not in c.text
    assert c.text.splitlines()[-1] == "VLAN 30 for printers"


def test_pem_private_key_is_withheld_and_flagged():
    c = clean("key below\n-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----\ndone", 600)
    assert "MIIEow" not in c.text and c.redacted


def test_unterminated_pem_is_withheld_to_the_end():
    c = clean("-----BEGIN PRIVATE KEY-----\nMIIEvQ\nAAAA", 600)
    assert "MIIEvQ" not in c.text and "AAAA" not in c.text and c.redacted


@pytest.mark.parametrize("line", [
    "Pinged NFD-FS01: replies. SMB from FD-01 times out.",
    "If S: fails after Windows updates, check the network profile is Domain, not Public.",
    "Front desk PCs cannot reach imaging share since this morning",
    "Printers on VLAN 30.",
])
def test_ordinary_support_text_is_kept(line):
    c = clean(line, 600)
    assert c.text == line and not c.redacted


def test_length_cap_is_flagged():
    c = clean("a" * 1000, 600)
    assert len(c.text) == 600 and c.truncated


@pytest.mark.parametrize("name", ["Admin password", "Door passcode", "Alarm PIN", "License key", "Client secret",
                                  "VPN credential", "API token", "Wi-Fi PSK", "creds"])
def test_secret_sounding_field_names(name):
    assert name_suggests_secret(name)


@pytest.mark.parametrize("name", ["Internet provider", "Wi-Fi network", "Backup window", "After-hours contact", "Firewall"])
def test_ordinary_field_names(name):
    assert not name_suggests_secret(name)
