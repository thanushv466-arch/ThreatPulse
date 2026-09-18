"""MITRE ATT&CK Enterprise tactics, in kill-chain order."""

TACTICS = [
    ("Reconnaissance", "TA0043"),
    ("Initial Access", "TA0001"),
    ("Execution", "TA0002"),
    ("Persistence", "TA0003"),
    ("Privilege Escalation", "TA0004"),
    ("Defense Evasion", "TA0005"),
    ("Credential Access", "TA0006"),
    ("Discovery", "TA0007"),
    ("Command and Control", "TA0011"),
    ("Exfiltration", "TA0010"),
    ("Impact", "TA0040"),
]
TACTIC_NAMES = [name for name, _ in TACTICS]
