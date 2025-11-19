
# SSH Rules (/etc/ssh/sshd_config)

SSH_RULES = {
    "PermitRootLogin": {
        "expected": "no",
        "description": "Disable root SSH login"
    },
    "PasswordAuthentication": {
        "expected": "no",
        "description": "Disable password authentication"
    },
}

# ============================
# Master rule set
# ============================
ALL_RULES = {
    "ssh": SSH_RULES
}

