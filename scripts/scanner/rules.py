
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
    "PermitEmptyPasswords": {
        "expected": "no",
        "description": "Do not allow passwordsless accounts to login"
    },
    "MaxAuthTries": {
        "expected": "3",
        "description": "Reduce login attempts. Defence against bruteforcing"
    },
    "LoginGraceTime": {
        "expected": "30",
        "description": "Reduce the duration of half-open connections, reduces DoS angles"
    },
    "PubkeyAuthentication": {
        "expected": "yes",
        "description": "Enable public key authentication"
    },
    "AllowTcpForwarding": {
        "expected": "no",
        "description": "Allows to connect to the internet bypass network segmentation and firewall, should be disabled unless explicitly needed"
    },
    "PermitUserEnvironment": {
        "expected": "no",
        "description": "Disallow user-controlled environment variables. User can modify PATH to point to malicious binaries, must be disabled unless you know why you need it"
    },
            }

# ============================
# Master rule set
# ============================
ALL_RULES = {
    "ssh": SSH_RULES
}

