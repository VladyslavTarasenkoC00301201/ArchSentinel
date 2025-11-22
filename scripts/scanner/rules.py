
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


LOGIN_DEFS_RULES = {
    "PASS_MAX_DAYS": {
        "expected": "90",
        "description": "Maximum password age"
    },
    "PASS_MIN_DAYS": {
        "expected": "1",
        "description": "Minimum days between password changes"
    },
    "PASS_WARN_AGE": {
        "expected": "7",
        "description": "Days before expiration to warn user"
    },
    "UID_MIN": {
        "expected": "1000",
        "description": "Minimum UID for normal user accounts"
    },
    "UMASK": {
        "expected": "022",
        "description": "Default file creation mask"
    }
}


SYSCTL_RULES = {
    "kernel.kptr_restrict": {
        "expected": "2",
        "description": "Hide kernel pointers"
    },
    "kernel.yama.ptrace_scope": {
        "expected": "2",
        "description": "Restrict ptrace"
    },
    "net.ipv4.ip_forward": {
        "expected": "0",
        "description": "Disable IPv4 forwarding"
    },
    "net.ipv4.conf.all.accept_redirects": {
        "expected": "0",
        "description": "Disable ICMP redirects"
    },
    "net.ipv4.conf.all.send_redirects": {
        "expected": "0",
        "description": "Disable sending redirects"
    },
}


LIMITS_RULES = {
    "nofile": {
        "expected": "10000",
        "description": "Max open files"
    },
    "nproc": {
        "expected": "4096",
        "description": "Max number of processes"
    }
}


RESOLV_RULES = {
    "nameserver": {
        "expected": "1.1.1.1",
        "description": "Preferred DNS server"
    },
    "options": {
        "expected": "edns0",
        "description": "DNS recommended options"
    }
}


RSYSLOG_RULES = {
    "module(load=\"imtcp\")": {
        "expected": "yes",
        "description": "TCP syslog module loaded"
    },
    "$ModLoad imuxsock": {
        "expected": "",
        "description": "Unix socket module loaded"
    },
    "$ModLoad imklog": {
        "expected": "",
        "description": "Kernel logging enabled"
    },
    "$ActionFileDefaultTemplate": {
        "expected": "RSYSLOG_TraditionalFileFormat",
        "description": "Standard file output template"
    }
}



ALL_RULES = {
    "ssh": SSH_RULES,
    "login_defs": LOGIN_DEFS_RULES,
    "sysctl": SYSCTL_RULES,
    "limits": LIMITS_RULES,
    "resolv": RESOLV_RULES,
    "rsyslog": RSYSLOG_RULES
}

