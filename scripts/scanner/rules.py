# ============================
# SSH Rules
# ============================
SSH_RULES = {
    "PermitRootLogin": {
        "expected": "no",
        "description": "Disable SSH root login"
    },
    "PasswordAuthentication": {
        "expected": "no",
        "description": "Disable password authentication"
    },
    "Ciphers": {
        "expected": "strong",
        "description": "Strong SSH cipher suites"
    },
    "MACs": {
        "expected": "strong",
        "description": "Strong SSH MAC algorithms"
    },
    "KexAlgorithms": {
        "expected": "strong",
        "description": "Strong SSH key exchange algorithms"
    },
    "Banner": {
        "expected": "enabled",
        "description": "SSH banner must be configured"
    },
    "ClientAliveInterval": {
        "expected": "300",
        "description": "Idle timeout"
    }
}

# ============================
# passwd rules
# ============================
PASSWD_RULES = {
    "disabled_shells": {
        "description": "System accounts should use /usr/bin/nologin or /bin/false"
    },
    "uid_anomalies": {
        "description": "Detect unexpected UID=0 users or UID conflicts"
    }
}

# ============================
# shadow rules
# ============================
SHADOW_RULES = {
    "empty_passwords": {
        "description": "No user should have an empty password field"
    },
    "password_aging": {
        "description": "Password aging policies must be enforced"
    }
}

# ============================
# sudoers rules
# ============================
SUDOERS_RULES = {
    "no_nopasswd": {
        "description": "NOPASSWD should be avoided"
    },
    "wheel_group_required": {
        "description": "Only wheel group should have sudo access"
    },
    "allowed_commands": {
        "description": "Check for overly permissive sudo rules"
    }
}

# ============================
# limits.conf rules
# ============================
LIMITS_RULES = {
    "resource_limits": {
        "description": "Check resource limits for users"
    }
}

# ============================
# sysctl rules
# ============================
SYSCTL_RULES = {
    "kernel_hardening": {
        "description": "Ensure kernel hardening sysctl values"
    },
    "ip_forwarding": {
        "description": "Ensure IP forwarding is disabled unless required"
    },
    "syn_protection": {
        "description": "Enable TCP SYN protection"
    }
}

# ============================
# hosts.allow / hosts.deny rules
# ============================
HOSTS_ALLOW_RULES = {
    "whitelist": {
        "description": "Check for allowed hosts"
    }
}

HOSTS_DENY_RULES = {
    "blacklist": {
        "description": "Check for denied hosts"
    }
}

# ============================
# resolv.conf (DNS security)
# ============================
RESOLV_RULES = {
    "dns_security": {
        "description": "Check secure DNS options"
    }
}

# ============================
# auditd.conf
# ============================
AUDITD_RULES = {
    "audit_retention": {
        "description": "Check audit log retention"
    },
    "max_log_size": {
        "description": "Check max audit log size"
    }
}

# ============================
# audit.rules
# ============================
AUDIT_RULE_FILES = {
    "privileged_commands": {
        "description": "Audit important privileged command execution"
    },
    "file_integrity": {
        "description": "Audit important file integrity changes"
    }
}

# ============================
# rsyslog rules
# ============================
RSYSLOG_RULES = {
    "remote_logging": {
        "description": "Check if remote logging is configured"
    }
}

# ============================
# fstab rules
# ============================
FSTAB_RULES = {
    "nodev_nosuid_noexec": {
        "description": "Non-root partitions should use nodev, nosuid, noexec"
    }
}

# ============================
# login.defs rules
# ============================
LOGIN_DEFS_RULES = {
    "password_complexity": {
        "description": "Check password complexity parameters"
    },
    "password_expiration": {
        "description": "Check password expiration defaults"
    }
}

# ============================
# Master mapping: file → rule set
# ============================
ALL_RULES = {
    "ssh": SSH_RULES,
    "passwd": PASSWD_RULES,
    "shadow": SHADOW_RULES,
    "sudoers": SUDOERS_RULES,
    "limits": LIMITS_RULES,
    "sysctl": SYSCTL_RULES,
    "hosts_allow": HOSTS_ALLOW_RULES,
    "hosts_deny": HOSTS_DENY_RULES,
    "resolv": RESOLV_RULES,
    "auditd": AUDITD_RULES,
    "audit_rules": AUDIT_RULE_FILES,
    "rsyslog": RSYSLOG_RULES,
    "fstab": FSTAB_RULES,
    "login_defs": LOGIN_DEFS_RULES,
}

