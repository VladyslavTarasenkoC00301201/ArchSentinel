# ============================
# Single-file configuration paths
# ============================

SSH_CONFIG          = "/etc/ssh/sshd_config"
PASSWD              = "/etc/passwd"
SHADOW              = "/etc/shadow"
SUDOERS             = "/etc/sudoers"
LIMITS_CONF         = "/etc/security/limits.conf"
SYSCTL_CONF         = "/etc/sysctl.conf"
HOSTS_ALLOW         = "/etc/hosts.allow"
HOSTS_DENY          = "/etc/hosts.deny"
RESOLV_CONF         = "/etc/resolv.conf"
AUDITD_CONF         = "/etc/audit/auditd.conf"
RSYSLOG_CONF        = "/etc/rsyslog.conf"
FSTAB               = "/etc/fstab"
LOGIN_DEFS          = "/etc/login.defs"

# ============================
# Multi-file directories
# ============================

AUDIT_RULES_DIR     = "/etc/audit/rules.d"
PAM_DIR             = "/etc/pam.d"

# ============================
# Master configuration map
# ============================

CONFIG_PATHS = {
    "ssh": SSH_CONFIG,
    "passwd": PASSWD,
    "shadow": SHADOW,
    "sudoers": SUDOERS,
    "limits": LIMITS_CONF,
    "sysctl": SYSCTL_CONF,
    "hosts_allow": HOSTS_ALLOW,
    "hosts_deny": HOSTS_DENY,
    "resolv": RESOLV_CONF,
    "auditd": AUDITD_CONF,
    "rsyslog": RSYSLOG_CONF,
    "fstab": FSTAB,
    "login_defs": LOGIN_DEFS,

    # Directories containing rule files
    "audit_rules": AUDIT_RULES_DIR,
    "pam": PAM_DIR,
}

