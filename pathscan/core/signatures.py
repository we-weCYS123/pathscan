# ═══════════════════════════════════════════════════════
#  signatures.py — Sensitive File Signatures
#  Matching any signature indicates confirmed path traversal / file disclosure
# ═══════════════════════════════════════════════════════

SIGNATURES = {
    # ─── Linux ───
    "linux_passwd": {
        "patterns": ["root:x:0:0", "root:*:0:0", "daemon:x:1:1",
                     "bin:x:2:2", "nobody:x:", "/bin/bash", "/bin/sh"],
        "severity": "critical",
        "description": "Read /etc/passwd — system users disclosure",
    },
    "linux_shadow": {
        "patterns": ["root:$6$", "root:$1$", "root:$y$", "root:$5$", "root:*:", "root:!:"],
        "severity": "critical",
        "description": "Read /etc/shadow — hashed passwords disclosure",
    },
    "linux_hosts": {
        "patterns": ["127.0.0.1 localhost", "127.0.0.1\tlocalhost", "127.0.1.1"],
        "severity": "low",
        "description": "Read /etc/hosts — local network hostnames",
    },
    "linux_environ": {
        "patterns": ["PATH=/", "HOSTNAME=", "HOME=/", "PWD=/"],
        "severity": "high",
        "description": "Read /proc/self/environ — environment variables leak",
    },

    # ─── Windows ───
    "win_ini": {
        "patterns": ["[fonts]", "[extensions]", "[mci extensions]", "[files]"],
        "severity": "high",
        "description": "Read C:\\Windows\\win.ini — system configuration",
    },
    "win_boot": {
        "patterns": ["[boot loader]", "[operating systems]"],
        "severity": "high",
        "description": "Read C:\\boot.ini — bootloader configuration",
    },

    # ─── Common Configuration Files ───
    "env_file": {
        "patterns": ["DB_PASSWORD=", "APP_KEY=", "SECRET_KEY=",
                     "DATABASE_URL=", "API_KEY=", "DB_HOST=", "REDIS_PASSWORD="],
        "severity": "critical",
        "description": "Read .env — application secrets disclosure",
    },
    "wp_config": {
        "patterns": ["DB_NAME", "DB_USER", "DB_PASSWORD", "table_prefix", "AUTH_KEY"],
        "severity": "critical",
        "description": "Read wp-config.php — database credentials disclosure",
    },

    # ─── PHP Wrappers ───
    "php_filter": {
        "patterns": ["PD9waHA", "PD9QSF"],  # Base64 for <?php and <?PH
        "severity": "critical",
        "description": "Source code leak via php://filter (Base64)",
    },

    # ─── LFI Error Disclosures ───
    "lfi_errors": {
        "patterns": [
            "failed to open stream",
            "open_basedir restriction in effect",
            "java.io.FileNotFoundException",
            "System.IO.FileNotFoundException",
            "fread(): supplied argument is not a valid stream resource",
        ],
        "severity": "medium",
        "description": "System error leak indicating input reached file-handling function",
    },
}

