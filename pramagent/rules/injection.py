"""
pramagent.rules.injection
=========================
Classic injection corpora — SQL, shell, SSRF, path traversal, server-side
template injection.

Source corpora:
  - OWASP injection cheatsheets
  - PortSwigger Web Security Academy SSTI / SQLi labs
  - PayloadsAllTheThings (https://github.com/swisskyrepo/PayloadsAllTheThings)
"""
from __future__ import annotations

from ..layers import Rule
from ..types import Verdict


_PATTERNS: list[tuple[str, str, str, Verdict]] = [
    # SQL injection
    ("inj_sql_or_1eq1",
     r"(?:'|\")\s*(?:OR|AND)\s+(?:1\s*=\s*1|'1'\s*=\s*'1'|true)\s*(?:--|#|/\*)?",
     "SQLi: tautology", Verdict.BLOCK),
    ("inj_sql_union_select",
     r"\bUNION(?:\s+ALL)?\s+SELECT\b",
     "SQLi: UNION SELECT", Verdict.BLOCK),
    ("inj_sql_drop_table",
     r"(?:;|^|\s)\s*DROP\s+TABLE\b",
     "SQLi: DROP TABLE chain", Verdict.BLOCK),
    ("inj_sql_information_schema",
     r"\bFROM\s+information_schema\.\w+",
     "SQLi: information_schema probe", Verdict.BLOCK),
    ("inj_sql_sleep",
     r"\b(?:SLEEP|PG_SLEEP|WAITFOR\s+DELAY)\s*\(",
     "SQLi: time-based blind", Verdict.BLOCK),
    ("inj_sql_outfile",
     r"\bINTO\s+(?:OUT|DUMP)FILE\b",
     "SQLi: file-write exfil", Verdict.BLOCK),
    ("inj_sql_load_file",
     r"\bLOAD_FILE\s*\(",
     "SQLi: file-read exfil", Verdict.BLOCK),
    ("inj_sql_xp_cmdshell",
     r"\bxp_cmdshell\b|\bsp_OACreate\b",
     "SQLi: MSSQL RCE primitive", Verdict.BLOCK),

    # NoSQL injection
    ("inj_nosql_operator",
     r"\$\s*(?:where|ne|gt|lt|gte|lte|regex|in|or|and)\s*:",
     "NoSQL: operator injection", Verdict.BLOCK),

    # Shell / command injection
    ("inj_shell_backticks",
     r"`[^`]{0,200}\b(?:curl|wget|nc|bash|sh|python|perl|ruby|powershell)\b[^`]{0,200}`",
     "Shell: backtick command", Verdict.BLOCK),
    ("inj_shell_dollar_paren",
     r"\$\(\s*(?:curl|wget|nc|bash|sh|python|perl|ruby|powershell|cat|ls|rm|mv|cp)\b",
     "Shell: $(...) command", Verdict.BLOCK),
    ("inj_shell_pipe_curl",
     r"\b(?:curl|wget)\s+[^|;&\n]{0,200}\s*\|\s*(?:sh|bash|zsh|python|perl)\b",
     "Shell: curl | sh pipeline", Verdict.BLOCK),
    ("inj_shell_meta_chain",
     r"(?:;|&&|\|\|)\s*(?:rm|mv|cp|chmod|chown|kill|wget|curl|nc|bash|sh)\b",
     "Shell: chained command", Verdict.BLOCK),
    ("inj_shell_reverse_shell",
     r"(?:bash\s+-i\s*>&|nc\s+-e\s+/bin/(?:sh|bash)|/dev/tcp/\d+\.\d+\.\d+\.\d+/)",
     "Shell: reverse-shell pattern", Verdict.BLOCK),
    ("inj_shell_powershell_iex",
     r"(?:Invoke-Expression|IEX)\s+\(?\s*(?:New-Object\s+Net\.WebClient|System\.Net\.WebClient)",
     "Shell: PowerShell IEX downloader", Verdict.BLOCK),

    # SSRF (Server-Side Request Forgery)
    ("inj_ssrf_169_254",
     r"\b169\.254\.169\.254\b",
     "SSRF: cloud metadata IP (AWS/GCP/Azure)", Verdict.BLOCK),
    ("inj_ssrf_metadata_host",
     r"(?:metadata\.google\.internal|metadata\.azure\.com|metadata\.aws\.internal)",
     "SSRF: cloud metadata hostname", Verdict.BLOCK),
    ("inj_ssrf_localhost",
     r"https?://(?:127\.0\.0\.1|0\.0\.0\.0|localhost|\[::1\])(?::\d+)?/",
     "SSRF: loopback target", Verdict.BLOCK),
    ("inj_ssrf_internal_rfc1918",
     r"https?://(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})",
     "SSRF: RFC1918 private IP", Verdict.ESCALATE),
    ("inj_ssrf_file_scheme",
     r"\bfile://(?:/?[\w./-]+)?",
     "SSRF: file:// scheme", Verdict.BLOCK),
    ("inj_ssrf_gopher_dict",
     r"\b(?:gopher|dict|ftp|ldap|jar)://",
     "SSRF: non-http scheme", Verdict.BLOCK),

    # Path traversal
    ("inj_path_dotdot",
     r"(?:\.\./){2,}|(?:\.\.\\){2,}",
     "Path: directory traversal", Verdict.BLOCK),
    ("inj_path_etc_passwd",
     r"/etc/(?:passwd|shadow|hosts|sudoers)\b",
     "Path: linux sensitive file", Verdict.BLOCK),
    ("inj_path_windows_sys",
     r"(?:C:\\Windows\\System32|\\\\\?\\C:\\)",
     "Path: windows system path", Verdict.BLOCK),
    ("inj_path_url_encoded_traversal",
     r"(?:%2e%2e(?:%2f|%5c)){2,}",
     "Path: url-encoded ../", Verdict.BLOCK),

    # Server-Side Template Injection
    ("inj_ssti_jinja",
     r"\{\{\s*[\w.]*(?:__class__|__mro__|__subclasses__|__import__|config|self|request)\b",
     "SSTI: jinja/python sandbox escape", Verdict.BLOCK),
    ("inj_ssti_freemarker",
     r"<#assign\s+\w+\s*=\s*\"freemarker\.template\.utility\.Execute\"",
     "SSTI: freemarker Execute", Verdict.BLOCK),
    ("inj_ssti_velocity",
     r"#set\s*\(\s*\$\w+\s*=\s*\$\w+\.getClass\(\)",
     "SSTI: velocity getClass()", Verdict.BLOCK),
    ("inj_ssti_smarty",
     r"\{(?:php|system|exec)\}",
     "SSTI: smarty/php tag", Verdict.BLOCK),
    ("inj_ssti_twig",
     r"\{\{\s*['\"][^'\"]*['\"]\s*\|\s*(?:filter|map)\s*\(\s*['\"](?:system|exec|passthru)",
     "SSTI: twig filter abuse", Verdict.BLOCK),

    # XXE / XML
    ("inj_xxe_doctype",
     r"<!DOCTYPE\s+\w+\s*\[\s*<!ENTITY\s+\w+\s+SYSTEM",
     "XXE: external entity declaration", Verdict.BLOCK),

    # LDAP injection
    ("inj_ldap_wildcard",
     r"\)\(\|\(\w+=\*\)\)|\)\(\&\(\w+=\*\)\)",
     "LDAP: filter injection", Verdict.BLOCK),

    # Log4Shell
    ("inj_log4shell_jndi",
     r"\$\{jndi:(?:ldap|ldaps|rmi|dns)://",
     "Log4Shell: JNDI lookup", Verdict.BLOCK),
]


INJECTION_CORPUS: list[Rule] = [
    Rule(rule_id=rid, action=verdict, pattern=pat, detail=detail)
    for rid, pat, detail, verdict in _PATTERNS
]

__all__ = ["INJECTION_CORPUS"]
