# Eradication — Remove Malicious Persistence Playbook
**Phase:** Eradication | **Maturity:** Operational | **Version:** 1.0

## Objective
Identify and remove all attacker persistence mechanisms from affected systems to
ensure the threat is fully expelled before recovery begins. Verify that no residual
access paths remain.

## Prerequisites
- Containment phase completed (attacker's active access is blocked)
- Forensic images or memory captures taken (where applicable)
- Analyst authorized to modify system configurations on affected hosts
- Change management record open

---

## Step 1 — Enumerate Persistence Locations (20–60 min)

Systematically review known persistence locations on affected systems.

### Linux / Unix Systems

| Location | Check Command |
|---|---|
| Cron jobs | `crontab -l -u <user>`, `cat /etc/cron*` |
| Systemd services | `systemctl list-units --type=service`, inspect `/etc/systemd/system/` |
| Init scripts | `ls /etc/init.d/`, `ls /etc/rc*.d/` |
| Bash/shell profiles | `~/.bashrc`, `~/.bash_profile`, `~/.profile`, `/etc/profile.d/` |
| SSH authorized keys | `~/.ssh/authorized_keys` for all users |
| Setuid/setgid binaries | `find / -perm /4000 -o -perm /2000 2>/dev/null` (compare to baseline) |
| Kernel modules | `lsmod`, compare to known-good list |
| `/tmp` and `/dev/shm` | `ls -la /tmp /dev/shm` for unusual executables |
| SUID binaries modified | Compare against package manager checksums |

### Windows Systems

| Location | Check Method |
|---|---|
| Scheduled tasks | `schtasks /query /fo LIST /v`, look for unusual tasks |
| Services | `sc query`, Autoruns tool |
| Registry run keys | `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` and variants |
| Startup folders | `shell:startup`, `shell:common startup` |
| WMI subscriptions | `Get-WMIObject -Namespace root\subscription -Class __EventConsumer` |
| DLL hijacking | Inspect PATH order for writable directories |
| Browser extensions | Review installed extensions for all profiles |

### Cloud / Identity Layer

- [ ] Check for new IAM users, service accounts, or roles created during attacker's window
- [ ] Review OAuth app authorizations for the compromised account
- [ ] Check for new API keys or long-lived tokens created during the incident
- [ ] Review GitHub / GitLab OAuth apps and deploy keys
- [ ] Check for new SSH keys in cloud console (EC2 key pairs, GCP project metadata)

---

## Step 2 — Remove Confirmed Persistence Mechanisms

For each confirmed malicious persistence item:

1. **Document the item** before removal:
   - Full path, content, creation time, owning user
   - Save a copy to `EVIDENCE_DIR` under the incident ID

2. **Remove the persistence mechanism:**

```bash
# Example: remove malicious cron job
crontab -r -u <compromised-user>

# Example: disable and remove malicious systemd service
systemctl stop <malicious-service>
systemctl disable <malicious-service>
rm /etc/systemd/system/<malicious-service>.service
systemctl daemon-reload

# Example: remove unauthorized SSH authorized key
# Edit ~/.ssh/authorized_keys and remove the attacker's public key
```

3. **Verify removal:** Re-run the discovery command and confirm the item is gone.

---

## Step 3 — Remove Malicious Binaries and Files

1. Identify malicious files using:
   - File hash comparison against threat intelligence feeds (VirusTotal, internal TI)
   - Unusual creation timestamps (correlate with attacker's activity window)
   - Files in unusual locations (`/tmp`, `$APPDATA`, world-writable directories)

2. Before deletion:
   - Copy to quarantine location for forensic preservation
   - Hash the file: `sha256sum <file>`
   - Record in evidence manifest

3. Delete or quarantine the file:
```bash
# Move to quarantine (preserve for forensics)
mv /tmp/malicious_binary /incident-evidence/<INC-ID>/quarantine/

# On Windows: move to a restricted quarantine share
Move-Item "C:\Temp\malicious.exe" "\\quarantine\<INC-ID>\"
```

---

## Step 4 — Patch or Remediate the Initial Access Vector

Identify how the attacker gained initial access and address the root cause:

| Attack Vector | Remediation |
|---|---|
| Compromised credential | Already handled in containment; verify MFA enforced |
| Unpatched vulnerability | Apply patch; if no patch available, apply virtual patch (WAF rule, network block) |
| Misconfigured cloud resource | Implement SCPs / org policies to prevent recurrence |
| Supply chain compromise | Remove affected dependency; audit other dependencies |
| Phishing | Retrain affected user; tune email gateway filters |
| Insider threat | Coordinate with HR and Legal; revoke access |

---

## Step 5 — Validate Clean State

Run the following checks to confirm no residual persistence:

- [ ] Re-run all persistence enumeration checks from Step 1 — zero findings
- [ ] Verify no unexpected outbound connections from affected systems
- [ ] Confirm no new accounts or credentials were created after containment
- [ ] Run an endpoint security scan (EDR/AV) on affected systems — clean
- [ ] Compare system file hashes against trusted baseline where available

---

## Documentation Checkpoint
- [ ] All persistence mechanisms enumerated
- [ ] Evidence of each persistence mechanism captured
- [ ] All persistence mechanisms removed
- [ ] Malicious files quarantined
- [ ] Initial access vector remediated or mitigated
- [ ] Clean-state validation passed
- [ ] Eradication timestamp recorded in incident record
- [ ] Proceed to Recovery playbook
