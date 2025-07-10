import os
import re
import subprocess
import audit

# V-260469 
# Cat 1
def check_ctrl_alt_delete():
    try:
        for _ in range(2):
            result = subprocess.run(["systemctl","status","ctrl-alt-del.target"], capture_output=True, text=True)
            output = result.stdout + result.stderr
            
            if "masked" in output:
                return "Pass: V-260469"
            else:
                subprocess.run(["sudo", "systemctl", "disable", "ctrl-alt-del.target"], check=True)
                subprocess.run(["sudo", "systemctl", "mask", "ctrl-alt-del.target"], check=True)
                subprocess.run(["sudo", "systemctl", "daemon-reload"], check=True)

        if "masked" in output:
            return "Pass: V-260469"
        else:
            return "Fail to fix: V-260469"

    except Exception as e:
        return f"ERROR: Failed to check ctrl-alt-del.target - {str(e)}"


# V-260482
# Cat 1
def check_rsh_server_not_installed():
    try:
        for _ in range(2):
            result = subprocess.run(["dpkg","-l","|","grep","rsh-server"], capture_output=True, text=True)

            if "rsh-server" in result.stdout:
                subprocess.run(["apt-get", "purge", "rsh-server", "-y"], check=True)
            else:
                return "Pass: V-260482"
        
        return "Fail: V-260482"
        
    except Exception as e:
        return f"ERROR: {str(e)}"

# V-260483
# Cat 1
def check_telnet_not_installed():
    try:
        for _ in range(2):
            result = subprocess.run(["dpkg","-l","|","grep","telnetd"], capture_output=True, text=True)

            if "telnetd" in result.stdout:
                subprocess.run(["apt-get", "purge", "telnetd", "-y"], check=True)
            else:
                return "Pass: V-260483"
        
        return "Fail: V-260483"
        
    except Exception as e:
        return f"ERROR: {str(e)}"    


# V-260523
# Cat 1
def check_ssh_not_installed():
    try:

        for _ in range(2):
            result = subprocess.run(["dpkg","-l","openssh-server"], capture_output=True, text=True)
            output = result.stdout + result.stderr

            if re.search(r"^ii\s+openssh-server", output, re.MULTILINE):
                return "Pass: V-260523"
            else:
                subprocess.run(["sudo", "apt", "install", "-y", "ssh"], check=True)
        

        return "Fail: V-260523"
        
    except Exception as e:
        return f"ERROR: {str(e)}"  

# V-260524
# Cat 1
def check_ssh_enabled():
    try:
        for _ in range(2):
            result1 = subprocess.run(["systemctl","is-enabled","ssh"], capture_output=True, text=True)
            result2 = subprocess.run(["systemctl","is-active","ssh"], capture_output=True, text=True)

            if "enabled" in result1.stdout and "active" in result2.stdout:
                return "Pass: V-260524"
            else:
                subprocess.run(["systemctl","enable","ssh-service","--now"], text=True)
        

        return "Fail: V-260524"
        
    except Exception as e:
        return f"ERROR: {str(e)}"      




# V-260539
# Cat 1
def check_ctrl_alt_delete_graphical():
    try:
        result_display = subprocess.run(["echo", "$DISPLAY"], capture_output=True, text=True, shell=True)
        if not result_display.stdout.strip():
            return "N/A: V-260539 - No graphical user interface detected"
        
        result_gnome = subprocess.run(["which", "gsettings"], capture_output=True, text=True)
        if result_gnome.returncode != 0:
            return "N/A: V-260539 - GNOME/gsettings not available"

        for attempt in range(2):
            result = subprocess.run(
                ["gsettings", "get", "org.gnome.settings-daemon.plugins.media-keys", "logout"], 
                capture_output=True, text=True
            )
            
            if result.returncode != 0:
                return f"ERROR: Failed to get gsettings - {result.stderr.strip()}"
            output = result.stdout.strip()
            
            if output == "[]" or output == "@as []" or output == '""':
                return "Pass: V-260539"
            
            if attempt == 0:
                try:
                    dconf_dir = "/etc/dconf/db/local.d"
                    dconf_file = os.path.join(dconf_dir, "00-screensaver")
                    
                    os.makedirs(dconf_dir, exist_ok=True)
                    
                    dconf_contents = (
                        "[org/gnome/settings-daemon/plugins/media-keys]\n"
                        'logout=""\n'
                    )
                    
                    with open(dconf_file, "w") as f:
                        f.write(dconf_contents)
                    
                    subprocess.run(["sudo", "dconf", "update"], check=True)
                    
                except Exception as fix_error:
                    return f"ERROR: Failed to apply fix - {str(fix_error)}"
                
        result = subprocess.run(
            ["gsettings", "get", "org.gnome.settings-daemon.plugins.media-keys", "logout"], 
            capture_output=True, text=True
        )
        output = result.stdout.strip()
        
        if output == "[]" or output == "@as []" or output == '""':
            return "Pass: V-260539"
        else:
            return f"Fail: V-260539 - logout key still bound to: {output}"
        
    except Exception as e:
        return f"ERROR: V-260539 - {str(e)}"
    
# V-260559
# Cat 1
def get_sudo_group():
    try:
        result = subprocess.run(["grep", "sudo", "/etc/group"], capture_output=True, text=True)
        if ":" in result.stdout:
            return "Sudo group users(V-260559): "+", ".join(result.stdout.strip().split(":")[-1].split(","))
        return "No sudo group users(V-260559)"
    except Exception as e:
        return f"ERROR: {str(e)}" 

# V-260570
# Cat 1
def no_null_passwords():
    try:
        pam_files = ["/etc/pam.d/common-auth", "/etc/pam.d/common-password"]
        
        for attempt in range(2):
            issues = []
            for pam_file in pam_files:
                if os.path.exists(pam_file):
                    result = subprocess.run(["grep", "-n", "nullok", pam_file], capture_output=True, text=True)
                    if result.stdout:
                        for line in result.stdout.strip().split('\n'):
                            if line and not line.split(':', 2)[2].strip().startswith('#'):
                                issues.append(f"{pam_file}:{line}")
            
            if not issues:
                return "Pass: V-260570"
            
            if attempt == 0:
                for pam_file in pam_files:
                    if os.path.exists(pam_file):
                        subprocess.run(["sudo", "cp", pam_file, f"{pam_file}.backup"], check=True)
                        subprocess.run([
                            "sudo", "sed", "-i", 
                            "s/\\s*nullok\\(_secure\\)\\?\\s*/ /g", 
                            pam_file
                        ], check=True)
        
        final_issues = []
        for pam_file in pam_files:
            if os.path.exists(pam_file):
                result = subprocess.run(["grep", "-n", "nullok", pam_file], capture_output=True, text=True)
                if result.stdout:
                    for line in result.stdout.strip().split('\n'):
                        if line and not line.split(':', 2)[2].strip().startswith('#'):
                            final_issues.append(line)
        
        return "Pass: V-260570" if not final_issues else f"Fail: V-260570 - nullok found:\n" + "\n".join(final_issues)
        
    except Exception as e:
        return f"ERROR: V-260570 - {str(e)}"

# todo: Implement an auto fix
# V-260571
# Cat 1
def no_account_null_passwords():
    try:
        result = subprocess.run(["awk", "-F:", "!$2 {print $1}", "/etc/shadow"], capture_output=True, text=True)
        if result.stdout.strip():
            return "Fail: Accounts with blank passwords(V-260571):\n" + result.stdout.strip()
        else:
            return "Pass: V-260571"  
              
    except Exception as e:
        return f"ERROR: {str(e)}"      

# V-260471
# Cat 2
def check_audit_enabled_in_grub():
    try:
        result = subprocess.run(["grep", "^\s*linux", "/boot/grub/grub.cfg"],capture_output=True,text=True)
        lines = result.stdout.strip().splitlines()
        
        if not lines:
            return "Fail: No 'linux' lines found in grub.cfg(V-260471)"

        # Check each line for "audit=1"
        if all("audit=1" in line for line in lines):
            return "Pass: V-260471"
        else:
            return "Fail: Some boot entries are missing audit=1(V-260471)"

    except Exception as e:
        return f"ERROR: {str(e)}"      

# V-260529
# Cat 1
def check_ssh_x11_forwarding():
    """V-260529 - Disable SSH X11 forwarding"""
    try:
        sshd_config = "/etc/ssh/sshd_config"
        
        if subprocess.run(["which", "sshd"], capture_output=True).returncode != 0:
            return "N/A: V-260529 - SSH daemon not installed"
        
        if not os.path.exists(sshd_config):
            return f"ERROR: V-260529 - {sshd_config} not found"
        
        for attempt in range(2):
            result = subprocess.run([
                "grep", "-i", "^\\s*x11forwarding", sshd_config
            ], capture_output=True, text=True)
            
            active_setting = None
            if result.stdout:
                for line in result.stdout.strip().split('\n'):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        parts = line.split()
                        if len(parts) >= 2:
                            active_setting = parts[1].lower()
                            break
            
            if active_setting == "no":
                return "Pass: V-260529"
            
            if attempt == 0:
                subprocess.run(["sudo", "cp", sshd_config, f"{sshd_config}.backup"], check=True)
                
                subprocess.run([
                    "sudo", "sed", "-i", 
                    "/^\\s*X11Forwarding/Id", 
                    sshd_config
                ], check=True)
                
                subprocess.run([
                    "sudo", "sh", "-c", 
                    f"echo 'X11Forwarding no' >> {sshd_config}"
                ], check=True)
                
                if subprocess.run(["sudo", "sshd", "-t"], capture_output=True).returncode != 0:
                    return "ERROR: V-260529 - Invalid SSH configuration"
                
                subprocess.run(["sudo", "systemctl", "restart", "sshd.service"], check=True)
        
        return "Fail: V-260529 - X11Forwarding not set to no"
        
    except Exception as e:
        return f"ERROR: V-260529 - {str(e)}"

# not done
# V-260470
# Cat 1
def check_grub_password_required():
    try:
        if not os.path.exists("/boot/grub/grub.cfg"):
            return "ERROR: /boot/grub/grub.cfg not found (V-260470)"
        
        result = subprocess.run(
            ["grep", "-i", "password", "/boot/grub/grub.cfg"],
            capture_output=True,
            text=True
        )
        if "password_pbkdf2" in result.stdout:
            return "Pass: V-260470"

        
    except Exception as e:
        return f"ERROR: {str(e)}"

# V-260649
# Cat 2
def check_sudo_log_audit():
    try:
        for attempt in range(2):
            if subprocess.run(["which", "auditctl"], capture_output=True).returncode != 0:
                if attempt == 0:
                    subprocess.run(["apt", "install", "-y", "auditd"], check=True, capture_output=True)
                    subprocess.run(["systemctl", "enable", "--now", "auditd"], check=True)
                    continue
                else:
                    return "ERROR: auditctl not found (V-260649)"
            
            result = subprocess.run(["auditctl", "-l"], capture_output=True, text=True)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if '/var/log/sudo.log' in line and '-p wa' in line and 'maintenance' in line:
                        return "Pass: V-260649"
            
            if attempt == 0:
                audit_rules = "/etc/audit/rules.d/audit.rules"
                subprocess.run(["mkdir", "-p", "/etc/audit/rules.d"], check=True)
                subprocess.run(["sh", "-c", f"echo '-w /var/log/sudo.log -p wa -k maintenance' >> {audit_rules}"], check=True)
                subprocess.run(["augenrules", "--load"], check=True)
        
        return "Fail: sudo.log audit rule not found (V-260649)"
        
    except Exception as e:
        return f"ERROR: {str(e)}"
    
# V-260648
# Cat 2
def check_execve_privilege_audit():
    try:
        for attempt in range(2):
            if subprocess.run(["which", "auditctl"], capture_output=True).returncode != 0:
                if attempt == 0:
                    subprocess.run(["apt", "install", "-y", "auditd"], check=True, capture_output=True)
                    subprocess.run(["systemctl", "enable", "--now", "auditd"], check=True)
                    continue
                else:
                    return "ERROR: auditctl not found (V-260648)"
            
            result = subprocess.run(["auditctl", "-l"], capture_output=True, text=True)
            if result.returncode == 0:
                required_patterns = [
                    ("arch=b64", "execve", "uid!=euid", "euid=0"),
                    ("arch=b64", "execve", "gid!=egid", "egid=0"),
                    ("arch=b32", "execve", "uid!=euid", "euid=0"),
                    ("arch=b32", "execve", "gid!=egid", "egid=0")
                ]
                
                found_count = 0
                for line in result.stdout.split('\n'):
                    for pattern in required_patterns:
                        if all(p in line for p in pattern):
                            found_count += 1
                            break
                
                if found_count >= 4:
                    return "Pass: V-260648"
            
            if attempt == 0:
                audit_rules = "/etc/audit/rules.d/audit.rules"
                subprocess.run(["mkdir", "-p", "/etc/audit/rules.d"], check=True)
                
                rules = [
                    "-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k execpriv",
                    "-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -k execpriv",
                    "-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k execpriv",
                    "-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -k execpriv"
                ]
                
                for rule in rules:
                    subprocess.run(["sh", "-c", f"echo '{rule}' >> {audit_rules}"], check=True)
                
                subprocess.run(["augenrules", "--load"], check=True)
        
        return "Fail: execve privilege audit rules not found (V-260648)"
        
    except Exception as e:
        return f"ERROR: {str(e)}"

# V-260469 
# Cat 1
def check_ctrl_alt_delete():
    try:
        for _ in range(2):
            result = subprocess.run(["systemctl","status","ctrl-alt-del.target"], capture_output=True, text=True)
            output = result.stdout + result.stderr
            
            if "masked" in output:
                return "Pass: V-260469"
            else:
                subprocess.run(["sudo", "systemctl", "disable", "ctrl-alt-del.target"], check=True)
                subprocess.run(["sudo", "systemctl", "mask", "ctrl-alt-del.target"], check=True)
                subprocess.run(["sudo", "systemctl", "daemon-reload"], check=True)

        if "masked" in output:
            return "Pass: V-260469"
        else:
            return "Fail to fix: V-260469"

    except Exception as e:
        return f"ERROR: Failed to check ctrl-alt-del.target - {str(e)}"


# V-260482
# Cat 1
def check_rsh_server_not_installed():
    try:
        for _ in range(2):
            result = subprocess.run(["dpkg","-l","|","grep","rsh-server"], capture_output=True, text=True)

            if "rsh-server" in result.stdout:
                subprocess.run(["apt-get", "purge", "rsh-server", "-y"], check=True)
            else:
                return "Pass: V-260482"
        
        return "Fail: V-260482"
        
    except Exception as e:
        return f"ERROR: {str(e)}"

# V-260483
# Cat 1
def check_telnet_not_installed():
    try:
        for _ in range(2):
            result = subprocess.run(["dpkg","-l","|","grep","telnetd"], capture_output=True, text=True)

            if "telnetd" in result.stdout:
                subprocess.run(["apt-get", "purge", "telnetd", "-y"], check=True)
            else:
                return "Pass: V-260483"
        
        return "Fail: V-260483"
        
    except Exception as e:
        return f"ERROR: {str(e)}"    


# V-260523
# Cat 1
def check_ssh_not_installed():
    try:

        for _ in range(2):
            result = subprocess.run(["dpkg","-l","openssh-server"], capture_output=True, text=True)
            output = result.stdout + result.stderr

            if re.search(r"^ii\s+openssh-server", output, re.MULTILINE):
                return "Pass: V-260523"
            else:
                subprocess.run(["sudo", "apt", "install", "-y", "ssh"], check=True)
        

        return "Fail: V-260523"
        
    except Exception as e:
        return f"ERROR: {str(e)}"  

# V-260524
# Cat 1
def check_ssh_enabled():
    try:
        for _ in range(2):
            result1 = subprocess.run(["systemctl","is-enabled","ssh"], capture_output=True, text=True)
            result2 = subprocess.run(["systemctl","is-active","ssh"], capture_output=True, text=True)

            if "enabled" in result1.stdout and "active" in result2.stdout:
                return "Pass: V-260524"
            else:
                subprocess.run(["systemctl","enable","ssh-service","--now"], text=True)
        

        return "Fail: V-260524"
        
    except Exception as e:
        return f"ERROR: {str(e)}"      




# V-260539
# Cat 1
def check_ctrl_alt_delete_graphical():
    try:
        result_display = subprocess.run(["echo", "$DISPLAY"], capture_output=True, text=True, shell=True)
        if not result_display.stdout.strip():
            return "N/A: V-260539 - No graphical user interface detected"
        
        result_gnome = subprocess.run(["which", "gsettings"], capture_output=True, text=True)
        if result_gnome.returncode != 0:
            return "N/A: V-260539 - GNOME/gsettings not available"

        for attempt in range(2):
            result = subprocess.run(
                ["gsettings", "get", "org.gnome.settings-daemon.plugins.media-keys", "logout"], 
                capture_output=True, text=True
            )
            
            if result.returncode != 0:
                return f"ERROR: Failed to get gsettings - {result.stderr.strip()}"
            output = result.stdout.strip()
            
            if output == "[]" or output == "@as []" or output == '""':
                return "Pass: V-260539"
            
            if attempt == 0:
                try:
                    dconf_dir = "/etc/dconf/db/local.d"
                    dconf_file = os.path.join(dconf_dir, "00-screensaver")
                    
                    os.makedirs(dconf_dir, exist_ok=True)
                    
                    dconf_contents = (
                        "[org/gnome/settings-daemon/plugins/media-keys]\n"
                        'logout=""\n'
                    )
                    
                    with open(dconf_file, "w") as f:
                        f.write(dconf_contents)
                    
                    subprocess.run(["sudo", "dconf", "update"], check=True)
                    
                except Exception as fix_error:
                    return f"ERROR: Failed to apply fix - {str(fix_error)}"
                
        result = subprocess.run(
            ["gsettings", "get", "org.gnome.settings-daemon.plugins.media-keys", "logout"], 
            capture_output=True, text=True
        )
        output = result.stdout.strip()
        
        if output == "[]" or output == "@as []" or output == '""':
            return "Pass: V-260539"
        else:
            return f"Fail: V-260539 - logout key still bound to: {output}"
        
    except Exception as e:
        return f"ERROR: V-260539 - {str(e)}"
    
# V-260559
# Cat 1
def get_sudo_group():
    try:
        result = subprocess.run(["grep", "sudo", "/etc/group"], capture_output=True, text=True)
        if ":" in result.stdout:
            return "Sudo group users(V-260559): "+", ".join(result.stdout.strip().split(":")[-1].split(","))
        return "No sudo group users(V-260559)"
    except Exception as e:
        return f"ERROR: {str(e)}" 

# V-260570
# Cat 1
def no_null_passwords():
    try:
        pam_files = ["/etc/pam.d/common-auth", "/etc/pam.d/common-password"]
        
        for attempt in range(2):
            issues = []
            for pam_file in pam_files:
                if os.path.exists(pam_file):
                    result = subprocess.run(["grep", "-n", "nullok", pam_file], capture_output=True, text=True)
                    if result.stdout:
                        for line in result.stdout.strip().split('\n'):
                            if line and not line.split(':', 2)[2].strip().startswith('#'):
                                issues.append(f"{pam_file}:{line}")
            
            if not issues:
                return "Pass: V-260570"
            
            if attempt == 0:
                for pam_file in pam_files:
                    if os.path.exists(pam_file):
                        subprocess.run(["sudo", "cp", pam_file, f"{pam_file}.backup"], check=True)
                        subprocess.run([
                            "sudo", "sed", "-i", 
                            "s/\\s*nullok\\(_secure\\)\\?\\s*/ /g", 
                            pam_file
                        ], check=True)
        
        final_issues = []
        for pam_file in pam_files:
            if os.path.exists(pam_file):
                result = subprocess.run(["grep", "-n", "nullok", pam_file], capture_output=True, text=True)
                if result.stdout:
                    for line in result.stdout.strip().split('\n'):
                        if line and not line.split(':', 2)[2].strip().startswith('#'):
                            final_issues.append(line)
        
        return "Pass: V-260570" if not final_issues else f"Fail: V-260570 - nullok found:\n" + "\n".join(final_issues)
        
    except Exception as e:
        return f"ERROR: V-260570 - {str(e)}"

# todo: Implement an auto fix
# V-260571
# Cat 1
def no_account_null_passwords():
    try:
        result = subprocess.run(["awk", "-F:", "!$2 {print $1}", "/etc/shadow"], capture_output=True, text=True)
        if result.stdout.strip():
            return "Fail: Accounts with blank passwords(V-260571):\n" + result.stdout.strip()
        else:
            return "Pass: V-260571"  
              
    except Exception as e:
        return f"ERROR: {str(e)}"      

# V-260471
# Cat 2
def check_audit_enabled_in_grub():
    try:
        result = subprocess.run(["grep", "^\s*linux", "/boot/grub/grub.cfg"],capture_output=True,text=True)
        lines = result.stdout.strip().splitlines()
        
        if not lines:
            return "Fail: No 'linux' lines found in grub.cfg(V-260471)"

        # Check each line for "audit=1"
        if all("audit=1" in line for line in lines):
            return "Pass: V-260471"
        else:
            return "Fail: Some boot entries are missing audit=1(V-260471)"

    except Exception as e:
        return f"ERROR: {str(e)}"      

# V-260529
# Cat 1
def check_ssh_x11_forwarding():
    """V-260529 - Disable SSH X11 forwarding"""
    try:
        sshd_config = "/etc/ssh/sshd_config"
        
        if subprocess.run(["which", "sshd"], capture_output=True).returncode != 0:
            return "N/A: V-260529 - SSH daemon not installed"
        
        if not os.path.exists(sshd_config):
            return f"ERROR: V-260529 - {sshd_config} not found"
        
        for attempt in range(2):
            result = subprocess.run([
                "grep", "-i", "^\\s*x11forwarding", sshd_config
            ], capture_output=True, text=True)
            
            active_setting = None
            if result.stdout:
                for line in result.stdout.strip().split('\n'):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        parts = line.split()
                        if len(parts) >= 2:
                            active_setting = parts[1].lower()
                            break
            
            if active_setting == "no":
                return "Pass: V-260529"
            
            if attempt == 0:
                subprocess.run(["sudo", "cp", sshd_config, f"{sshd_config}.backup"], check=True)
                
                subprocess.run([
                    "sudo", "sed", "-i", 
                    "/^\\s*X11Forwarding/Id", 
                    sshd_config
                ], check=True)
                
                subprocess.run([
                    "sudo", "sh", "-c", 
                    f"echo 'X11Forwarding no' >> {sshd_config}"
                ], check=True)
                
                if subprocess.run(["sudo", "sshd", "-t"], capture_output=True).returncode != 0:
                    return "ERROR: V-260529 - Invalid SSH configuration"
                
                subprocess.run(["sudo", "systemctl", "restart", "sshd.service"], check=True)
        
        return "Fail: V-260529 - X11Forwarding not set to no"
        
    except Exception as e:
        return f"ERROR: V-260529 - {str(e)}"

# not done
# V-260470
# Cat 1
def check_grub_password_required():
    try:
        if not os.path.exists("/boot/grub/grub.cfg"):
            return "ERROR: /boot/grub/grub.cfg not found (V-260470)"
        
        result = subprocess.run(
            ["grep", "-i", "password", "/boot/grub/grub.cfg"],
            capture_output=True,
            text=True
        )
        if "password_pbkdf2" in result.stdout:
            return "Pass: V-260470"

        
    except Exception as e:
        return f"ERROR: {str(e)}"

# V-260649
# Cat 2
def check_sudo_log_audit():
    try:
        for attempt in range(2):
            if subprocess.run(["which", "auditctl"], capture_output=True).returncode != 0:
                if attempt == 0:
                    subprocess.run(["apt", "install", "-y", "auditd"], check=True, capture_output=True)
                    subprocess.run(["systemctl", "enable", "--now", "auditd"], check=True)
                    continue
                else:
                    return "ERROR: auditctl not found (V-260649)"
            
            result = subprocess.run(["auditctl", "-l"], capture_output=True, text=True)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if '/var/log/sudo.log' in line and '-p wa' in line and 'maintenance' in line:
                        return "Pass: V-260649"
            
            if attempt == 0:
                audit_rules = "/etc/audit/rules.d/audit.rules"
                subprocess.run(["mkdir", "-p", "/etc/audit/rules.d"], check=True)
                subprocess.run(["sh", "-c", f"echo '-w /var/log/sudo.log -p wa -k maintenance' >> {audit_rules}"], check=True)
                subprocess.run(["augenrules", "--load"], check=True)
        
        return "Fail: sudo.log audit rule not found (V-260649)"
        
    except Exception as e:
        return f"ERROR: {str(e)}"
    
# V-260648
# Cat 2
def check_execve_privilege_audit():
    try:
        for attempt in range(2):
            if subprocess.run(["which", "auditctl"], capture_output=True).returncode != 0:
                if attempt == 0:
                    subprocess.run(["apt", "install", "-y", "auditd"], check=True, capture_output=True)
                    subprocess.run(["systemctl", "enable", "--now", "auditd"], check=True)
                    continue
                else:
                    return "ERROR: auditctl not found (V-260648)"
            
            result = subprocess.run(["auditctl", "-l"], capture_output=True, text=True)
            if result.returncode == 0:
                required_patterns = [
                    ("arch=b64", "execve", "uid!=euid", "euid=0"),
                    ("arch=b64", "execve", "gid!=egid", "egid=0"),
                    ("arch=b32", "execve", "uid!=euid", "euid=0"),
                    ("arch=b32", "execve", "gid!=egid", "egid=0")
                ]
                
                found_count = 0
                for line in result.stdout.split('\n'):
                    for pattern in required_patterns:
                        if all(p in line for p in pattern):
                            found_count += 1
                            break
                
                if found_count >= 4:
                    return "Pass: V-260648"
            
            if attempt == 0:
                audit_rules = "/etc/audit/rules.d/audit.rules"
                subprocess.run(["mkdir", "-p", "/etc/audit/rules.d"], check=True)
                
                rules = [
                    "-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k execpriv",
                    "-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -k execpriv",
                    "-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k execpriv",
                    "-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -k execpriv"
                ]
                
                for rule in rules:
                    subprocess.run(["sh", "-c", f"echo '{rule}' >> {audit_rules}"], check=True)
                
                subprocess.run(["augenrules", "--load"], check=True)
        
        return "Fail: execve privilege audit rules not found (V-260648)"
        
    except Exception as e:
        return f"ERROR: {str(e)}"

# Combined V-260647, V-260646, V-260645, V-260644, V-260643, V-260642, V-260641, V-260640, V-260639, V-260638, V-260637, V-260636, V-260635
# Cat 2
def check_audit_rules_combined():
    return audit.combined()

# V-260603
# Cat 2
def check_audit_config_group_ownership():
    """V-260603 - Ensure audit configuration files are owned by root group"""
    try:
        for attempt in range(2):
            result = subprocess.run(["ls", "-al", "/etc/audit/audit.rules", "/etc/audit/auditd.conf", "/etc/audit/rules.d/*"], shell=True, capture_output=True, text=True)
            
            if result.returncode != 0:
                return f"ERROR: V-260603 - Failed to list audit files: {result.stderr.strip()}"
            
            awk_result = subprocess.run(["awk", "{print $4, $9}"], input=result.stdout, capture_output=True, text=True)
            
            if awk_result.returncode != 0:
                return f"ERROR: V-260603 - Failed to parse file listing: {awk_result.stderr.strip()}"
            
            # Check if all files are owned by root group
            issues = []
            for line in awk_result.stdout.strip().split('\n'):
                if line.strip():
                    parts = line.strip().split(' ', 1)
                    if len(parts) >= 2:
                        group, filename = parts[0], parts[1]
                        if group != "root":
                            issues.append(f"{filename} (group: {group})")
            
            if not issues:
                return "Pass: V-260603"
            
            if attempt == 0:
                try:
                    subprocess.run(["sudo", "chown", "-R", ":root", "/etc/audit/audit.rules", "/etc/audit/auditd.conf", "/etc/audit/rules.d/*"], shell=True,check=True)
                except subprocess.CalledProcessError as e:
                    return f"ERROR: V-260603 - Failed to fix group ownership: {str(e)}"
        
        if issues:
            return f"Fail: V-260603 - Files not owned by root group:\n" + "\n".join(issues)
        else:
            return "Pass: V-260603"
        
    except Exception as e:
        return f"ERROR: V-260603 - {str(e)}"

# V-260602
# Cat 2
def check_audit_config_user_ownership():
    """V-260602 - Ensure audit configuration files are owned by root user"""
    try:
        for attempt in range(2):
            result = subprocess.run(["ls", "-al", "/etc/audit/audit.rules", "/etc/audit/auditd.conf", "/etc/audit/rules.d/*"], shell=True, capture_output=True, text=True)
            
            if result.returncode != 0:
                return f"ERROR: V-260602 - Failed to list audit files: {result.stderr.strip()}"
            
            awk_result = subprocess.run([
                "awk", "{print $3, $9}"
            ], input=result.stdout, capture_output=True, text=True)
            
            if awk_result.returncode != 0:
                return f"ERROR: V-260602 - Failed to parse file listing: {awk_result.stderr.strip()}"
            
            issues = []
            for line in awk_result.stdout.strip().split('\n'):
                if line.strip():
                    parts = line.strip().split(' ', 1)
                    if len(parts) >= 2:
                        user, filename = parts[0], parts[1]
                        if user != "root":
                            issues.append(f"{filename} (user: {user})")
            
            if not issues:
                return "Pass: V-260602"
            
            if attempt == 0:
                try:
                    subprocess.run(["sudo", "chown", "-R", "root", "/etc/audit/audit.rules", "/etc/audit/auditd.conf", "/etc/audit/rules.d/*"], shell=True, check=True)
                except subprocess.CalledProcessError as e:
                    return f"ERROR: V-260602 - Failed to fix user ownership: {str(e)}"
        
        if issues:
            return f"Fail: V-260602 - Files not owned by root user:\n" + "\n".join(issues)
        else:
            return "Pass: V-260602"
        
    except Exception as e:
        return f"ERROR: V-260602 - {str(e)}"

# V-260601
# Cat 2
def check_audit_config_permissions():
    """V-260601 - Ensure audit configuration files have mode 640 or less permissive"""
    try:
        for attempt in range(2):
            ls_result = subprocess.run(
                ["ls", "-al", "/etc/audit/audit.rules", "/etc/audit/auditd.conf", "/etc/audit/rules.d/*"],
                capture_output=True, text=True
            )
            
            if ls_result.returncode != 0:
                return f"ERROR: V-260601 - Failed to list audit files: {ls_result.stderr.strip()}"
            
            awk_result = subprocess.run(
                ["awk", "{print $1, $9}"],
                input=ls_result.stdout,
                capture_output=True, text=True
            )
            
            if awk_result.returncode != 0:
                return f"ERROR: V-260601 - Failed to parse file listing: {awk_result.stderr.strip()}"
            
            issues = []
            for line in awk_result.stdout.strip().split('\n'):
                if line.strip():
                    parts = line.strip().split(' ', 1)
                    if len(parts) >= 2:
                        permissions = parts[0]
                        filename = parts[1]
                        
                        if not permissions.startswith('-'):
                            continue

                        perm_str = permissions[1:]
                        
                        # Calculate octal permissions
                        octal_perm = 0
                        # Owner permissions
                        if perm_str[0] == 'r': octal_perm += 400
                        if perm_str[1] == 'w': octal_perm += 200
                        if perm_str[2] == 'x': octal_perm += 100
                        # Group permissions
                        if perm_str[3] == 'r': octal_perm += 40
                        if perm_str[4] == 'w': octal_perm += 20
                        if perm_str[5] == 'x': octal_perm += 10
                        # Other permissions
                        if perm_str[6] == 'r': octal_perm += 4
                        if perm_str[7] == 'w': octal_perm += 2
                        if perm_str[8] == 'x': octal_perm += 1
                        
                        # Check if permissions are more permissive than 640
                        if octal_perm > 640:
                            issues.append(f"{filename} (mode: {oct(octal_perm)[2:]})")
            
            if not issues:
                return "Pass: V-260601 - All audit configuration files have appropriate permissions"
            
            # First attempt - try to fix the permissions
            if attempt == 0:
                try:
                    # Fix permissions using chmod -R 640 as specified
                    subprocess.run(
                        ["chmod", "-R", "640", "/etc/audit/audit.rules", "/etc/audit/auditd.conf", "/etc/audit/rules.d/*"],
                        shell=True, check=True, capture_output=True
                    )
                    print("INFO: V-260601 - Attempted to fix file permissions")
                except subprocess.CalledProcessError as e:
                    return f"ERROR: V-260601 - Failed to fix file permissions: {str(e)}"
            else:
                # Second attempt failed, return the issues
                return f"Fail: V-260601 - Files have permissions more permissive than 640:\n" + "\n".join(issues)
        
        # If we get here after the loop, check was successful
        return "Pass: V-260601 - All audit configuration files have appropriate permissions"
        
    except Exception as e:
        return f"ERROR: V-260601 - {str(e)}"

# V-260600
# Cat 2
def check_audit_log_directory_permissions():
    try:
        grep_result = subprocess.run(
            ["grep", "-iw", "log_file", "/etc/audit/auditd.conf"],
            capture_output=True, text=True
        )
        
        if grep_result.returncode != 0:
            return f"ERROR: V-260600 - Failed to find log_file in auditd.conf: {grep_result.stderr.strip()}"
        
        log_file_path = None
        for line in grep_result.stdout.strip().split('\n'):
            if 'log_file' in line.lower() and '=' in line:
                parts = line.split('=', 1)
                if len(parts) == 2:
                    log_file_path = parts[1].strip()
                    break
        
        if not log_file_path:
            return "ERROR: V-260600 - Could not parse log_file path from auditd.conf"
        
        # Get the directory containing the audit log
        audit_log_dir = os.path.dirname(log_file_path)
        
        if not audit_log_dir:
            return "ERROR: V-260600 - Could not determine audit log directory"
        
        print(f"INFO: V-260600 - Audit log directory: {audit_log_dir}")
        
        for attempt in range(2):
            # Step 2: Check directory permissions using stat
            stat_result = subprocess.run(
                ["stat", "-c", "%n %a", audit_log_dir],
                capture_output=True, text=True
            )
            
            if stat_result.returncode != 0:
                return f"ERROR: V-260600 - Failed to stat audit log directory: {stat_result.stderr.strip()}"
            
            # Parse the stat output
            stat_output = stat_result.stdout.strip()
            parts = stat_output.split()
            
            if len(parts) < 2:
                return f"ERROR: V-260600 - Could not parse stat output: {stat_output}"
            
            directory_path = parts[0]
            current_mode = parts[1]
            
            # Convert mode to integer for comparison
            try:
                mode_int = int(current_mode, 8)  # Convert octal string to integer
                target_mode = 0o750  # 750 in octal
                
                if mode_int <= target_mode:
                    return f"Pass: V-260600"
                
                # Directory has permissions more permissive than 750
                issue_msg = f"Audit log directory {directory_path} has mode {current_mode} (more permissive than 750)"
                
                # First attempt - try to fix the permissions
                if attempt == 0:
                    try:
                        # Fix permissions using chmod -R g-w,o-rwx as specified
                        subprocess.run(
                            ["sudo", "chmod", "-R", "g-w,o-rwx", audit_log_dir],
                            check=True, capture_output=True
                        )
                        print(f"INFO: V-260600 - Attempted to fix directory permissions for {audit_log_dir}")
                    except subprocess.CalledProcessError as e:
                        return f"ERROR: V-260600 - Failed to fix directory permissions: {str(e)}"
                else:
                    # Second attempt failed, return the issue
                    return f"Fail: V-260600 - {issue_msg}"
                    
            except ValueError:
                return f"ERROR: V-260600 - Invalid mode format: {current_mode}"
        
        # If we get here after the loop, check was successful
        return f"Pass: V-260600"
        
    except Exception as e:
        return f"ERROR: V-260600 - {str(e)}"

# V-260599
# Cat 2
def check_audit_log_group_owner():
    try:
        for attempt in range(2):
            # Check the log_group setting in auditd.conf
            grep_result = subprocess.run(
                ["sudo", "grep", "-iw", "log_group", "/etc/audit/auditd.conf"],
                capture_output=True, text=True
            )
            
            current_log_group = None
            if grep_result.returncode == 0:
                for line in grep_result.stdout.strip().split('\n'):
                    if 'log_group' in line.lower() and '=' in line:
                        current_log_group = line.split('=', 1)[1].strip()
                        break
            
            if current_log_group == "root":
                return "Pass: V-260599"
            
            # First attempt - try to fix
            if attempt == 0:
                try:
                    # Read and modify auditd.conf
                    with open('/etc/audit/auditd.conf', 'r') as f:
                        content = f.read()
                    
                    # Replace existing or add new log_group setting
                    if re.search(r'^(\s*#?\s*log_group\s*=.*?)$', content, re.MULTILINE | re.IGNORECASE):
                        content = re.sub(r'^(\s*#?\s*log_group\s*=.*?)$', 'log_group = root', 
                                       content, flags=re.MULTILINE | re.IGNORECASE)
                    else:
                        content = content.rstrip() + '\nlog_group = root\n'
                    
                    with open('/etc/audit/auditd.conf', 'w') as f:
                        f.write(content)
                    
                    # Reload audit service
                    subprocess.run(["sudo", "systemctl", "kill", "auditd", "-s", "SIGHUP"], 
                                 check=True, capture_output=True)
                    
                except (IOError, subprocess.CalledProcessError) as e:
                    return f"ERROR: V-260599 - Failed to fix configuration: {str(e)}"
            else:
                # Second attempt failed
                issue = f"log_group is set to '{current_log_group}'" if current_log_group else "log_group is not set"
                return f"Fail: V-260599 - {issue}"
        
        return "Pass: V-260599"
        
    except Exception as e:
        return f"ERROR: V-260599 - {str(e)}"


if __name__ == "__main__":
    checks = [
        check_ctrl_alt_delete,
        check_rsh_server_not_installed,
        check_telnet_not_installed,
        check_ssh_not_installed,
        check_ssh_enabled
        ,check_ctrl_alt_delete_graphical
        ,get_sudo_group,
        no_null_passwords,
        no_account_null_passwords,
        check_audit_enabled_in_grub,
        check_ssh_x11_forwarding,
        check_sudo_log_audit
        ,check_execve_privilege_audit,
        check_audit_rules_combined,
        check_audit_config_group_ownership,
        check_audit_config_user_ownership,
        check_audit_config_permissions,
        check_audit_log_directory_permissions,
        check_audit_log_group_owner
    ]

    results = "\n".join(check() for check in checks)
    print(results)