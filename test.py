
# Combined V-260604 to V-260647 Ubuntu STIG 22.04 Audit Rules
# Cat 2
import glob
import subprocess
import time
import os


def combined():
    audit_rules = {
        # V-260604 to V-260632 - Fixed rule format inconsistencies
        'V-260632': {
            'rule': '-w /etc/shadow -p wa -k usergroup_modification',
            'check_pattern': ['-w /etc/shadow ', 'usergroup_modification'], 
            'description': 'shadow file monitoring'
        },
        'V-260631': {
            'rule': '-w /etc/passwd -p wa -k usergroup_modification',
            'check_pattern': ['-w /etc/passwd ', 'usergroup_modification'], 
            'description': 'passwd file monitoring'
        },
        'V-260630': {
            'rule': '-w /etc/security/opasswd -p wa -k usergroup_modification',
            'check_pattern': ['-w /etc/security/opasswd ', 'usergroup_modification'], 
            'description': 'opasswd file monitoring'
        },
        'V-260629': {
            'rule': '-w /etc/gshadow -p wa -k usergroup_modification',
            'check_pattern': ['-w /etc/gshadow ', 'usergroup_modification'], 
            'description': 'gshadow file monitoring'
        },
        'V-260628': {
            'rule': '-w /etc/group -p wa -k usergroup_modification',
            'check_pattern': ['-w /etc/group ', 'usergroup_modification'], 
            'description': 'group file monitoring'
        },
        'V-260627': {
            'rule': '-a always,exit -S all -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-usermod',
            'check_pattern': ['/usr/sbin/usermod'], 
            'description': 'usermod command monitoring'
        },
        'V-260626': {
            'rule': '-a always,exit -S all -F path=/sbin/unix_update -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-unix-update',
            'check_pattern': ['/sbin/unix_update'], 
            'description': 'unix_update command monitoring'
        },
        'V-260625': {
            'rule': '-a always,exit -S all -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-umount',
            'check_pattern': ['/usr/bin/umount'], 
            'description': 'umount command monitoring'
        },
        'V-260624': {
            'rule': '-a always,exit -S all -F path=/usr/bin/sudoedit -F perm=x -F auid>=1000 -F auid!=-1 -F key=priv_cmd',
            'check_pattern': ['/usr/bin/sudoedit'], 
            'description': 'sudoedit command monitoring'
        },
        'V-260623': {
            'rule': '-a always,exit -S all -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=-1 -F key=priv_cmd',
            'check_pattern': ['/usr/bin/sudo'], 
            'description': 'sudo command monitoring'
        },
        'V-260622': {
            'rule': '-a always,exit -S all -F path=/bin/su -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-priv_change',
            'check_pattern': ['/bin/su'], 
            'description': 'su command monitoring'
        },
        'V-260621': {
            'rule': '-a always,exit -S all -F path=/usr/lib/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-ssh',
            'check_pattern': ['/usr/lib/openssh/ssh-keysign'], 
            'description': 'ssh-keysign command monitoring'
        },
        'V-260620': {
            'rule': '-a always,exit -S all -F path=/usr/bin/ssh-agent -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-ssh',
            'check_pattern': ['/usr/bin/ssh-agent'], 
            'description': 'ssh-agent command monitoring'
        },
        'V-260619': {
            'rule': '-a always,exit -S all -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=-1 -F key=perm_chng',
            'check_pattern': ['/usr/bin/setfacl'], 
            'description': 'setfacl command monitoring'
        },
        'V-260618': {
            'rule': '-a always,exit -S all -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-passwd',
            'check_pattern': ['/usr/bin/passwd'], 
            'description': 'passwd command monitoring'
        },
        'V-260617': {
            'rule': '-a always,exit -S all -F path=/usr/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-pam_timestamp_check',
            'check_pattern': ['/usr/sbin/pam_timestamp_check'], 
            'description': 'pam_timestamp_check command monitoring'
        },
        'V-260616': {
            'rule': '-a always,exit -S all -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=-1 -F key=priv_cmd',
            'check_pattern': ['/usr/bin/newgrp'], 
            'description': 'newgrp command monitoring'
        },
        'V-260615': {
            'rule': '-a always,exit -S all -F path=/usr/bin/mount -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-mount',
            'check_pattern': ['/usr/bin/mount'], 
            'description': 'mount command monitoring'
        },
        'V-260614': {
            'rule': '-w /sbin/modprobe -p x -k modules',
            'check_pattern': ['-w /sbin/modprobe ', 'modules'], 
            'description': 'modprobe command monitoring'
        },
        'V-260613': {
            'rule': '-w /bin/kmod -p x -k module',
            'check_pattern': ['-w /bin/kmod ', 'module'], 
            'description': 'kmod command monitoring'
        },
        'V-260612': {
            'rule': '-a always,exit -S all -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-gpasswd',
            'check_pattern': ['/usr/bin/gpasswd'], 
            'description': 'gpasswd command monitoring'
        },
        'V-260611': {
            'rule': '-w /usr/sbin/fdisk -p x -k fdisk',
            'check_pattern': ['-w /usr/sbin/fdisk ', 'fdisk'], 
            'description': 'fdisk command monitoring'
        },
        'V-260610': {
            'rule': '-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=unset -k privileged-crontab',
            'check_pattern': ['/usr/bin/crontab'], 
            'description': 'crontab command monitoring'
        },
        'V-260609': {
            'rule': '-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=unset -k priv_cmd',
            'check_pattern': ['/usr/bin/chsh'], 
            'description': 'chsh command monitoring'
        },
        'V-260608': {
            'rule': '-a always,exit -F path=/usr/bin/chfn -F perm=x -F auid>=1000 -F auid!=unset -k privileged-chfn',
            'check_pattern': ['/usr/bin/chfn'], 
            'description': 'chfn command monitoring'
        },
        'V-260607': {
            'rule': '-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng',
            'check_pattern': ['/usr/bin/chcon'], 
            'description': 'chcon command monitoring'
        },
        'V-260606': {
            'rule': '-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=unset -k privileged-chage',
            'check_pattern': ['/usr/bin/chage'], 
            'description': 'chage command monitoring'
        },
        'V-260605': {
            'rule': '-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng',
            'check_pattern': ['/usr/bin/chacl'], 
            'description': 'chacl command monitoring'
        },
        'V-260604': {
            'rule': '-a always,exit -F path=/sbin/apparmor_parser -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng',
            'check_pattern': ['/sbin/apparmor_parser'], 
            'description': 'apparmor_parser command monitoring'
        },
        
        # Original V-260633 to V-260647 rules - Fixed format consistency
        'V-260647': {
            'rule': '-w /etc/sudoers.d -p wa -k privilege_modification', 
            'check_pattern': ['-w /etc/sudoers.d ', 'privilege_modification'], 
            'description': 'sudoers.d directory monitoring'
        },
        'V-260646': {
            'rule': '-w /etc/sudoers -p wa -k privilege_modification', 
            'check_pattern': ['-w /etc/sudoers ', 'privilege_modification'], 
            'description': 'sudoers file monitoring'
        },
        'V-260645': {
            'rule': '-w /var/log/lastlog -p wa -k logins', 
            'check_pattern': ['-w /var/log/lastlog ', 'logins'], 
            'description': 'lastlog file monitoring'
        },
        'V-260644': {
            'rule': '-w /var/log/faillog -p wa -k logins', 
            'check_pattern': ['-w /var/log/faillog ', 'logins'], 
            'description': 'faillog file monitoring'
        },
        'V-260643': {
            'rule': '-w /var/run/utmp -p wa -k logins', 
            'check_pattern': ['-w /var/run/utmp ', 'logins'], 
            'description': 'utmp file monitoring'
        },
        'V-260642': {
            'rule': '-w /var/log/wtmp -p wa -k logins', 
            'check_pattern': ['-w /var/log/wtmp ', 'logins'], 
            'description': 'wtmp file monitoring'
        },
        'V-260641': {
            'rule': '-w /var/log/btmp -p wa -k logins', 
            'check_pattern': ['-w /var/log/btmp ', 'logins'], 
            'description': 'btmp file monitoring'
        },
        'V-260640': {
            'rule': '-w /var/log/journal -p wa -k systemd_journal', 
            'check_pattern': ['-w /var/log/journal ', 'systemd_journal'], 
            'description': 'journal directory monitoring'
        },
        'V-260639': {
            'rule': ['-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat,rmdir -F auid>=1000 -F auid!=unset -k delete',
                     '-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat,rmdir -F auid>=1000 -F auid!=unset -k delete'],
            'check_pattern': ['unlink', 'unlinkat', 'rename', 'renameat', 'rmdir'], 
            'description': 'delete syscalls monitoring'
        },
        'V-260638': {
            'rule': ['-a always,exit -F arch=b32 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid>=1000 -F auid!=unset -k perm_mod',
                     '-a always,exit -F arch=b32 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid=0 -k perm_mod',
                     '-a always,exit -F arch=b64 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid>=1000 -F auid!=unset -k perm_mod',
                     '-a always,exit -F arch=b64 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid=0 -k perm_mod'],
            'check_pattern': ['setxattr', 'fsetxattr', 'lsetxattr', 'removexattr', 'fremovexattr', 'lremovexattr'], 
            'description': 'xattr syscalls monitoring'
        },
        'V-260637': {
            'rule': ['-a always,exit -F arch=b32 -S init_module,finit_module -F auid>=1000 -F auid!=unset -k module_chng',
                     '-a always,exit -F arch=b64 -S init_module,finit_module -F auid>=1000 -F auid!=unset -k module_chng'],
            'check_pattern': ['init_module', 'finit_module'], 
            'description': 'module load syscalls monitoring'
        },
        'V-260636': {
            'rule': ['-a always,exit -F arch=b32 -S delete_module -F auid>=1000 -F auid!=unset -k module_chng',
                     '-a always,exit -F arch=b64 -S delete_module -F auid>=1000 -F auid!=unset -k module_chng'],
            'check_pattern': ['delete_module'], 
            'description': 'module delete syscall monitoring'
        },
        'V-260635': {
            'rule': ['-a always,exit -F arch=b32 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k perm_access',
                     '-a always,exit -F arch=b32 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k perm_access',
                     '-a always,exit -F arch=b64 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k perm_access',
                     '-a always,exit -F arch=b64 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k perm_access'],
            'check_pattern': ['creat', 'open', 'openat', 'open_by_handle_at', 'truncate', 'ftruncate'], 
            'description': 'file access syscalls monitoring'
        },
        'V-260634': {
            'rule': ['-a always,exit -F arch=b32 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -k perm_chng',
                     '-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -k perm_chng'],
            'check_pattern': ['chown', 'fchown', 'fchownat', 'lchown'], 
            'description': 'chown syscalls monitoring'
        },
        'V-260633': {
            'rule': ['-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_chng',
                     '-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_chng'],
            'check_pattern': ['chmod', 'fchmod', 'fchmodat'], 
            'description': 'chmod syscalls monitoring'
        }
    }
    
    results = {}
    rules_to_add = []
    
    def install_auditd():
        """Install and enable auditd if not present"""
        if subprocess.run(["which", "auditctl"], capture_output=True).returncode != 0:
            print("Installing auditd...")
            subprocess.run(["apt", "install", "-y", "auditd"], check=True, capture_output=True)
            subprocess.run(["systemctl", "enable", "--now", "auditd"], check=True)
            time.sleep(3)
    
    def get_active_rules():
        """Get currently active audit rules"""
        result = subprocess.run(["auditctl", "-l"], capture_output=True, text=True)
        return result.stdout if result.returncode == 0 else ""
    
    def check_syscall_rules(rule_id, rule_info, active_rules):
        """Check if syscall audit rules are properly configured"""
        rules_list = rule_info['rule'] if isinstance(rule_info['rule'], list) else [rule_info['rule']]
        
        # Special handling for V-260635 (needs both EPERM and EACCES)
        if rule_id == 'V-260635':
            eperm_b32 = any('-EPERM' in line and 'arch=b32' in line and 
                           any(syscall in line for syscall in rule_info['check_pattern']) 
                           for line in active_rules.split('\n'))
            eacces_b32 = any('-EACCES' in line and 'arch=b32' in line and 
                            any(syscall in line for syscall in rule_info['check_pattern']) 
                            for line in active_rules.split('\n'))
            eperm_b64 = any('-EPERM' in line and 'arch=b64' in line and 
                           any(syscall in line for syscall in rule_info['check_pattern']) 
                           for line in active_rules.split('\n'))
            eacces_b64 = any('-EACCES' in line and 'arch=b64' in line and 
                            any(syscall in line for syscall in rule_info['check_pattern']) 
                            for line in active_rules.split('\n'))
            
            if eperm_b32 and eacces_b32 and eperm_b64 and eacces_b64:
                return "Pass"
        else:
            # For other syscall rules, check if patterns are found in active rules
            if len(rules_list) == 1:  # Single architecture rules
                if any(pattern in active_rules for pattern in rule_info['check_pattern']):
                    return "Pass"
            else:  # Multi-architecture rules
                found_count = sum(1 for pattern in rule_info['check_pattern'] 
                                if any(pattern in line for line in active_rules.split('\n')))
                if found_count >= len(rule_info['check_pattern']):
                    return "Pass"
        
        # Check if rules exist in config files
        for rules_file in glob.glob("/etc/audit/rules.d/*.rules"):
            try:
                with open(rules_file, 'r') as f:
                    content = f.read()
                    if all(rule in content for rule in rules_list):
                        return "Configured (reload needed)"
            except FileNotFoundError:
                continue
        
        # Add rules to be configured
        rules_to_add.extend(rules_list)
        return "Configured (reload needed)"
    
    def check_file_watch_rules(rule_id, rule_info, active_rules):
        """Check if file watch audit rules are properly configured"""
        check_patterns = rule_info['check_pattern'] if isinstance(rule_info['check_pattern'], list) else [rule_info['check_pattern']]
        
        # Check if rule is active
        rule_active = any(pattern in line and ('-p wa' in line or '-p x' in line) 
                         for line in active_rules.split('\n') 
                         for pattern in check_patterns)
        
        if rule_active:
            # Check if rule is commented out in config files
            for rules_file in glob.glob("/etc/audit/rules.d/*.rules"):
                try:
                    with open(rules_file, 'r') as f:
                        for line_num, file_line in enumerate(f, 1):
                            if (file_line.strip().startswith('#') and 
                                any(pattern in file_line for pattern in check_patterns) and 
                                ('-p wa' in file_line or '-p x' in file_line)):
                                return f"Fail: {rule_info['description']} rule commented out in {rules_file} line {line_num}"
                except Exception:
                    continue
            return "Pass"
        
        # Check if rule exists in config files
        for rules_file in glob.glob("/etc/audit/rules.d/*.rules"):
            try:
                with open(rules_file, 'r') as f:
                    if rule_info['rule'] in f.read():
                        return "Configured (reload needed)"
            except FileNotFoundError:
                continue
        
        # Add rule to be configured
        rules_to_add.append(rule_info['rule'])
        return "Configured (reload needed)"
    
    def rule_conflicts(new_rule, existing_rules):
        """Check if a new rule conflicts with existing rules"""
        for existing_rule in existing_rules:
            if new_rule.startswith('-w ') and existing_rule.startswith('-w '):
                # File watch rules conflict if they monitor the same path
                new_path = new_rule.split()[1]
                existing_path = existing_rule.split()[1]
                if new_path == existing_path:
                    return True
            elif new_rule.startswith('-a always,exit') and existing_rule.startswith('-a always,exit'):
                # Syscall rules conflict if they have same arch, syscalls, auid, and exit conditions
                if new_rule == existing_rule:
                    return True
        return False
    
    def load_rules_and_verify():
        """Load new audit rules and verify they're active"""
        if not rules_to_add:
            return get_active_rules()
        
        # Get existing rules from all files
        all_existing_rules = []
        for rules_file in glob.glob("/etc/audit/rules.d/*.rules"):
            try:
                with open(rules_file, 'r') as f:
                    all_existing_rules.extend([line.strip() for line in f 
                                             if line.strip() and not line.startswith('#')])
            except Exception:
                continue
        
        # Filter out conflicting rules
        new_rules = []
        for rule in rules_to_add:
            if not rule_conflicts(rule, all_existing_rules):
                new_rules.append(rule)
                all_existing_rules.append(rule)
        
        # Add new rules if any
        if new_rules:
            os.makedirs("/etc/audit/rules.d", exist_ok=True)
            with open("/etc/audit/rules.d/audit.rules", 'a') as f:
                f.write('\n' + '\n'.join(new_rules) + '\n')
            print(f"Added {len(new_rules)} new audit rules")
        
        # Load rules with error handling
        for attempt in range(3):
            result = subprocess.run(["augenrules", "--load"], capture_output=True, text=True)
            if result.returncode == 0 or "Rule exists" in result.stderr:
                break
            elif attempt == 0 and "There was an error in line" in result.stderr:
                print("Clearing existing rules and retrying...")
                subprocess.run(["auditctl", "-D"], capture_output=True)
                time.sleep(1)
            else:
                print(f"WARNING: Failed to load audit rules (attempt {attempt + 1}): {result.stderr.strip()}")
                if attempt == 2:
                    break
        
        time.sleep(2)
        return get_active_rules()
    
    def is_syscall_rule(rule_id):
        """Determine if a rule is a syscall rule or file watch rule"""
        syscall_rules = [
            'V-260639', 'V-260638', 'V-260637', 'V-260636', 'V-260635', 'V-260634', 'V-260633',
            'V-260627', 'V-260626', 'V-260625', 'V-260624', 'V-260623', 'V-260622', 'V-260621',
            'V-260620', 'V-260619', 'V-260618', 'V-260617', 'V-260616', 'V-260615', 'V-260612',
            'V-260610', 'V-260609', 'V-260608', 'V-260607', 'V-260606', 'V-260605', 'V-260604'
        ]
        return rule_id in syscall_rules
    
    try:
        install_auditd()
        current_rules = get_active_rules()
        
        # Check all rules
        for rule_id, rule_info in audit_rules.items():
            if is_syscall_rule(rule_id):
                results[rule_id] = check_syscall_rules(rule_id, rule_info, current_rules)
            else:
                results[rule_id] = check_file_watch_rules(rule_id, rule_info, current_rules)
        
        # Load new rules if needed
        if rules_to_add:
            final_rules = load_rules_and_verify()
            
            # Re-check rules that needed configuration
            for rule_id, rule_info in audit_rules.items():
                if results[rule_id] == "Configured (reload needed)":
                    if is_syscall_rule(rule_id):
                        # Re-check syscall rules
                        rules_list = rule_info['rule'] if isinstance(rule_info['rule'], list) else [rule_info['rule']]
                        
                        if rule_id == 'V-260635':
                            # Special check for V-260635 (needs all 4 rules)
                            eperm_b32 = any('-EPERM' in line and 'arch=b32' in line and 
                                           any(syscall in line for syscall in rule_info['check_pattern']) 
                                           for line in final_rules.split('\n'))
                            eacces_b32 = any('-EACCES' in line and 'arch=b32' in line and 
                                            any(syscall in line for syscall in rule_info['check_pattern']) 
                                            for line in final_rules.split('\n'))
                            eperm_b64 = any('-EPERM' in line and 'arch=b64' in line and 
                                           any(syscall in line for syscall in rule_info['check_pattern']) 
                                           for line in final_rules.split('\n'))
                            eacces_b64 = any('-EACCES' in line and 'arch=b64' in line and 
                                            any(syscall in line for syscall in rule_info['check_pattern']) 
                                            for line in final_rules.split('\n'))
                            
                            if eperm_b32 and eacces_b32 and eperm_b64 and eacces_b64:
                                results[rule_id] = "Pass"
                            else:
                                results[rule_id] = f"Fail: {rule_info['description']} - incomplete rules"
                        else:
                            # Regular syscall rule check
                            if any(pattern in final_rules for pattern in rule_info['check_pattern']):
                                results[rule_id] = "Pass"
                            else:
                                results[rule_id] = f"Fail: {rule_info['description']} - rule not found after configuration"
                    else:
                        # Re-check file watch rules
                        check_patterns = rule_info['check_pattern'] if isinstance(rule_info['check_pattern'], list) else [rule_info['check_pattern']]
                        rule_found = any(pattern in line and ('-p wa' in line or '-p x' in line) 
                                       for line in final_rules.split('\n') 
                                       for pattern in check_patterns)
                        
                        if rule_found:
                            results[rule_id] = "Pass"
                        else:
                            results[rule_id] = f"Fail: {rule_info['description']} - rule not found after configuration"
    
    except Exception as e:
        return f"ERROR: {str(e)}"
    
    # Sort results by rule ID for consistent output
    sorted_results = sorted(results.items(), reverse=True)
    return '\n'.join(f"{result}: {rule_id}" for rule_id, result in sorted_results)
