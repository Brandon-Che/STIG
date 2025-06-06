import os
import re
import subprocess

# V-260469 
# Cat 1
def check_ctrl_alt_delete():
    try:
        output

        for _ in range(2):
            result = subprocess.run(["systemctl","status","ctrl-alt-del.target"], capture_output=True, text=True)
            output = result.stdout + result.stderr

            print("OUTPUT: "+output)

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


### Not Done ###
# V-260539
# Cat 1
def check_ctrl_alt_delete_graphical():
    try:

        result = subprocess.run(["gsettings", "get", "org.gnome.settings-daemon.plugins.media-keys", "logout"], capture_output=True, text=True)
        output = result.stdout.strip()

        if output == "[]" or output=="@as []":
            return "Pass: V-260539"
            
        dconf_dir = "/etc/dconf/db/local.d"
        dconf_file = os.path.join(dconf_dir, "00-screensaver")
        dconf_contents = (
        "[org/gnome/settings-daemon/plugins/media-keys]\n"
        'logout=""\n'
        )
        os.makedirs(dconf_dir, exist_ok=True)
            
        with open(dconf_file, "w") as f:
            f.write(dconf_contents)

        subprocess.run(["sudo", "dconf", "update"], check=True)

        #recheck
        result = subprocess.run(["gsettings", "get", "org.gnome.settings-daemon.plugins.media-keys", "logout"], capture_output=True, text=True)
        output = result.stdout.strip()

        if output == "[]" or output=="@as []":
            return "Pass: V-260539"

        return "Fail: V-260539"
        
    except Exception as e:
        return f"ERROR: {str(e)}"       
    
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

# todo: Implement an auto fix
# V-260570
# Cat 1
def no_null_passwords():
    try:
        result = subprocess.run(["grep", "nullok", " /etc/pam.d/common-auth", " /etc/pam.d/common-password"], capture_output=True, text=True)

        if result.stdout.strip():
            return "Fail: 'nullok' found in PAM configuration(V-260570):\n" + result.stdout.strip()
        else:
            return "Pass: V-260559"
    except Exception as e:
        return f"ERROR: {str(e)}" 

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



if __name__ == "__main__":
    checks = [
        check_ctrl_alt_delete,
        check_rsh_server_not_installed,
        check_telnet_not_installed,
        check_ssh_not_installed,
        check_ssh_enabled
        #,check_ctrl_alt_delete_graphical
        ,get_sudo_group,
        no_null_passwords,
        no_account_null_passwords
    ]

    results = "\n".join(check() for check in checks)
    print(results)
    