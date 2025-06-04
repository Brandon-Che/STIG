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



if __name__ == "__main__":
    result = check_ctrl_alt_delete()+"\n"+check_rsh_server_not_installed()+"\n"+check_telnet_not_installed()+"\n"
    print(result)
    