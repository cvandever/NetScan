from check_nmap import check_and_install, subprocess

def main():
    try:
        check_and_install()
        
        target_ip = "10.10.221.0/24"
        
        # Construct the Nmap command
        nmap_command = ["nmap", "-sV","--script=host_script.nse", target_ip]
        
        # Run the Nmap scan using subprocess
        process = subprocess.Popen(nmap_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()
        
        # Check for errors and write the scan output to a file
        if process.returncode == 0:
            print("Scan completed successfully.")
            with open("scan_results.txt", "w") as f:
                f.write(stdout)
        else:
            print(f"An error occurred: {stderr}")
            
        
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
