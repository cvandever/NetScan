import subprocess
import sys
import platform

def is_nmap_installed():
    try:
        subprocess.run(["nmap", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return True
    except FileNotFoundError:
        return False

def install_nmap():
    system_platform = platform.system().lower()
    
    if system_platform == "linux":
        try:
            subprocess.run(["sudo", "apt-get", "install", "nmap"], check=True)
            print("Nmap has been installed successfully.")
        except subprocess.CalledProcessError:
            print("Nmap installation failed.")
    elif system_platform == "windows":
        try:
            subprocess.run(["winget", "install", "Nmap"], check=True)
            print("Nmap has been installed successfully.")
        except subprocess.CalledProcessError:
            print("Nmap installation failed.")
    else:
        print("Unsupported operating system for Nmap installation.")

def check_and_install():
    if not is_nmap_installed():
        print("Nmap is not installed.")
        response = input("Do you want to install Nmap? (y/n): ")
        if response.lower() == "y":
            install_nmap()
        else:
            sys.exit("Nmap installation canceled.")
    else:
        print("Nmap is already installed.")