import os
import platform
import socket
import subprocess
import sys
from scapy.all import ARP, Ether, srp

# Silver/Gray ANSI text colors
SILVER = "\033[90m"
RESET = "\033[0m"
BOLD = "\033[1m"
CYAN = "\033[96m"


def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def draw_interface():
    clear_screen()

    # Get terminal width to align the header to the top right
    try:
        columns = os.get_terminal_size().columns
    except OSError:
        columns = 80

    # 1. Top Right Header in Silver
    header_text = "NETscanner"
    padding = columns - len(header_text)
    print(f"{' ' * padding}{SILVER}{BOLD}{header_text}{RESET}")

    # 2. Cool design of a 'G' in the center/bottom of header
    g_design = [
        "    GGGGGGGGGGGGG  ",
        "  GGG::::::::::::G ",
        " G:::::::::::::::G ",
        "G:::::GGGGGGGG::::G",
        "G::::G        GGGGG",
        "G::::G             ",
        "G::::G             ",
        "G::::G    GGGGGGGGG",
        "G::::G    G_______G",
        "G::::G        G:::G",
        " G:::::GGGGGGGG:::G",
        "  GGG::::::::::::G ",
        "     GGGGGGGGGGGG  ",
    ]

    for line in g_design:
        # Center the 'G' design visually
        print(f"{line.center(columns)}")
    print("\n" + "=" * columns + "\n")


def get_local_subnet():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        ip_parts = local_ip.split(".")
        ip_parts[-1] = "0/24"
        return ".".join(ip_parts)
    except Exception:
        return "192.168.1.0/24"
    finally:
        s.close()


def run_network_scan(scan_type):
    """Handles Option 1 (IPs only) and Option 2 (Device Names)."""
    ip_range = get_local_subnet()
    print(f"Scanning target subnet: {ip_range}...\n")

    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    try:
        result = srp(packet, timeout=2, verbose=0)[0]
    except Exception as e:
        print(f"Scan failed. Ensure you are running as Admin/Sud0. Error: {e}")
        return

    if scan_type == "ips_only":
        print(f"{'IP Address':<15} | {'MAC Address'}")
        print("-" * 35)
        for sent, received in result:
            print(f"{received.psrc:<15} | {received.hwsrc}")

    elif scan_type == "names":
        print(f"{'IP Address':<15} | {'Device Name'}")
        print("-" * 45)
        for sent, received in result:
            ip = received.psrc
            try:
                hostname, _, _ = socket.gethostbyaddr(ip)
            except socket.herror:
                hostname = "Unknown Device"
            print(f"{ip:<15} | {hostname}")


def get_current_connection_details():
    """Option 3: Displays Network Name, local IP, and saved Wi-Fi password (Windows only)."""
    # Get Local IP
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    local_ip = "Unknown"
    try:
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
    except Exception:
        pass
    finally:
        s.close()

    print(f"Local IP Address: {local_ip}")

    # Windows-specific Wi-Fi profile check
    if platform.system() == "Windows":
        try:
            # Get the active Wi-Fi interface profile name
            interface_output = subprocess.check_output(
                "netsh wlan show interfaces", shell=True, text=True
            )
            ssid = "Not Connected / Ethernet"
            for line in interface_output.split("\n"):
                if "SSID" in line and "BSSID" not in line:
                    ssid = line.split(":")[1].strip()
                    break

            print(f"Network Name (SSID): {ssid}")

            if ssid != "Not Connected / Ethernet":
                # Fetch security key for the active SSID
                profile_output = subprocess.check_output(
                    f'netsh wlan show profile name="{ssid}" key=clear',
                    shell=True,
                    text=True,
                )
                password = "None (Open Network or Hidden)"
                for line in profile_output.split("\n"):
                    if "Key Content" in line:
                        password = line.split(":")[1].strip()
                        break
                print(f"Stored Wi-Fi Password: {password}")
        except Exception:
            print("Network Name: Unable to parse Wi-Fi profile details.")
            print(
                "Password: Could not retrieve. (Ensure tool is run as Administrator)"
            )
    else:
        print(
            f"Network Details: Password extraction via netsh is only configured for Windows environments."
        )


def main_menu():
    while True:
        draw_interface()
        print(f"{CYAN}--- MAIN MENU ---{RESET}")
        print("1. Scan for IP Addresses")
        print("2. Scan for Device Names")
        print("3. Show Current Connection Details (Name, Password, IP)")
        print("4. Exit")

        choice = input("\nSelect an option (1-4): ").strip()

        if choice == "1":
            clear_screen()
            run_network_scan("ips_only")
        elif choice == "2":
            clear_screen()
            run_network_scan("names")
        elif choice == "3":
            clear_screen()
            get_current_connection_details()
        elif choice == "4":
            print("Exiting tool.")
            sys.exit(0)
        else:
            print("Invalid option. Please try again.")

        input("\nPress Enter to return to the menu...")


if __name__ == "__main__":
    # Ensure ANSI rendering is enabled on Windows command prompt
    if os.name == "nt":
        os.system("")
    main_menu()
