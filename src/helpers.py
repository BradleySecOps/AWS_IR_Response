import sys
import getpass
from colorama import init, Fore, Style

# Initialize colorama for cross-platform colored text
init(autoreset=True)

def print_header():
    """Prints the script header."""
    print(Fore.CYAN + Style.BRIGHT + "=" * 70)
    print(Fore.CYAN + Style.BRIGHT + "=== AWS EC2 Instance Containment Script ===")
    print(Fore.CYAN + Style.BRIGHT + "===         Created by Bradley Carpenter        ===")
    print(Fore.CYAN + Style.BRIGHT + "=" * 70)
    print(Fore.YELLOW + "Purpose: To quarantine a potentially compromised EC2 instance.")
    print(Fore.YELLOW + "Disclaimer: This script modifies your AWS environment (NACLs, Instance Attributes, potentially IAM Roles and Instance State).")
    print(Fore.YELLOW + "It is intended for Incident Response scenarios. Use with caution.")
    print(Fore.YELLOW + "This script interacts only with AWS APIs and does not connect outside your specified AWS environment.")
    print(Fore.YELLOW + "If you encounter issues, please report them.")
    print("-" * 70)

def print_status(action, status, message=None):
    """Prints a formatted status line."""
    if status == "pending":
        print(f"{action}: " + Fore.YELLOW + "PENDING...")
    elif status == "complete":
        print(f"{action}: " + Fore.GREEN + "COMPLETE")
        if message: # Optionally print a success message
             print(Fore.GREEN + f"  └── {message}")
    elif status == "error":
        print(f"{action}: " + Fore.RED + "ERROR")
        if message:
            print(Fore.RED + f"  └── Error Details: {message}")
    elif status == "skipped":
         print(f"{action}: " + Fore.BLUE + "SKIPPED")
         if message:
             print(Fore.BLUE + f"  └── Reason: {message}")
    elif status == "info":
        print(f"{action}: " + Fore.BLUE + f"INFO - {message}")
    elif status == "warning":
        print(f"{action}: " + Fore.YELLOW + f"WARNING - {message}")

def get_aws_credentials():
    """Prompts user for temporary AWS credentials."""
    print(Fore.CYAN + "\n--- AWS Credentials ---")
    print("Please enter your temporary AWS credentials.")
    aws_access_key_id = input("AWS Access Key ID: ").strip()
    # Use getpass for secrets to avoid echoing them to the terminal
    aws_secret_access_key = getpass.getpass("AWS Secret Access Key: ").strip()
    aws_session_token = getpass.getpass("AWS Session Token (leave blank if none): ").strip()
    region_name = input("AWS Region (e.g., us-east-1): ").strip()

    # Basic validation
    if not all([aws_access_key_id, aws_secret_access_key, region_name]):
        print(Fore.RED + "Error: Access Key ID, Secret Access Key, and Region cannot be empty.")
        sys.exit(1)

    # Handle optional session token
    if not aws_session_token:
        aws_session_token = None

    return aws_access_key_id, aws_secret_access_key, aws_session_token, region_name

def select_target_instance(instances_map):
    """Asks user to select the target instance from the provided map."""
    if not instances_map:
        print(Fore.RED + "No instances available to select.")
        sys.exit(1)

    while True:
        target_id = input(f"\nEnter the Instance ID ({Fore.YELLOW}e.g., i-012345abcdef{Style.RESET_ALL}) to quarantine: ").strip()
        if target_id in instances_map:
            print(f"Selected instance: {target_id}")
            # Return both the ID and the full details dictionary
            return target_id, instances_map[target_id]
        else:
            print(Fore.RED + "Invalid Instance ID. Please choose from the list above.")