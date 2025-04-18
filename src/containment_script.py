#!/usr/bin/env python3

"""
AWS EC2 Instance Containment Script

Purpose: To quarantine a potentially compromised EC2 instance by applying network
         restrictions (NACLs), gathering instance information, taking EBS snapshots,
         revoking associated IAM role sessions, and stopping the instance.

Disclaimer: This script modifies your AWS environment. It is intended for
            Incident Response scenarios. Use with caution and ensure you have the
            necessary permissions and understanding of its actions.

Created by: Bradley Carpenter
"""

import sys
import boto3
import logging
from datetime import datetime
from botocore.exceptions import BotoCoreError, ClientError
from colorama import Fore, Style

# Import functions from our modules (relative imports for package structure)
from .helpers import (print_header, print_status, get_aws_credentials,
                     select_target_instance)
from .aws_interactions import (validate_credentials, list_ec2_instances,
                              apply_sg_containment, enable_termination_protection, # Changed NACL to SG
                              check_autoscaling_groups, check_load_balancers,
                              get_instance_role_info, check_imds_version,
                              find_instances_with_same_role, get_role_permissions,
                              revoke_role_sessions, get_ebs_volumes,
                              describe_and_update_volume_sizes, snapshot_ebs_volumes,
                              stop_instance, perform_preflight_checks,
                              collect_and_upload_logs, _check_ssm_agent) # Added imports
# Import configuration constants (relative import)
from .config import CONTAINMENT_SG_NAME, DENY_POLICY_NAME # Changed NACL to SG

# --- Logging Setup ---
def setup_logging():
    """Sets up file logging."""
    # Log file will be created in the directory where the script is run from
    log_filename = f"containment_script_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    log_format = '%(asctime)s - %(levelname)s - %(message)s'
    logging.basicConfig(level=logging.INFO,
                        format=log_format,
                        filename=log_filename,
                        filemode='w') # Overwrite log file each run

    logging.info("Logging initialized.")
    print(f"Detailed logs will be written to: {log_filename}") # Inform user about log file
    return log_filename

# --- Main Execution Logic ---
def main():
    """Main function to orchestrate the instance containment process."""
    log_file = setup_logging() # Setup logging first
    logging.info("Starting AWS EC2 Instance Containment Script.")
    action_summary = {} # Dictionary to store action outcomes

    print_header() # Keep console header
    logging.info("Printed script header.")
    action_summary['00_ScriptStart'] = {'status': 'Initiated', 'details': f"Script started at {datetime.now().isoformat()}"}

    # 1. Get AWS Credentials from User
    logging.info("Attempting to get AWS credentials from user.")
    access_key, secret_key, session_token, region = get_aws_credentials()
    # The except KeyboardInterrupt for this is handled by the main try/except at the bottom

    # 2. Create Boto3 Session & Clients
    logging.info("Initializing Boto3 session and clients.")
    print_status("Initializing AWS Session", "pending") # Keep console status
    try:
        session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            aws_session_token=session_token,
            region_name=region
        )
        # Initialize all necessary service clients
        ec2 = session.client('ec2')
        iam = session.client('iam')
        autoscaling = session.client('autoscaling')
        elb = session.client('elb')       # Classic Load Balancer client
        elbv2 = session.client('elbv2')   # Application/Network Load Balancer client
        ssm_client = session.client('ssm') # Added SSM client needed earlier now
        logging.info("Boto3 session and clients initialized successfully.")
        print_status("Initializing AWS Session", "complete")
    except (BotoCoreError, ClientError) as e:
        logging.error(f"Failed to create Boto3 session or clients: {e}", exc_info=True)
        print_status("Initializing AWS Session", "error", f"Failed to create Boto3 session or clients: {e}")
        sys.exit(1)
    except Exception as e: # Catch any other unexpected errors during session creation
        logging.error(f"An unexpected error occurred during session setup: {e}", exc_info=True)
        print_status("Initializing AWS Session", "error", f"An unexpected error occurred during session setup: {e}")
        sys.exit(1)

    # 3. Validate Credentials & Confirm Account
    # This function handles its own exit or continuation logic based on user input
    logging.info("Validating credentials and confirming account.")
    validated, missing_perms = validate_credentials(session) # This function now handles its own exit/logging for failure
    action_summary['03_ValidateCredentials'] = {'status': 'Success' if validated else 'Partial Success (User Override)', 'details': f"Missing permissions: {missing_perms or 'None'}"}
    logging.info(f"Credential validation completed. Result: {validated}. Missing permissions identified: {missing_perms}")
    # Note: Script might continue even if validation returns False (with missing perms), as per user choice in validate_credentials

    logging.info("Starting main containment process.")
    print("\n" + Fore.CYAN + "--- Starting Containment Process ---") # Keep console separator

    # 4. List Available EC2 Instances
    logging.info("Listing available EC2 instances.")
    instances_map = list_ec2_instances(ec2)
    if not instances_map:
        logging.warning("No suitable instances found in the specified region. Exiting.")
        print(Fore.YELLOW + "Exiting as no suitable instances were found in the specified region.")
        sys.exit(0)

    # 5. Select Target Instance
    logging.info("Prompting user to select target instance.")
    try:
        target_instance_id, target_instance_details = select_target_instance(instances_map)
    except KeyboardInterrupt:
        logging.warning("Operation cancelled by user during instance selection.")
        print("\nOperation cancelled by user during instance selection.")
        sys.exit(1)

    # Extract necessary details from the selected instance
    logging.info(f"Target instance selected: {target_instance_id}")
    vpc_id = target_instance_details.get('VpcId')
    subnet_id = target_instance_details.get('SubnetId')

    if not vpc_id or not subnet_id:
        error_msg = f"Could not determine VPC ID ('{vpc_id}') or Subnet ID ('{subnet_id}') for instance {target_instance_id}. Cannot proceed."
        logging.error(error_msg)
        print(Fore.RED + "Error: " + error_msg)
        sys.exit(1)

    logging.info(f"Target details - VPC: {vpc_id}, Subnet: {subnet_id}")
    print(f"\nTargeting Instance: {Fore.YELLOW}{target_instance_id}{Style.RESET_ALL} in VPC: {vpc_id}, Subnet: {subnet_id}")
    print("-" * 70) # Keep console separator

    # --- Gather Info Needed for Pre-flight ---
    logging.info("Gathering preliminary info for pre-flight checks...")
    # Get Role Info (formerly step 10)
    instance_role_name, instance_profile_arn = get_instance_role_info(ec2, iam, target_instance_details)
    logging.info(f"Preliminary Role Info - Role Name: {instance_role_name}, Profile ARN: {instance_profile_arn}")
    # Get EBS Volumes (formerly step 15) - Need this info for pre-flight
    attached_volumes = get_ebs_volumes(target_instance_details) # This function prints status but doesn't return it easily for summary yet
    action_summary['05a_GetEBSVolumes'] = {'status': 'Info Gathered', 'details': f"Found {len(attached_volumes)} EBS volume(s)."} # Basic tracking
    logging.info(f"Preliminary EBS Info - Found {len(attached_volumes)} attached EBS volume(s).")
    logging.info("Finished gathering preliminary info.")

    # --- Pre-flight Checks ---
    logging.info("Starting pre-flight checks.")
    preflight_success, preflight_issues = perform_preflight_checks(
        session, target_instance_id, target_instance_details, vpc_id, subnet_id, instance_role_name, attached_volumes
    )
    logging.info(f"Pre-flight checks completed. Success: {preflight_success}, Issues: {preflight_issues}")
    action_summary['05b_PreflightChecks'] = {'status': 'Success' if preflight_success else 'Failed', 'details': f"Issues found: {preflight_issues or 'None'}"}

    if not preflight_success:
        error_msg = "Critical pre-flight checks failed. Cannot guarantee successful execution. Exiting."
        logging.error(error_msg)
        print(Fore.RED + Style.BRIGHT + f"\nError: {error_msg}")
        print(Fore.RED + "Please review the errors above and in the log file.")
        sys.exit(1)
    elif preflight_issues:
        # Warnings were found, prompt user
        print(Fore.YELLOW + "\nPre-flight checks passed with warnings (see details above).")
        cont = input(f"Do you want to continue with the containment process despite the warnings? ({Fore.YELLOW}yes/no{Style.RESET_ALL}): ").lower().strip()
        if cont != 'yes':
            logging.warning("User chose not to continue after pre-flight warnings. Exiting.")
            print(Fore.RED + "Operation cancelled by user due to pre-flight warnings.")
            sys.exit(1)
        logging.warning("User chose to continue despite pre-flight warnings.")
    else:
        logging.info("Pre-flight checks successful.")

    # --- Execute Containment Steps ---
    logging.info("Proceeding with containment actions...")
    print("\n" + Fore.CYAN + "--- Executing Containment Actions ---")

    # Step numbering adjusted for clarity after adding pre-flight
    logging.info("Step 6: Applying Security Group containment.")
    # Call the new SG function, passing instance_details instead of subnet_id
    sg_containment_success, original_sg_ids = apply_sg_containment(ec2, vpc_id, target_instance_id, target_instance_details)
    action_summary['06_SGContainment'] = {'status': 'Success' if sg_containment_success else 'Failed', 'details': f"Containment SG '{CONTAINMENT_SG_NAME}' applied. Original SGs: {original_sg_ids}"}
    logging.info("Step 6: Security Group containment function finished.")

    logging.info("Step 7: Enabling termination protection.")
    term_prot_success = enable_termination_protection(ec2, target_instance_id)
    action_summary['07_TerminationProtection'] = {'status': 'Success' if term_prot_success else 'Failed'}
    logging.info("Step 7: Termination protection function finished.")

    logging.info("Step 8: Checking Auto Scaling Group membership.")
    check_autoscaling_groups(autoscaling, target_instance_id)
    logging.info("Step 8: Auto Scaling Group check finished.")

    logging.info("Step 9: Checking Load Balancer membership.")
    check_load_balancers(elb, elbv2, target_instance_id)
    logging.info("Step 9: Load Balancer check finished.")

    # Role info already gathered before pre-flight
    logging.info("Step 10: Attached IAM role info already gathered.")

    logging.info("Step 11: Checking IMDS version.")
    check_imds_version(ec2, target_instance_details)
    logging.info("Step 11: IMDS version check finished.")

    # --- Role-Specific Actions (Only if a role was identified) ---
    if instance_role_name:
        logging.info(f"Performing IAM role actions for role: {instance_role_name}")
        print("\n" + Fore.CYAN + f"--- IAM Role Actions ({instance_role_name}) ---") # Keep console separator

        logging.info("Step 12: Finding other instances with the same role profile.")
        find_instances_with_same_role(ec2, instance_profile_arn, target_instance_id)
        logging.info("Step 12: Finding similar instances finished.")

        logging.info("Step 13: Getting role permissions.")
        get_role_permissions(iam, instance_role_name)
        logging.info("Step 13: Getting role permissions finished.")

        logging.info("Step 14: Offering to revoke role sessions.")
        # Note: revoke_role_sessions has internal logic based on user input, difficult to capture exact outcome here without modifying it significantly.
        # We'll record that the step was offered/attempted.
        revoke_role_sessions(iam, instance_role_name) # Returns None currently
        action_summary['14_RevokeRoleSessions'] = {'status': 'Attempted/Offered', 'details': f"Check logs for user choice and outcome for role {instance_role_name}."}
        logging.info("Step 14: Role session revocation function finished.")
    else:
        skip_msg = "Skipping IAM role permission checks and session revocation as the specific IAM Role name could not be determined or no role is attached."
        action_summary['12_FindSimilarInstances'] = {'status': 'Skipped', 'details': skip_msg}
        action_summary['13_GetRolePermissions'] = {'status': 'Skipped', 'details': skip_msg}
        action_summary['14_RevokeRoleSessions'] = {'status': 'Skipped', 'details': skip_msg}
        logging.info(skip_msg)
        print("\n" + Fore.BLUE + skip_msg) # Keep console message

    # --- EBS Volume Actions (Forensic Preparation) ---
    logging.info("Starting EBS volume analysis and snapshotting.")
    print("\n" + Fore.CYAN + "--- EBS Volume Analysis & Snapshots ---") # Keep console separator

    # Volume info already gathered before pre-flight
    logging.info("Step 15: Attached EBS volume info already gathered.")

    logging.info("Step 16: Getting EBS volume sizes.")
    # Use the 'attached_volumes' list gathered earlier
    attached_volumes_with_size = describe_and_update_volume_sizes(ec2, attached_volumes)
    logging.info("Step 16: Volume size check finished.")

    logging.info("Step 17: Offering to snapshot volumes.")
    # Note: snapshot_ebs_volumes has internal logic based on user input.
    snapshot_ebs_volumes(ec2, attached_volumes_with_size, target_instance_id) # Returns None currently
    action_summary['17_SnapshotVolumes'] = {'status': 'Attempted/Offered', 'details': f"Check logs for user choice and snapshot IDs/status for volumes: {[v['VolumeId'] for v in attached_volumes_with_size]}"}
    logging.info("Step 17: Snapshotting function finished.")

    # --- Check SSM Agent Status (Before Stop) ---
    logging.info("Step 18: Checking SSM Agent status.")
    ssm_status = _check_ssm_agent(ssm_client, target_instance_id)
    action_summary['18_CheckSSMAgent'] = {'status': 'Online' if ssm_status else 'Offline/Error/NotManaged', 'details': 'Check logs for details.'}
    logging.info("Step 18: SSM Agent check finished.")


    # --- Final Action: Stop Instance ---
    logging.info("Step 19: Offering to stop the instance.")
    # Note: stop_instance has internal logic based on user input.
    stop_instance(ec2, target_instance_id) # Returns None currently
    action_summary['19_StopInstance'] = {'status': 'Attempted/Offered', 'details': f"Check logs for user choice and outcome."}
    logging.info("Step 19: Stop instance function finished.")

    # --- Log Collection (Optional) ---
    # Retrieve account_id again safely in case it wasn't passed correctly initially
    try:
        account_id = session.client('sts').get_caller_identity().get('Account')
    except Exception as sts_err:
        logging.error(f"Could not re-confirm account ID for log collection: {sts_err}")
        account_id = "unknown-account" # Fallback

    logging.info("Step 20: Offering log collection and upload.")
    # Pass the action summary to the log collection function
    log_collection_result = collect_and_upload_logs(session, target_instance_id, account_id, region, action_summary)
    action_summary['20_LogCollection'] = {'status': 'Attempted/Offered', 'details': f"Check logs for user choice and outcome. Result: {log_collection_result}"} # Basic tracking
    logging.info("Step 20: Log collection function finished.")


    # --- Completion Summary ---
    summary_msg = f"Containment script finished for instance {target_instance_id}."
    logging.info(summary_msg)
    logging.info(f"Detailed execution logs available in: {log_file}")

    print("\n" + Fore.CYAN + Style.BRIGHT + "=" * 70)
    print(Fore.CYAN + Style.BRIGHT + "=== Containment Script Finished ===")
    print(f"Review the console output above and the log file '{log_file}' for detailed status.")
    print(Fore.YELLOW + "Next Steps: Follow your organization's Incident Response procedures.")
    print(Fore.YELLOW + "This may include forensic analysis of snapshots, reviewing CloudTrail logs,")
    print(Fore.YELLOW + "analyzing compromised role permissions, and remediating the root cause.")
    print("-" * 70)
    print(Fore.YELLOW + Style.BRIGHT + "Cleanup Reminder:")
    # Construct cleanup messages for logging and printing
    # Updated cleanup message for Security Groups
    original_sg_ids_str = ', '.join(original_sg_ids) if sg_containment_success else '(Check Logs/AWS Console)'
    cleanup_sg = f"- Manually re-attach original Security Group(s) ({original_sg_ids_str}) to instance {target_instance_id} and delete the containment SG ('{CONTAINMENT_SG_NAME}') once no longer needed."
    cleanup_role = ""
    if instance_role_name: # Only remind about policy if role revocation was attempted
        cleanup_role = f"- Manually review and remove the inline policy ('{DENY_POLICY_NAME}') from IAM role '{instance_role_name}' after remediation."
    cleanup_term = "- Consider disabling termination protection if the instance needs to be terminated later."

    logging.info("Cleanup Reminder:" + cleanup_sg) # Use SG cleanup message
    print(Fore.YELLOW + cleanup_sg) # Use SG cleanup message
    if cleanup_role:
        logging.info("Cleanup Reminder:" + cleanup_role)
        print(Fore.YELLOW + cleanup_role)
    logging.info("Cleanup Reminder:" + cleanup_term)
    print(Fore.YELLOW + cleanup_term)
    print(Fore.CYAN + Style.BRIGHT + "=" * 70)

# --- Script Entry Point ---
if __name__ == "__main__":
    log_file_name = None # Initialize log file name
    try:
        # Assign log file name globally if setup succeeds
        log_file_name = setup_logging()
        main()
    except KeyboardInterrupt:
        if log_file_name: logging.warning("Operation cancelled by user via KeyboardInterrupt.")
        print("\n\nOperation cancelled by user. Exiting.")
        sys.exit(1)
    except SystemExit as e:
        # Log SystemExit calls (e.g., from validation failures)
        if log_file_name: logging.warning(f"Script exited intentionally with code {e.code}.")
        # No need to print again, previous functions handle user messages
        raise # Re-raise to ensure script actually exits
    except Exception as e:
        # Catch-all for any unexpected errors not handled within specific functions
        if log_file_name: logging.critical(f"An unexpected critical error occurred: {e}", exc_info=True)
        print(Fore.RED + Style.BRIGHT + "\n--- UNEXPECTED SCRIPT ERROR ---")
        print(Fore.RED + f"An unexpected error occurred: {e}")
        print(Fore.RED + "Please review the script output and log file for details.")
        if log_file_name:
             print(Fore.RED + f"Log file: {log_file_name}")
        sys.exit(1)