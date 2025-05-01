import sys
import time
import logging
from datetime import datetime
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError, WaiterError
from colorama import Fore, Style

# Import helper functions and configuration
from .helpers import print_status
from .config import CONTAINMENT_SG_NAME, DENY_POLICY_NAME # Updated import

# --- AWS Interaction Functions ---

def validate_credentials(session):
    """
    Checks basic credential validity, confirms the target account,
    and checks some key permissions using the provided session.
    """
    action = "Validating Credentials & Confirming Account"
    print_status(action, "pending")
    missing_permissions = []
    account_id = None
    account_alias = "N/A" # Default if alias cannot be retrieved

    try:
        # --- Initial Authentication & Account Identification ---
        sts_client = session.client('sts')
        iam_client = session.client('iam') # Need IAM client earlier for alias lookup
        ec2_client = session.client('ec2')

        caller_id = sts_client.get_caller_identity()
        account_id = caller_id.get('Account')
        print(Fore.GREEN + f"  └── Successfully authenticated as: {caller_id.get('Arn', 'Unknown ARN')}")

        if account_id:
            print(f"  └── AWS Account ID: {Fore.CYAN}{account_id}{Style.RESET_ALL}")
            # Attempt to get account alias (requires iam:ListAccountAliases)
            try:
                alias_response = iam_client.list_account_aliases()
                aliases = alias_response.get('AccountAliases', [])
                if aliases:
                    account_alias = aliases[0]
                    print(f"  └── AWS Account Alias: {Fore.CYAN}{account_alias}{Style.RESET_ALL}")
                else:
                    print(f"  └── AWS Account Alias: {Fore.YELLOW}(No alias found){Style.RESET_ALL}")
                    account_alias = "(No alias found)" # Update default
            except ClientError as alias_err:
                if alias_err.response['Error']['Code'] in ['AccessDenied', 'AccessDeniedException']:
                    print(f"  └── AWS Account Alias: {Fore.YELLOW}(Permission denied for iam:ListAccountAliases){Style.RESET_ALL}")
                    account_alias = "(Permission Denied)" # Update default
                    missing_permissions.append("iam:ListAccountAliases (to display account name)") # Add as missing, but non-critical
                else:
                    print(f"  └── AWS Account Alias: {Fore.YELLOW}(Error checking alias: {alias_err}){Style.RESET_ALL}")
                    account_alias = "(Error)" # Update default
            except Exception as alias_exc: # Catch other potential errors
                 print(f"  └── AWS Account Alias: {Fore.YELLOW}(Unexpected error checking alias: {alias_exc}){Style.RESET_ALL}")
                 account_alias = "(Error)"

            # --- Account Confirmation Prompt ---
            print("-" * 40)
            confirm = input(f"Is this the correct AWS Account ({Fore.CYAN}{account_id} / {account_alias}{Style.RESET_ALL}) you want to target? ({Fore.YELLOW}yes/no{Style.RESET_ALL}): ").lower().strip()
            print("-" * 40)
            if confirm != 'yes':
                print(Fore.RED + "Operation cancelled by user. Exiting to prevent actions on the wrong account.")
                sys.exit(1)
            # --- End Account Confirmation ---
        else:
            # Should not happen if get_caller_identity worked, but handle defensively
            print(Fore.RED + "Could not determine AWS Account ID from credentials. Exiting.")
            sys.exit(1)


        # --- Basic Permission Check (proceed only after account confirmation) ---
        print_status("Checking Key Permissions", "pending") # Separate status for this part
        try:
            # Check EC2 read permission
            ec2_client.describe_instances(MaxResults=5)
        except ClientError as e:
            if e.response['Error']['Code'] == 'UnauthorizedOperation':
                missing_permissions.append("ec2:DescribeInstances")
            # Handle potential variations in pagination parameters across Boto3 versions
            elif 'Unknown parameter' in str(e) and 'MaxResults' in str(e):
                 print(Fore.YELLOW + "Warning: Boto3 version might have slight variations in DescribeInstances pagination parameters. Continuing...")
            else:
                # Log other unexpected client errors during the check
                print(Fore.YELLOW + f"Warning during EC2 check: {e}")

        try:
            # Check IAM read permission (using MaxItems for list_roles)
            iam_client.list_roles(MaxItems=1)
        except ClientError as e:
             if e.response['Error']['Code'] == 'UnauthorizedOperation':
                 missing_permissions.append("iam:ListRoles (or similar read permissions)")
             else:
                 # Log other unexpected client errors during the check
                 print(Fore.YELLOW + f"Warning during IAM check: {e}")

        # Check if only non-critical permissions (like ListAccountAliases) are missing
        critical_missing = [p for p in missing_permissions if "iam:ListAccountAliases" not in p]

        if not critical_missing:
            # If only ListAccountAliases was missing (or none were), mark as complete
            print_status("Checking Key Permissions", "complete")
            # Return True indicating core validation passed, along with potentially missing non-critical perms
            return True, missing_permissions
        else:
            # If critical permissions are missing
            error_msg = f"Missing critical permissions: {', '.join(critical_missing)}. Full functionality may be limited."
            print_status("Checking Key Permissions", "warning", error_msg)
            # Ask user if they want to proceed despite missing critical permissions
            cont = input(f"Continue anyway with missing critical permissions? ({Fore.YELLOW}yes/no{Style.RESET_ALL}): ").lower().strip()
            if cont != 'y':
                 print(Fore.RED + "Exiting due to missing critical permissions.")
                 sys.exit(1)
            # Return False indicating critical validation failed, but user chose to continue
            return False, missing_permissions

    except (NoCredentialsError, PartialCredentialsError):
        print_status(action, "error", "AWS credentials not found, incomplete, or invalid.")
        sys.exit(1)
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code")
        if error_code == 'ExpiredToken':
             msg = "AWS session token has expired."
        elif error_code == 'InvalidClientTokenId':
             msg = "Invalid AWS Access Key ID or Session Token."
        elif error_code == 'SignatureDoesNotMatch':
             msg = "Invalid AWS Secret Access Key."
        else:
            msg = f"An AWS error occurred during credential validation: {e}"
        print_status(action, "error", msg)
        sys.exit(1)
    except Exception as e:
        # Catch potential validation errors specifically if possible
        if 'Parameter validation failed' in str(e) and 'MaxItems' in str(e):
             print_status(action, "error", f"Parameter validation failed for iam:ListRoles check: {e}. Check Boto3 version or IAM API changes.")
        else:
            print_status(action, "error", f"An unexpected error occurred during credential validation: {e}")
        sys.exit(1)

def list_ec2_instances(ec2_client):
    """Lists running or stopped EC2 instances using the provided EC2 client."""
    action = "Listing EC2 Instances"
    print_status(action, "pending")
    instances_map = {} # Dictionary to store instance details keyed by ID
    try:
        paginator = ec2_client.get_paginator('describe_instances')
        # Filter for instances that are either running or stopped
        pages = paginator.paginate(Filters=[{'Name': 'instance-state-name', 'Values': ['running', 'stopped']}])

        print("\nAvailable EC2 Instances (Running or Stopped):")
        print("-" * 40)
        count = 0
        for page in pages:
            for reservation in page.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    instance_id = instance['InstanceId']
                    instance_state = instance['State']['Name']
                    # Extract the 'Name' tag if it exists
                    instance_name = "N/A"
                    if 'Tags' in instance:
                        for tag in instance['Tags']:
                            if tag['Key'] == 'Name':
                                instance_name = tag['Value']
                                break
                    print(f"  - ID: {instance_id}, Name: {instance_name}, State: {instance_state}")
                    instances_map[instance_id] = instance # Store full instance details
                    count += 1

        if count == 0:
            print(Fore.YELLOW + "  No running or stopped instances found in this region.")
            print_status(action, "skipped", "No instances found.")
            return None # Return None if no instances are found

        print("-" * 40)
        print_status(action, "complete")
        return instances_map
    except ClientError as e:
        print_status(action, "error", f"Failed to list EC2 instances: {e}")
        return None
    except Exception as e:
        print_status(action, "error", f"An unexpected error occurred listing instances: {e}")
        return None

# --- NEW FUNCTION: Apply Security Group Containment ---
def apply_sg_containment(ec2_client, vpc_id, target_instance_id, instance_details):
    """
    Creates/finds an isolation Security Group and applies it exclusively
    to the target instance, removing its existing SGs.
    Returns tuple: (success_boolean, list_of_original_sg_ids)
    """
    action = f"Applying Security Group Containment ({CONTAINMENT_SG_NAME})"
    print_status(action, "pending")
    containment_sg_id = None
    original_sg_ids = [sg['GroupId'] for sg in instance_details.get('SecurityGroups', [])]
    logging.info(f"Original Security Groups for {target_instance_id}: {original_sg_ids}")

    try:
        # 1. Check if the containment SG already exists in the VPC
        print(f"  └── Checking for existing Security Group: {CONTAINMENT_SG_NAME}")
        response_existing = ec2_client.describe_security_groups(
            Filters=[
                {'Name': 'vpc-id', 'Values': [vpc_id]},
                {'Name': 'group-name', 'Values': [CONTAINMENT_SG_NAME]}
            ]
        )

        if response_existing.get('SecurityGroups'):
            containment_sg_id = response_existing['SecurityGroups'][0]['GroupId']
            print(f"  └── Found existing Containment SG: {containment_sg_id}")
        else:
            # 2. Create the new 'Containment SG' if it doesn't exist
            print(f"  └── Creating new Security Group: {CONTAINMENT_SG_NAME}")
            sg_response = ec2_client.create_security_group(
                GroupName=CONTAINMENT_SG_NAME,
                Description=f"Isolation SG for Incident Response - Applied to {target_instance_id}",
                VpcId=vpc_id,
                TagSpecifications=[{
                    'ResourceType': 'security-group',
                    'Tags': [{'Key': 'Name', 'Value': CONTAINMENT_SG_NAME}]
                }]
            )
            containment_sg_id = sg_response['GroupId']
            print(f"  └── Created Containment SG ID: {containment_sg_id}")

            # 3. Remove the default Egress rule (Allow All)
            #    New SGs usually have a default allow-all egress rule. We need to remove it for isolation.
            try:
                print(f"  └── Revoking default egress rule from {containment_sg_id}")
                # Describe to be sure about the default rule, though this is standard
                sg_details = ec2_client.describe_security_groups(GroupIds=[containment_sg_id])
                default_egress_rules = sg_details['SecurityGroups'][0].get('IpPermissionsEgress', [])

                if default_egress_rules:
                     # Attempt to revoke the common default rule first
                     try:
                         ec2_client.revoke_security_group_egress(
                             GroupId=containment_sg_id,
                             IpPermissions=[{
                                 'IpProtocol': '-1', # All protocols
                                 'IpRanges': [{'CidrIp': '0.0.0.0/0'}], # All IPv4
                                 'Ipv6Ranges': [],
                                 'PrefixListIds': [],
                                 'UserIdGroupPairs': []
                             }]
                         )
                         print(f"  └── Successfully revoked default IPv4 egress rule.")
                     except ClientError as revoke_err_ipv4:
                         if revoke_err_ipv4.response['Error']['Code'] == 'InvalidPermission.NotFound':
                             print(f"  └── Default IPv4 egress rule likely already removed or different.")
                         else:
                             raise revoke_err_ipv4 # Re-raise other errors

                     # Also attempt to revoke default IPv6 if present
                     try:
                         ec2_client.revoke_security_group_egress(
                             GroupId=containment_sg_id,
                             IpPermissions=[{
                                 'IpProtocol': '-1', # All protocols
                                 'IpRanges': [],
                                 'Ipv6Ranges': [{'CidrIpv6': '::/0'}], # All IPv6
                                 'PrefixListIds': [],
                                 'UserIdGroupPairs': []
                             }]
                         )
                         print(f"  └── Successfully revoked default IPv6 egress rule.")
                     except ClientError as revoke_err_ipv6:
                         if revoke_err_ipv6.response['Error']['Code'] == 'InvalidPermission.NotFound':
                             print(f"  └── Default IPv6 egress rule likely already removed or different.")
                         else:
                             raise revoke_err_ipv6 # Re-raise other errors
                else:
                    print(f"  └── No default egress rules found to revoke (already isolated).")

            except ClientError as revoke_err:
                # Catch errors during revoke attempt
                print_status(action, "warning", f"Could not revoke default egress rule from {containment_sg_id}: {revoke_err}. Manual check recommended.")
                # Continue, as applying the SG is the main goal

        # 4. Apply *only* the Containment SG to the instance
        print(f"  └── Applying {containment_sg_id} exclusively to instance {target_instance_id}")
        ec2_client.modify_instance_attribute(
            InstanceId=target_instance_id,
            Groups=[containment_sg_id] # This replaces existing SGs
        )
        print(f"  └── Instance {target_instance_id} is now associated ONLY with {containment_sg_id}")

        print_status(action, "complete")
        # Return success and original SG IDs for logging/rollback info
        return True, original_sg_ids

    except ClientError as e:
        error_msg = f"Failed during Security Group operations: {e}"
        print_status(action, "error", error_msg)
        logging.error(f"{action} Error: {error_msg}", exc_info=True)
        return False, original_sg_ids # Return original IDs even on failure
    except Exception as e:
        error_msg = f"An unexpected error occurred during SG ops: {e}"
        print_status(action, "error", error_msg)
        logging.error(f"{action} Error: {error_msg}", exc_info=True)
        return False, original_sg_ids

# --- END NEW FUNCTION ---


def enable_termination_protection(ec2_client, instance_id):
    """Enables termination protection on the specified instance."""
    action = f"Enabling Termination Protection for {instance_id}"
    print_status(action, "pending")
    try:
        ec2_client.modify_instance_attribute(
            InstanceId=instance_id,
            DisableApiTermination={'Value': True} # Set termination protection attribute
        )
        print_status(action, "complete")
        return True
    except ClientError as e:
        print_status(action, "error", f"Failed to enable termination protection: {e}")
        return False
    except Exception as e:
        print_status(action, "error", f"An unexpected error enabling term protection: {e}")
        return False

def check_autoscaling_groups(autoscaling_client, instance_id):
    """Checks if the instance is part of an Auto Scaling Group."""
    action = f"Checking Auto Scaling Group Membership for {instance_id}"
    print_status(action, "pending")
    try:
        response = autoscaling_client.describe_auto_scaling_instances(InstanceIds=[instance_id])
        asg_instances = response.get('AutoScalingInstances', [])
        if asg_instances:
            asg_name = asg_instances[0]['AutoScalingGroupName']
            # Use the 'warning' status for this message
            print_status(action,"warning", f"Instance is part of Auto Scaling Group: {asg_name}")
            print(Fore.YELLOW + "  └── WARNING: Auto Scaling might replace this instance if health checks fail due to containment.")
        else:
            print_status(action, "info", "Instance is NOT part of any Auto Scaling Group.")
    except ClientError as e:
        # Handle specific permission errors gracefully
        if e.response['Error']['Code'] in ['AccessDeniedException', 'AccessDenied']:
             print_status(action, "error", "Permission denied checking ASG membership (describe-auto-scaling-instances).")
        else:
             print_status(action, "error", f"Could not check ASG status: {e}")
    except Exception as e:
         print_status(action, "error", f"An unexpected error occurred checking ASG: {e}")

def check_load_balancers(elb_client, elbv2_client, instance_id):
    """Checks if the instance is registered with Classic, Application, or Network Load Balancers."""
    action = f"Checking Load Balancer Membership for {instance_id}"
    print_status(action, "pending")
    found_lb = False

    # Check ELBv2 (ALB/NLB) Target Groups
    try:
        paginator_tg = elbv2_client.get_paginator('describe_target_groups')
        for page_tg in paginator_tg.paginate():
            for tg in page_tg.get('TargetGroups', []):
                tg_arn = tg['TargetGroupArn']
                tg_name = tg.get('TargetGroupName', 'Unknown Name')
                try:
                    # Check target health specifically for the instance within this target group
                    response_health = elbv2_client.describe_target_health(
                        TargetGroupArn=tg_arn,
                        Targets=[{'Id': instance_id}]
                    )
                    # If the response contains health descriptions, the instance is registered
                    if response_health.get('TargetHealthDescriptions'):
                        lb_arns = tg.get('LoadBalancerArns', [])
                        # Attempt to extract readable LB names/identifiers from ARNs
                        lb_names = [arn.split('/')[-2] if '/' in arn else arn.split(':')[-1] for arn in lb_arns]
                        print_status(action, "warning", f"Instance is registered with Target Group: {tg_name} ({tg_arn})")
                        if lb_names:
                            print(f"  └── Associated Load Balancer(s): {', '.join(lb_names)}")
                        print(Fore.YELLOW + "  └── WARNING: Load Balancer health checks may fail, potentially removing the instance from service.")
                        found_lb = True
                except ClientError as e:
                    # Handle common errors gracefully when checking individual target groups
                    if e.response['Error']['Code'] == 'TargetGroupNotFoundException':
                        continue # Target group might have been deleted since listing
                    elif e.response['Error']['Code'] == 'InvalidTargetException':
                        continue # Instance is not registered with this specific target group
                    elif e.response['Error']['Code'] in ['AccessDeniedException', 'AccessDenied']:
                        print(Fore.YELLOW + f"  └── Permission denied checking health for Target Group {tg_name} ({tg_arn}).")
                    else:
                        print(Fore.YELLOW + f"  └── Could not check health for Target Group {tg_name} ({tg_arn}): {e}")
    except ClientError as e:
        # Handle errors listing target groups
        if e.response['Error']['Code'] in ['AccessDeniedException', 'AccessDenied']:
             print_status(action, "error", "Permission denied listing Target Groups (elbv2:DescribeTargetGroups).")
        else:
            print(Fore.YELLOW + f"  └── Could not list Target Groups: {e}")
    except Exception as e:
         print(Fore.YELLOW + f"  └── An unexpected error occurred checking Target Groups: {e}")

    # Check Classic Load Balancers (ELBv1)
    try:
        paginator_elb = elb_client.get_paginator('describe_load_balancers')
        for page_elb in paginator_elb.paginate():
            for lb in page_elb.get('LoadBalancerDescriptions', []):
                lb_name = lb['LoadBalancerName']
                # Check if the target instance ID is in the list of instances for this classic LB
                lb_instance_ids = [inst['InstanceId'] for inst in lb.get('Instances', [])]
                if instance_id in lb_instance_ids:
                     print_status(action, "warning", f"Instance is registered with Classic Load Balancer: {lb_name}")
                     print(Fore.YELLOW + "  └── WARNING: Load Balancer health checks may fail, potentially removing the instance from service.")
                     found_lb = True
    except ClientError as e:
        # Handle errors listing classic load balancers
        if e.response['Error']['Code'] in ['AccessDeniedException', 'AccessDenied']:
             print_status(action, "error", "Permission denied listing Classic LBs (elasticloadbalancing:DescribeLoadBalancers).")
        # Ignore 'LoadBalancerNotFound' as it might have been deleted during pagination
        elif e.response['Error']['Code'] != 'LoadBalancerNotFound':
             print(Fore.YELLOW + f"  └── Could not list Classic Load Balancers: {e}")
    except Exception as e:
         print(Fore.YELLOW + f"  └── An unexpected error occurred checking Classic LBs: {e}")

    if not found_lb:
        print_status(action, "info", "Instance does not appear to be registered with any checked Load Balancers.")


def get_instance_role_info(ec2_client, iam_client, instance_details):
    """
    Gets the IAM Role name attached via an Instance Profile from instance details.
    Handles cases where Instance Profile name and Role name might differ.
    Returns: tuple (actual_role_name, instance_profile_arn) or (None, None)
    """
    action = "Getting Attached IAM Role"
    print_status(action, "pending")
    instance_profile_details = instance_details.get('IamInstanceProfile')

    # Check if an instance profile is attached at all
    if not instance_profile_details or 'Arn' not in instance_profile_details:
        print_status(action, "info", "Instance does not have an IAM Instance Profile attached.")
        return None, None # No profile, so no role name or ARN

    instance_profile_arn = instance_profile_details['Arn']
    instance_profile_name = None
    actual_role_name = None

    # --- Extract Instance Profile Name from ARN ---
    try:
        # Standard ARN format: arn:partition:service:region:account-id:resource-type/resource-id
        if '/' in instance_profile_arn:
            instance_profile_name = instance_profile_arn.split('/')[-1]
        else: # Less common case, attempt to split by ':'
            instance_profile_name = instance_profile_arn.split(':')[-1]
        print(f"  └── Found Instance Profile Name: {instance_profile_name}")
    except IndexError:
        print_status(action, "error", f"Could not parse Instance Profile name from ARN: {instance_profile_arn}")
        # Return the ARN even if name parsing failed, as it might be useful context
        return None, instance_profile_arn

    if not instance_profile_name: # Double-check if parsing failed
         print_status(action, "error", f"Could not determine Instance Profile name from ARN: {instance_profile_arn}")
         return None, instance_profile_arn

    # --- Get Instance Profile details to find the actual Role Name ---
    try:
        # Use the extracted profile name to get details, including the associated role(s)
        profile_response = iam_client.get_instance_profile(InstanceProfileName=instance_profile_name)

        # Check if the response structure is as expected and contains roles
        if (profile_response and 'InstanceProfile' in profile_response and
            'Roles' in profile_response['InstanceProfile'] and
            profile_response['InstanceProfile']['Roles']):
            # Assume the first role listed in the profile is the relevant one
            actual_role_name = profile_response['InstanceProfile']['Roles'][0]['RoleName']
            print(f"  └── Found underlying IAM Role Name: {Fore.CYAN}{actual_role_name}{Style.RESET_ALL}")
            print_status(action, "complete")
            # Return the actual role name and the profile ARN
            return actual_role_name, instance_profile_arn
        else:
            # Profile exists but has no roles attached (unusual but possible)
            print_status(action, "warning", f"Instance Profile '{instance_profile_name}' exists but contains no associated IAM Roles.")
            return None, instance_profile_arn # No role name found

    except ClientError as e:
        err_code = e.response.get("Error", {}).get("Code")
        if err_code == 'NoSuchEntity':
             msg = f"Could not find IAM Instance Profile details for '{instance_profile_name}'. Profile might not exist or permissions missing (iam:GetInstanceProfile)."
        elif err_code == 'AccessDenied':
             msg = f"Permission denied for iam:GetInstanceProfile on profile '{instance_profile_name}'. Cannot determine actual Role name."
        else:
            msg = f"Error calling iam:GetInstanceProfile for '{instance_profile_name}': {e}"
        print_status(action, "error", msg)
        # Return profile ARN even on error, as context
        return None, instance_profile_arn
    except Exception as e:
         print_status(action, "error", f"An unexpected error occurred getting profile details: {e}")
         return None, instance_profile_arn

def check_imds_version(ec2_client, instance_details):
    """Checks if the instance uses IMDSv1 (optional) or requires IMDSv2."""
    action = "Checking Instance Metadata Service (IMDS) Version"
    print_status(action, "pending")
    metadata_options = instance_details.get('MetadataOptions', {})
    http_tokens = metadata_options.get('HttpTokens') # 'optional' (v1 allowed) or 'required' (v2 only)
    http_endpoint = metadata_options.get('HttpEndpoint') # 'enabled' or 'disabled'

    if http_endpoint == 'disabled':
        print_status(action, "info", "IMDS is disabled on this instance.")
    elif http_tokens == 'required':
        print_status(action, "info", f"Instance is configured to require IMDSv2 ({Fore.GREEN}HttpTokens=required{Style.RESET_ALL}).")
        print(Fore.GREEN + "  └── Good security practice.")
    elif http_tokens == 'optional':
        # This is the less secure configuration
        print_status(action, "warning", f"Instance allows IMDSv1 ({Fore.RED}HttpTokens=optional{Style.RESET_ALL}).")
        print(Fore.RED + Style.BRIGHT + "  └── SECURITY CONCERN: If credentials were stolen via IMDSv1, the attached role could be misused. Review CloudTrail logs for the role's activity.")
    else:
         # Fallback for unexpected values
         print_status(action, "info", f"Could not definitively determine IMDS version (HttpTokens={http_tokens}, HttpEndpoint={http_endpoint}). Review instance metadata options manually.")

def find_instances_with_same_role(ec2_client, profile_arn, excluded_instance_id):
    """Finds other running/stopped instances using the same IAM instance profile ARN."""
    action = "Finding Other Instances with Same Role Profile"
    print_status(action, "pending")
    # If no profile ARN was found for the target instance, skip this check
    if not profile_arn:
        print_status(action, "skipped", "No role profile ARN provided to check.")
        return []

    found_instances = []
    try:
        paginator = ec2_client.get_paginator('describe_instances')
        # Filter by instance profile ARN and state
        pages = paginator.paginate(
            Filters=[
                {'Name': 'iam-instance-profile.arn', 'Values': [profile_arn]},
                {'Name': 'instance-state-name', 'Values': ['running', 'stopped']}
            ]
        )

        print(f"  └── Searching for other instances using profile: {profile_arn.split('/')[-1]}")
        count = 0
        for page in pages:
            for reservation in page.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    instance_id = instance['InstanceId']
                    # Exclude the instance we are currently containing
                    if instance_id != excluded_instance_id:
                        instance_state = instance['State']['Name']
                        instance_name = "N/A"
                        if 'Tags' in instance:
                            for tag in instance['Tags']:
                                if tag['Key'] == 'Name':
                                    instance_name = tag['Value']
                                    break
                        print(Fore.YELLOW + f"    - Found: ID: {instance_id}, Name: {instance_name}, State: {instance_state}")
                        found_instances.append(instance_id)
                        count += 1

        if count == 0:
            print(f"  └── No other running/stopped instances found using the same role profile.")
            print_status(action, "info", "No other instances found with the same role.")
        else:
            print(Fore.YELLOW + f"  └── WARNING: Found {count} other instance(s) using the same IAM role. If the role credentials were compromised, these instances might also be affected or could be used for lateral movement.")
            print_status(action, "warning", f"Found {count} other instance(s) with the same role.")

        return found_instances

    except ClientError as e:
        print_status(action, "error", f"Failed to search for instances with the same role: {e}")
        return [] # Return empty list on error
    except Exception as e:
        print_status(action, "error", f"An unexpected error occurred searching for instances: {e}")
        return []

def get_role_permissions(iam_client, role_name):
    """Lists managed and inline policies attached to the specified IAM role."""
    action = f"Getting Permissions for Role: {role_name}"
    print_status(action, "pending")
    try:
        # List Managed Policies
        print(f"  └── Checking Managed Policies attached to role '{role_name}'...")
        managed_policies = iam_client.list_attached_role_policies(RoleName=role_name).get('AttachedPolicies', [])
        if managed_policies:
            print(f"    Found {len(managed_policies)} Managed Policies:")
            for policy in managed_policies:
                print(f"      - Name: {policy['PolicyName']}, ARN: {policy['PolicyArn']}")
        else:
            print("    No Managed Policies found.")

        # List Inline Policies
        print(f"  └── Checking Inline Policies attached to role '{role_name}'...")
        inline_policies = iam_client.list_role_policies(RoleName=role_name).get('PolicyNames', [])
        if inline_policies:
            print(f"    Found {len(inline_policies)} Inline Policies:")
            for policy_name in inline_policies:
                print(f"      - Name: {policy_name}")
                # Optionally, you could get the policy document here too, but it can be large
                # policy_doc = iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)['PolicyDocument']
                # print(f"        Document: {policy_doc}") # Be careful printing large docs
        else:
            print("    No Inline Policies found.")

        print_status(action, "complete")

    except ClientError as e:
        # Handle common errors like NoSuchEntity or AccessDenied
        if e.response['Error']['Code'] == 'NoSuchEntityException':
             print_status(action, "error", f"IAM Role '{role_name}' not found.")
        elif e.response['Error']['Code'] in ['AccessDenied', 'AccessDeniedException']:
             print_status(action, "error", f"Permission denied to list policies for role '{role_name}'.")
        else:
             print_status(action, "error", f"Failed to get permissions for role '{role_name}': {e}")
    except Exception as e:
         print_status(action, "error", f"An unexpected error occurred getting role permissions: {e}")


def revoke_role_sessions(iam_client, role_name):
    """
    Applies a DENY ALL inline policy to the specified IAM role to revoke active sessions.
    Prompts the user for confirmation before applying.
    """
    action = f"Revoking Active Sessions for Role: {role_name}"
    print_status(action, "pending") # Initial status

    # Define the Deny All policy document
    deny_policy_doc = """{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*"
            }
        ]
    }"""

    try:
        # --- Confirmation Prompt ---
        print("\n" + Fore.YELLOW + Style.BRIGHT + "--- Action Confirmation Needed ---")
        print(f"You are about to apply a DENY ALL policy ('{DENY_POLICY_NAME}')")
        print(f"to the IAM role: {Fore.CYAN}{role_name}{Style.RESET_ALL}")
        print(Fore.YELLOW + "This will immediately invalidate any temporary credentials currently")
        print(Fore.YELLOW + "associated with this role, effectively stopping its use.")
        print(Fore.RED + Style.BRIGHT + "WARNING: This will affect ALL users/services/instances currently using this role.")
        print("-" * 40)
        confirm = input(f"Do you want to proceed with revoking sessions for role '{role_name}'? ({Fore.YELLOW}yes/no{Style.RESET_ALL}): ").lower().strip()
        print("-" * 40)

        if confirm == 'yes':
            print(f"  └── Applying DENY ALL policy '{DENY_POLICY_NAME}' to role '{role_name}'...")
            iam_client.put_role_policy(
                RoleName=role_name,
                PolicyName=DENY_POLICY_NAME,
                PolicyDocument=deny_policy_doc
            )
            success_msg = f"Successfully applied '{DENY_POLICY_NAME}' to role '{role_name}'. Active sessions should now be invalid."
            print(Fore.GREEN + f"  └── {success_msg}")
            print_status(action, "complete", success_msg)
            logging.info(f"User confirmed. Applied Deny policy {DENY_POLICY_NAME} to role {role_name}.")
        else:
            skip_msg = f"User chose NOT to apply DENY policy to role '{role_name}'. Sessions remain active."
            print(Fore.YELLOW + f"  └── {skip_msg}")
            print_status(action, "skipped", skip_msg)
            logging.warning(f"User skipped applying Deny policy to role {role_name}.")

    except ClientError as e:
        # Handle common errors like NoSuchEntity or AccessDenied
        if e.response['Error']['Code'] == 'NoSuchEntityException':
             error_msg = f"IAM Role '{role_name}' not found. Cannot apply policy."
        elif e.response['Error']['Code'] in ['AccessDenied', 'AccessDeniedException', 'UnrecognizedClientException']:
             error_msg = f"Permission denied to apply policy (iam:PutRolePolicy) to role '{role_name}'."
        elif e.response['Error']['Code'] == 'MalformedPolicyDocument':
             error_msg = f"The generated DENY policy document is invalid. This is unexpected. Error: {e}"
        elif e.response['Error']['Code'] == 'LimitExceeded':
             error_msg = f"Cannot apply policy: Inline policy limit reached for role '{role_name}'. Error: {e}"
        else:
             error_msg = f"Failed to apply DENY policy to role '{role_name}': {e}"
        print_status(action, "error", error_msg)
        logging.error(f"{action} Error: {error_msg}", exc_info=True)
    except Exception as e:
         error_msg = f"An unexpected error occurred during role session revocation: {e}"
         print_status(action, "error", error_msg)
         logging.error(f"{action} Error: {error_msg}", exc_info=True)


def get_ebs_volumes(instance_details):
    """Extracts EBS volume IDs and attachment info from instance details."""
    action = "Getting Attached EBS Volumes"
    print_status(action, "pending")
    volumes = []
    block_devices = instance_details.get('BlockDeviceMappings', [])
    if not block_devices:
        print_status(action, "info", "No block device mappings found for the instance.")
        return volumes # Return empty list

    for device in block_devices:
        if 'Ebs' in device and 'VolumeId' in device['Ebs']:
            volume_id = device['Ebs']['VolumeId']
            device_name = device.get('DeviceName', 'N/A')
            print(f"  └── Found EBS Volume: ID: {volume_id}, Attached as: {device_name}")
            volumes.append({'VolumeId': volume_id, 'DeviceName': device_name})

    if not volumes:
         print_status(action, "info", "No EBS volumes found in block device mappings.")
    else:
         print_status(action, "complete", f"Found {len(volumes)} EBS volume(s).")
    return volumes


def describe_and_update_volume_sizes(ec2_client, volumes):
    """
    Gets the size for each volume ID in the list and updates the list.
    Handles potential errors if a volume is not found (e.g., deleted).
    """
    action = "Getting EBS Volume Sizes"
    print_status(action, "pending")
    if not volumes:
        print_status(action, "skipped", "No volumes provided to describe.")
        return []

    volume_ids = [v['VolumeId'] for v in volumes]
    updated_volumes = [] # Create a new list for updated info

    try:
        response = ec2_client.describe_volumes(VolumeIds=volume_ids)
        volume_details_map = {vol['VolumeId']: vol for vol in response.get('Volumes', [])}

        processed_count = 0
        for vol_info in volumes: # Iterate through the original list
            vol_id = vol_info['VolumeId']
            if vol_id in volume_details_map:
                size_gb = volume_details_map[vol_id].get('Size', 'Unknown')
                print(f"  └── Volume: {vol_id}, Size: {size_gb} GiB")
                # Add size to the original dictionary and append to new list
                vol_info['SizeGiB'] = size_gb
                updated_volumes.append(vol_info)
                processed_count += 1
            else:
                print(Fore.YELLOW + f"  └── Warning: Could not find details for volume {vol_id}. It might have been deleted.")
                # Append original info but mark size as unknown
                vol_info['SizeGiB'] = 'Not Found'
                updated_volumes.append(vol_info)

        if processed_count == len(volumes):
            print_status(action, "complete")
        elif processed_count > 0:
             print_status(action, "warning", "Could not retrieve size for all volumes.")
        else:
             print_status(action, "error", "Failed to retrieve size for any provided volumes.")

        return updated_volumes

    except ClientError as e:
        # Handle cases where some volumes might not be found or access denied
        if 'InvalidVolume.NotFound' in str(e):
             print_status(action, "warning", f"Some volumes were not found during size check: {e}")
             # Attempt to return partial results if possible by adding 'Not Found'
             for vol_info in volumes:
                 if 'SizeGiB' not in vol_info: # If not already processed
                     vol_info['SizeGiB'] = 'Error/Not Found'
                     updated_volumes.append(vol_info)
             return updated_volumes
        elif e.response['Error']['Code'] in ['AccessDenied', 'AccessDeniedException']:
             print_status(action, "error", f"Permission denied to describe volumes: {e}")
        else:
             print_status(action, "error", f"Failed to describe volume sizes: {e}")
        # Return the original list but mark all as unknown size on error
        for vol_info in volumes:
            vol_info['SizeGiB'] = 'Error'
            updated_volumes.append(vol_info)
        return updated_volumes
    except Exception as e:
         print_status(action, "error", f"An unexpected error occurred getting volume sizes: {e}")
         for vol_info in volumes:
            vol_info['SizeGiB'] = 'Error'
            updated_volumes.append(vol_info)
         return updated_volumes


def snapshot_ebs_volumes(ec2_client, volumes, instance_id):
    """
    Creates snapshots for the specified EBS volumes.
    Prompts the user for confirmation before snapshotting.
    Waits for snapshots to complete.
    """
    action = "Snapshotting EBS Volumes"
    print_status(action, "pending") # Initial status

    if not volumes:
        print_status(action, "skipped", "No volumes provided to snapshot.")
        return

    print("\n" + Fore.YELLOW + Style.BRIGHT + "--- Action Confirmation Needed ---")
    print(f"The following EBS volumes attached to instance {instance_id} were found:")
    total_size_gb = 0
    for vol in volumes:
        size_str = f"{vol.get('SizeGiB', 'Unknown')} GiB"
        print(f"  - Volume ID: {vol['VolumeId']}, Device: {vol['DeviceName']}, Size: {size_str}")
        if isinstance(vol.get('SizeGiB'), (int, float)):
            total_size_gb += vol['SizeGiB']
    print(f"Total estimated size to snapshot: {total_size_gb} GiB")
    print(Fore.YELLOW + "Creating snapshots preserves the state of these volumes for forensic analysis.")
    print("-" * 40)
    confirm = input(f"Do you want to proceed with creating snapshots for these {len(volumes)} volume(s)? ({Fore.YELLOW}yes/no{Style.RESET_ALL}): ").lower().strip()
    print("-" * 40)

    if confirm != 'yes':
        skip_msg = "User chose NOT to create EBS snapshots."
        print(Fore.YELLOW + f"  └── {skip_msg}")
        print_status(action, "skipped", skip_msg)
        logging.warning(skip_msg)
        return

    logging.info(f"User confirmed snapshotting for {len(volumes)} volumes.")
    snapshot_ids = []
    snapshot_status = {} # To track individual snapshot success/failure

    for vol in volumes:
        vol_id = vol['VolumeId']
        device_name = vol.get('DeviceName', 'UnknownDevice')
        snapshot_description = f"Containment snapshot for {instance_id} - Volume {vol_id} ({device_name}) - {datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}"
        print(f"  └── Creating snapshot for Volume: {vol_id}...")
        try:
            snap_response = ec2_client.create_snapshot(
                VolumeId=vol_id,
                Description=snapshot_description,
                TagSpecifications=[{
                    'ResourceType': 'snapshot',
                    'Tags': [
                        {'Key': 'Name', 'Value': f"Containment-{instance_id}-{vol_id}"},
                        {'Key': 'InstanceId', 'Value': instance_id},
                        {'Key': 'VolumeId', 'Value': vol_id},
                        {'Key': 'DeviceName', 'Value': device_name},
                        {'Key': 'ContainmentScript', 'Value': 'True'}
                    ]
                }]
            )
            snapshot_id = snap_response['SnapshotId']
            print(f"    └── Snapshot initiated: {snapshot_id}")
            snapshot_ids.append(snapshot_id)
            snapshot_status[snapshot_id] = 'pending'
        except ClientError as e:
            error_msg = f"Failed to initiate snapshot for {vol_id}: {e}"
            print(Fore.RED + f"    └── Error: {error_msg}")
            snapshot_status[vol_id] = f'Error: {e}' # Use vol_id as key if snapshot_id fails
            logging.error(f"Snapshot Error for {vol_id}: {error_msg}", exc_info=True)
        except Exception as e:
            error_msg = f"An unexpected error occurred initiating snapshot for {vol_id}: {e}"
            print(Fore.RED + f"    └── Error: {error_msg}")
            snapshot_status[vol_id] = f'Unexpected Error: {e}'
            logging.error(f"Snapshot Error for {vol_id}: {error_msg}", exc_info=True)


    if not snapshot_ids:
        error_msg = "No snapshots were successfully initiated."
        print_status(action, "error", error_msg)
        logging.error(error_msg)
        return # Exit if no snapshots started

    # Wait for snapshots to complete
    print(f"  └── Waiting for {len(snapshot_ids)} snapshot(s) to complete...")
    waiter = ec2_client.get_waiter('snapshot_completed')
    try:
        waiter.wait(
            SnapshotIds=snapshot_ids,
            WaiterConfig={'Delay': 15, 'MaxAttempts': 60} # Wait up to 15 mins (15*60s)
        )
        # Double check status after waiter returns, as it waits for ALL, some might fail individually before timeout
        final_check = ec2_client.describe_snapshots(SnapshotIds=snapshot_ids)
        all_successful = True
        for snap in final_check.get('Snapshots', []):
            snap_id = snap['SnapshotId']
            state = snap['State']
            if state == 'completed':
                snapshot_status[snap_id] = 'completed'
                print(Fore.GREEN + f"    └── Snapshot {snap_id} completed successfully.")
            else:
                snapshot_status[snap_id] = f'Failed ({state})'
                print(Fore.RED + f"    └── Snapshot {snap_id} failed or ended in state: {state}")
                all_successful = False

        if all_successful:
            success_msg = f"All {len(snapshot_ids)} snapshots completed successfully."
            print_status(action, "complete", success_msg)
            logging.info(success_msg)
        else:
             warning_msg = "Some snapshots failed or did not complete successfully. Check details above."
             print_status(action, "warning", warning_msg)
             logging.warning(warning_msg + f" Status: {snapshot_status}")

    except WaiterError as e:
        error_msg = f"Error or timeout waiting for snapshots: {e}. Some snapshots might still be pending or failed. Please check manually."
        print_status(action, "error", error_msg)
        logging.error(error_msg + f" Current Status: {snapshot_status}", exc_info=True)
        # Log the final known status even on waiter error
        try:
            final_check = ec2_client.describe_snapshots(SnapshotIds=snapshot_ids)
            for snap in final_check.get('Snapshots', []):
                 snapshot_status[snap['SnapshotId']] = snap['State']
            logging.error(f"Snapshot status at timeout: {snapshot_status}")
        except Exception as desc_err:
             logging.error(f"Could not describe snapshots after waiter error: {desc_err}")

    except Exception as e:
         error_msg = f"An unexpected error occurred waiting for snapshots: {e}"
         print_status(action, "error", error_msg)
         logging.error(error_msg + f" Current Status: {snapshot_status}", exc_info=True)


def stop_instance(ec2_client, instance_id):
    """
    Stops the specified EC2 instance if it is running.
    Prompts the user for confirmation before stopping.
    Waits for the instance to reach the 'stopped' state.
    """
    action = f"Stopping Instance: {instance_id}"
    print_status(action, "pending") # Initial status

    try:
        # Check current instance state first
        instance_status_response = ec2_client.describe_instance_status(
            InstanceIds=[instance_id],
            IncludeAllInstances=True # Important to get status even if not 'running'
        )

        current_state = None
        if instance_status_response.get('InstanceStatuses'):
            # If status is available, use it
            current_state = instance_status_response['InstanceStatuses'][0]['InstanceState']['Name']
        else:
            # If no status (e.g., instance already stopped or terminated), describe instance for state
            desc_response = ec2_client.describe_instances(InstanceIds=[instance_id])
            if desc_response.get('Reservations') and desc_response['Reservations'][0].get('Instances'):
                current_state = desc_response['Reservations'][0]['Instances'][0]['State']['Name']

        print(f"  └── Current instance state: {current_state}")

        if current_state in ['stopped', 'terminated', 'shutting-down']:
            info_msg = f"Instance {instance_id} is already {current_state}. No action needed."
            print(Fore.BLUE + f"  └── {info_msg}")
            print_status(action, "skipped", info_msg)
            logging.info(info_msg)
            return # Nothing to do

        if current_state not in ['running', 'pending']:
            warn_msg = f"Instance {instance_id} is in an unexpected state: {current_state}. Attempting to stop might fail or be irrelevant."
            print(Fore.YELLOW + f"  └── Warning: {warn_msg}")
            logging.warning(warn_msg)
            # Still proceed to prompt, as user might want to try anyway

        # --- Confirmation Prompt ---
        print("\n" + Fore.YELLOW + Style.BRIGHT + "--- Action Confirmation Needed ---")
        print(f"You are about to STOP the EC2 instance: {Fore.CYAN}{instance_id}{Style.RESET_ALL}")
        print(Fore.YELLOW + "Stopping the instance halts its execution and prevents further activity.")
        print(Fore.RED + Style.BRIGHT + "WARNING: Ensure evidence (snapshots) has been collected if needed.")
        print("-" * 40)
        confirm = input(f"Do you want to proceed with stopping instance '{instance_id}'? ({Fore.YELLOW}yes/no{Style.RESET_ALL}): ").lower().strip()
        print("-" * 40)

        if confirm == 'yes':
            print(f"  └── Initiating stop for instance {instance_id}...")
            ec2_client.stop_instances(InstanceIds=[instance_id])
            logging.info(f"User confirmed. Stop initiated for {instance_id}.")

            # Wait for the instance to stop
            print("  └── Waiting for instance to reach 'stopped' state...")
            waiter = ec2_client.get_waiter('instance_stopped')
            try:
                waiter.wait(
                    InstanceIds=[instance_id],
                    WaiterConfig={'Delay': 15, 'MaxAttempts': 40} # Wait up to 10 mins
                )
                success_msg = f"Instance {instance_id} stopped successfully."
                print(Fore.GREEN + f"  └── {success_msg}")
                print_status(action, "complete", success_msg)
                logging.info(success_msg)
            except WaiterError as e:
                # Check if the waiter failed because the instance terminated instead of stopping
                if "terminal failure state" in str(e) and "matched expected path: \"terminated\"" in str(e):
                    success_msg = f"Instance {instance_id} terminated instead of stopping. Execution halted."
                    print(Fore.GREEN + f"  └── {success_msg}")
                    print_status(action, "complete", success_msg) # Treat termination as successful halt
                    logging.info(success_msg)
                else:
                    # Handle other waiter errors (e.g., timeout)
                    error_msg = f"Error or timeout waiting for instance {instance_id} to stop: {e}. Please verify state manually."
                    print_status(action, "error", error_msg)
                    logging.error(error_msg, exc_info=True)
            except Exception as e_wait:
                 error_msg = f"An unexpected error occurred waiting for instance stop: {e_wait}"
                 print_status(action, "error", error_msg)
                 logging.error(error_msg, exc_info=True)

        else:
            skip_msg = f"User chose NOT to stop instance '{instance_id}'. Instance remains in state '{current_state}'."
            print(Fore.YELLOW + f"  └── {skip_msg}")
            print_status(action, "skipped", skip_msg)
            logging.warning(skip_msg)

    except ClientError as e:
        error_msg = f"Failed to check status or stop instance {instance_id}: {e}"
        print_status(action, "error", error_msg)
        logging.error(f"{action} Error: {error_msg}", exc_info=True)
    except Exception as e:
         error_msg = f"An unexpected error occurred during instance stop process: {e}"
         print_status(action, "error", error_msg)
         logging.error(f"{action} Error: {error_msg}", exc_info=True)


# --- UPDATED PREFLIGHT CHECKS ---
def perform_preflight_checks(session, instance_id, instance_details, vpc_id, instance_role_name, attached_volumes):
    """
    Performs non-mutating checks before containment actions.
    Checks permissions for SG changes, termination protection, role policy, snapshots, stop.
    Returns: tuple (success_boolean, list_of_issues)
    """
    action = "Performing Pre-flight Checks"
    print_status(action, "pending")
    issues = []
    success = True
    ec2 = session.client('ec2')
    iam = session.client('iam')

    # Permissions needed for SG containment
    sg_perms_needed = [
        "ec2:DescribeSecurityGroups",
        "ec2:CreateSecurityGroup",
        "ec2:CreateTags", # For tagging the SG
        "ec2:RevokeSecurityGroupEgress", # To remove default rule
        "ec2:ModifyInstanceAttribute" # To apply the SG
    ]
    # Permissions needed for Termination Protection
    term_prot_perms_needed = ["ec2:ModifyInstanceAttribute"] # Already covered by SG check
    # Permissions needed for Role Session Revocation (if role exists)
    role_perms_needed = ["iam:PutRolePolicy"]
    # Permissions needed for Snapshots
    snapshot_perms_needed = [
        "ec2:DescribeVolumes", # Already checked implicitly by getting volumes earlier? No, need explicit check.
        "ec2:CreateSnapshot",
        "ec2:DescribeSnapshots",
        "ec2:CreateTags" # For tagging snapshots
    ]
    # Permissions needed for Stop Instance
    stop_perms_needed = [
        "ec2:DescribeInstanceStatus",
        "ec2:StopInstances"
    ]

    # Combine all required EC2 perms for a single check if possible
    all_ec2_perms = list(set(
        sg_perms_needed +
        term_prot_perms_needed +
        snapshot_perms_needed +
        stop_perms_needed
    ))
    all_iam_perms = list(set(role_perms_needed)) # Only PutRolePolicy for now

    # --- Check Instance State ---
    instance_state = instance_details.get('State', {}).get('Name', 'unknown')
    print(f"  └── Checking Instance State: {instance_state}")
    if instance_state in ['terminated', 'shutting-down']:
        issue = f"Instance {instance_id} is already {instance_state}. Cannot proceed with containment."
        issues.append(issue)
        success = False # Critical failure
        print(Fore.RED + f"    └── CRITICAL: {issue}")
    elif instance_state == 'stopped':
         issue = f"Instance {instance_id} is already stopped. Some actions (like Stop Instance) will be skipped."
         issues.append(issue)
         print(Fore.YELLOW + f"    └── WARNING: {issue}")
         # Not critical, can still snapshot, apply SG etc.

    # --- Check Required Permissions using DryRun ---
    # Note: DryRun doesn't work for all actions (like CreateTags sometimes),
    # and doesn't perfectly simulate all conditions, but it's a good first pass.

    # Check EC2 Permissions
    print(f"  └── Checking EC2 permissions via DryRun...")
    try:
        # Try a common action that requires multiple permissions if possible
        # DryRun ModifyInstanceAttribute for SG change and Term Protection
        ec2.modify_instance_attribute(InstanceId=instance_id, Groups=['sg-dryrunplaceholder'], DryRun=True)
        ec2.modify_instance_attribute(InstanceId=instance_id, DisableApiTermination={'Value': True}, DryRun=True)
        # DryRun StopInstances
        ec2.stop_instances(InstanceIds=[instance_id], DryRun=True)
        # DryRun CreateSnapshot (needs a volume ID)
        if attached_volumes:
            ec2.create_snapshot(VolumeId=attached_volumes[0]['VolumeId'], DryRun=True)
        # DryRun CreateSecurityGroup
        ec2.create_security_group(GroupName="dryrun-sg-test", Description="dryrun", VpcId=vpc_id, DryRun=True)
        # Note: RevokeSecurityGroupEgress DryRun might be tricky without a real SG ID.
        # Note: CreateTags DryRun might fail even with permissions.
        print(Fore.GREEN + "    └── Basic EC2 DryRun checks passed (ModifyInstanceAttribute, StopInstances, CreateSnapshot, CreateSecurityGroup).")
    except ClientError as e:
        if e.response['Error']['Code'] == 'DryRunOperation':
            # This means the user *likely* has permission, DryRun itself is the "error"
             print(Fore.GREEN + f"    └── Basic EC2 DryRun checks indicate permissions likely present for key actions.")
        elif e.response['Error']['Code'] == 'UnauthorizedOperation':
            issue = f"Missing critical EC2 permissions. DryRun failed for one or more actions (ModifyInstanceAttribute, StopInstances, CreateSnapshot, CreateSecurityGroup). Check specific error: {e}"
            issues.append(issue)
            success = False # Critical failure
            print(Fore.RED + f"    └── CRITICAL: {issue}")
        else:
            # Other errors during DryRun (e.g., invalid parameter)
            issue = f"Potential issue during EC2 permission DryRun check: {e}. Proceed with caution."
            issues.append(issue)
            print(Fore.YELLOW + f"    └── WARNING: {issue}")

    # Check IAM Permissions (only if role exists)
    if instance_role_name:
        # Note: iam:PutRolePolicy does not support DryRun.
        # We can only check if the role exists, not the permission itself here.
        # The actual permission check will happen if/when revoke_role_sessions is called.
        print(f"  └── Checking if IAM role '{instance_role_name}' exists...")
        try:
            # Check if role exists by trying to get it
            iam.get_role(RoleName=instance_role_name)
            print(Fore.GREEN + f"    └── IAM role '{instance_role_name}' found.")
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                issue = f"IAM Role '{instance_role_name}' not found. Cannot perform role actions."
                issues.append(issue)
                success = False # Treat as critical failure if role doesn't exist
                print(Fore.RED + f"    └── CRITICAL: {issue}")
            elif e.response['Error']['Code'] == 'AccessDenied':
                 issue = f"Permission denied checking for IAM role '{instance_role_name}' (iam:GetRole)."
                 issues.append(issue)
                 print(Fore.YELLOW + f"    └── WARNING: {issue}") # Warning, might still have PutRolePolicy
            else:
                issue = f"Error checking IAM role '{instance_role_name}': {e}."
                issues.append(issue)
                print(Fore.YELLOW + f"    └── WARNING: {issue}")

    # --- Final Status ---
    if not issues:
        print_status(action, "complete", "All pre-flight checks passed.")
    elif success: # Issues found, but none were critical failures
        print_status(action, "warning", f"Pre-flight checks passed with warnings: {len(issues)} issue(s) found.")
    else: # Critical failure encountered
        print_status(action, "error", f"Pre-flight checks failed: {len(issues)} issue(s) found, including critical failures.")

    return success, issues
# --- END UPDATED PREFLIGHT CHECKS ---


# --- Log Collection Functions (Mostly Unchanged) ---

def _create_s3_bucket(s3_client, bucket_name, region):
    """Creates an S3 bucket if it doesn't exist. Handles potential naming conflicts."""
    action = f"Ensuring S3 Bucket Exists: {bucket_name}"
    print_status(action, "pending")
    try:
        # Check if bucket exists first (HeadBucket is cheaper and faster)
        try:
            s3_client.head_bucket(Bucket=bucket_name)
            print(f"  └── Bucket '{bucket_name}' already exists.")
            print_status(action, "complete", "Bucket already exists.")
            return True
        except ClientError as e:
            if e.response['Error']['Code'] == '404': # Not Found - Good, we can create it
                print(f"  └── Bucket '{bucket_name}' does not exist. Creating...")
            elif e.response['Error']['Code'] == '403': # Forbidden - Permission issue or bucket owned by another account
                 print_status(action, "error", f"Permission denied or bucket '{bucket_name}' owned by another account.")
                 return False
            else: # Other errors checking head_bucket
                raise e # Re-raise other ClientErrors

        # Create the bucket
        # Handle region constraints for bucket creation
        if region == 'us-east-1':
            s3_client.create_bucket(Bucket=bucket_name)
        else:
            s3_client.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={'LocationConstraint': region}
            )
        print(f"  └── Successfully created bucket '{bucket_name}' in region '{region}'.")
        print_status(action, "complete", "Bucket created successfully.")
        return True

    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'BucketAlreadyOwnedByYou':
            print(f"  └── Bucket '{bucket_name}' already exists and is owned by you.")
            print_status(action, "complete", "Bucket already exists.")
            return True
        elif error_code == 'BucketAlreadyExists':
             error_msg = f"Bucket name '{bucket_name}' is already taken globally. Please choose a different name or strategy."
             print_status(action, "error", error_msg)
             return False
        elif error_code == 'InvalidBucketName':
             error_msg = f"Bucket name '{bucket_name}' is invalid. Check S3 naming rules."
             print_status(action, "error", error_msg)
             return False
        else:
            error_msg = f"Failed to create or check S3 bucket '{bucket_name}': {e}"
            print_status(action, "error", error_msg)
            return False
    except Exception as e:
         error_msg = f"An unexpected error occurred with S3 bucket '{bucket_name}': {e}"
         print_status(action, "error", error_msg)
         return False


def _get_cloudwatch_logs(logs_client, instance_id, start_time_ms, end_time_ms, local_log_dir):
    """Attempts to find and download CloudWatch logs related to the instance."""
    action = "Collecting CloudWatch Logs"
    print_status(action, "pending")
    found_logs = False
    log_group_prefixes = [
        f'/aws/ec2/instances/{instance_id}', # Common pattern
        f'/var/log/messages', # System logs if configured
        f'/var/log/syslog',
        f'/var/log/cloud-init',
        f'/var/log/amazon/ssm', # SSM Agent logs
        # Add other potential common log group names/prefixes if known
    ]
    collected_files = []

    try:
        # Find relevant log groups
        print("  └── Searching for relevant CloudWatch Log Groups...")
        paginator = logs_client.get_paginator('describe_log_groups')
        relevant_groups = []
        for prefix in log_group_prefixes:
             try:
                 # Use prefix filtering for efficiency
                 pages = paginator.paginate(logGroupNamePrefix=prefix)
                 for page in pages:
                     for group in page.get('logGroups', []):
                         group_name = group['logGroupName']
                         if group_name not in relevant_groups: # Avoid duplicates
                             print(f"    └── Found potential group: {group_name}")
                             relevant_groups.append(group_name)
             except ClientError as desc_err:
                 if desc_err.response['Error']['Code'] in ['AccessDeniedException', 'AccessDenied']:
                      print(Fore.YELLOW + f"    └── Permission denied searching for log groups with prefix '{prefix}'. Skipping.")
                 else:
                      print(Fore.YELLOW + f"    └── Error searching log groups with prefix '{prefix}': {desc_err}. Skipping.")
             except Exception as desc_exc:
                  print(Fore.YELLOW + f"    └── Unexpected error searching log groups with prefix '{prefix}': {desc_exc}. Skipping.")


        if not relevant_groups:
            print("  └── No potentially relevant CloudWatch Log Groups found based on common prefixes.")
            print_status(action, "info", "No relevant log groups found.")
            return [] # Return empty list

        # Download logs from found groups
        print(f"  └── Attempting to download logs from {len(relevant_groups)} group(s)...")
        log_event_paginator = logs_client.get_paginator('filter_log_events')

        for group_name in relevant_groups:
            sanitized_group_name = group_name.replace('/', '_').strip('_') # Sanitize for filename
            output_filename = os.path.join(local_log_dir, f"cloudwatch_{sanitized_group_name}.log")
            print(f"    └── Downloading from '{group_name}' to '{output_filename}'...")
            try:
                with open(output_filename, 'w', encoding='utf-8') as f:
                    event_pages = log_event_paginator.paginate(
                        logGroupName=group_name,
                        startTime=start_time_ms,
                        endTime=end_time_ms
                        # Can add filterPattern here if needed, e.g., 'ERROR'
                    )
                    event_count = 0
                    for page in event_pages:
                        for event in page.get('events', []):
                            f.write(f"{datetime.fromtimestamp(event['timestamp']/1000).isoformat()} - {event['message']}\n")
                            event_count += 1
                        # Add a small delay to avoid throttling on very active groups
                        time.sleep(0.2)

                if event_count > 0:
                    print(f"      └── Downloaded {event_count} events.")
                    collected_files.append(output_filename)
                    found_logs = True
                else:
                    print(f"      └── No events found in the specified time range for this group.")
                    # Optionally remove the empty file
                    try: os.remove(output_filename)
                    except OSError: pass

            except ClientError as filter_err:
                 print(Fore.YELLOW + f"      └── Error downloading logs from '{group_name}': {filter_err}. Skipping group.")
                 logging.warning(f"Error downloading logs from {group_name}: {filter_err}")
            except Exception as file_err:
                 print(Fore.YELLOW + f"      └── Error writing log file for '{group_name}': {file_err}. Skipping group.")
                 logging.warning(f"Error writing log file for {group_name}: {file_err}")


        if found_logs:
            print_status(action, "complete", f"Downloaded logs to {len(collected_files)} file(s).")
        else:
            print_status(action, "info", "No log events found in the specified time range for any relevant groups.")

        return collected_files

    except ClientError as e:
        print_status(action, "error", f"Failed during CloudWatch log collection: {e}")
        return [] # Return empty list on error
    except Exception as e:
        print_status(action, "error", f"An unexpected error occurred during log collection: {e}")
        return []


def _check_ssm_agent(ssm_client, instance_id):
    """Checks if the SSM agent on the instance is online."""
    action = f"Checking SSM Agent Status for {instance_id}"
    print_status(action, "pending")
    try:
        response = ssm_client.describe_instance_information(
            Filters=[{'Key': 'InstanceIds', 'Values': [instance_id]}]
        )
        instance_info_list = response.get('InstanceInformationList', [])

        if not instance_info_list:
            print_status(action, "info", "Instance not managed by SSM or no information available.")
            return False

        instance_info = instance_info_list[0]
        ping_status = instance_info.get('PingStatus')

        if ping_status == 'Online':
            agent_version = instance_info.get('AgentVersion', 'Unknown')
            print(Fore.GREEN + f"  └── SSM Agent is Online (Version: {agent_version}).")
            print_status(action, "complete", "SSM Agent is Online.")
            return True
        else:
            last_ping = instance_info.get('LastPingDateTime', 'N/A')
            if isinstance(last_ping, datetime):
                last_ping = last_ping.isoformat()
            status_msg = f"SSM Agent is {ping_status}. Last ping: {last_ping}."
            print(Fore.YELLOW + f"  └── {status_msg}")
            print_status(action, "info", status_msg)
            return False

    except ClientError as e:
        if e.response['Error']['Code'] in ['AccessDeniedException', 'AccessDenied']:
             print_status(action, "error", "Permission denied checking SSM status (ssm:DescribeInstanceInformation).")
        else:
             print_status(action, "error", f"Could not check SSM Agent status: {e}")
        return False
    except Exception as e:
         print_status(action, "error", f"An unexpected error occurred checking SSM Agent: {e}")
         return False


def collect_and_upload_logs(session, instance_id, account_id, region, action_summary):
    """
    Orchestrates log collection: prompts user, creates bucket, gets logs,
    creates summary, zips, uploads, and cleans up.
    """
    action = "Log Collection & Upload"
    print_status(action, "pending") # Initial status

    # --- Confirmation Prompt ---
    print("\n" + Fore.YELLOW + Style.BRIGHT + "--- Optional: Log Collection ---")
    print("This step attempts to:")
    print("  1. Create a unique S3 bucket.")
    print("  2. Download recent CloudWatch Logs potentially related to the instance.")
    print("  3. Generate a summary file of actions taken by this script.")
    print("  4. Zip the logs and summary.")
    print("  5. Upload the zip file to the S3 bucket.")
    print(Fore.YELLOW + "Note: Log collection requires additional permissions (S3, CloudWatch Logs).")
    print("-" * 40)
    confirm = input(f"Do you want to attempt log collection and upload for instance '{instance_id}'? ({Fore.YELLOW}yes/no{Style.RESET_ALL}): ").lower().strip()
    print("-" * 40)

    if confirm != 'yes':
        skip_msg = "User chose NOT to collect logs."
        print(Fore.YELLOW + f"  └── {skip_msg}")
        print_status(action, "skipped", skip_msg)
        logging.warning(skip_msg)
        return "Skipped by user"

    logging.info(f"User confirmed log collection for {instance_id}.")
    s3_client = session.client('s3')
    logs_client = session.client('logs')

    # Define names and paths
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    # Ensure bucket name is globally unique and compliant
    bucket_name = f"containment-logs-{account_id}-{instance_id}-{timestamp}".lower()
    local_log_dir = f"temp_logs_{instance_id}_{timestamp}"
    summary_filename = "action_summary.txt"
    local_summary_path = os.path.join(local_log_dir, summary_filename)
    zip_filename = f"containment_package_{instance_id}_{timestamp}.zip"
    local_zip_path = os.path.join(local_log_dir, zip_filename) # Place zip inside temp dir initially

    try:
        # 1. Create local temp directory
        print(f"  └── Creating temporary directory: {local_log_dir}")
        os.makedirs(local_log_dir, exist_ok=True)

        # 2. Create S3 Bucket
        if not _create_s3_bucket(s3_client, bucket_name, region):
            # Error handled and logged within _create_s3_bucket
            raise Exception("Failed to create or verify S3 bucket.") # Raise to trigger cleanup

        # 3. Get CloudWatch Logs
        # Get logs from the last 30 days
        end_time = datetime.now()
        start_time = end_time - timedelta(days=30)
        start_time_ms = int(start_time.timestamp() * 1000)
        end_time_ms = int(end_time.timestamp() * 1000)

        collected_log_files = _get_cloudwatch_logs(logs_client, instance_id, start_time_ms, end_time_ms, local_log_dir)
        # Status printed within _get_cloudwatch_logs

        # 4. Generate Action Summary File
        print(f"  └── Generating action summary file: {local_summary_path}")
        try:
            with open(local_summary_path, 'w', encoding='utf-8') as f:
                f.write(f"Containment Action Summary for Instance: {instance_id}\n")
                f.write(f"Report Generated: {datetime.now().isoformat()}\n")
                f.write("="*40 + "\n")
                # Sort actions by step number (key) for readability
                for step, details in sorted(action_summary.items()):
                    f.write(f"Step: {step}\n")
                    f.write(f"  Status: {details.get('status', 'Unknown')}\n")
                    f.write(f"  Details: {details.get('details', 'N/A')}\n")
                    f.write("-" * 20 + "\n")
            print("    └── Summary file generated.")
            files_to_zip = collected_log_files + [local_summary_path]
        except IOError as io_err:
             print(Fore.RED + f"    └── Error writing summary file: {io_err}")
             logging.error(f"Error writing summary file {local_summary_path}: {io_err}")
             files_to_zip = collected_log_files # Zip only logs if summary fails
        except Exception as summary_err:
             print(Fore.RED + f"    └── Unexpected error generating summary: {summary_err}")
             logging.error(f"Unexpected error generating summary: {summary_err}")
             files_to_zip = collected_log_files

        # 5. Zip collected files
        if not files_to_zip:
            print("  └── No logs or summary file generated. Skipping zip and upload.")
            print_status(action, "skipped", "No files to collect.")
            # Cleanup handled in finally block
            return "No files collected"

        print(f"  └── Creating zip archive: {local_zip_path}")
        try:
            with zipfile.ZipFile(local_zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for file_path in files_to_zip:
                    # Add file to zip using its basename to avoid deep paths in archive
                    zipf.write(file_path, arcname=os.path.basename(file_path))
            print(f"    └── Zip archive created with {len(files_to_zip)} file(s).")
        except (zipfile.BadZipFile, OSError, FileNotFoundError) as zip_err:
            error_msg = f"Failed to create zip archive: {zip_err}"
            print_status(action, "error", error_msg)
            logging.error(error_msg, exc_info=True)
            raise Exception("Failed to create zip file.") # Trigger cleanup

        # 6. Upload Zip to S3
        print(f"  └── Uploading {zip_filename} to s3://{bucket_name}/")
        try:
            s3_client.upload_file(local_zip_path, bucket_name, zip_filename)
            success_msg = f"Successfully uploaded logs and summary to s3://{bucket_name}/{zip_filename}"
            print(Fore.GREEN + f"    └── {success_msg}")
            print_status(action, "complete", success_msg)
            logging.info(success_msg)
            return f"Logs uploaded to s3://{bucket_name}/{zip_filename}" # Return S3 path on success
        except ClientError as upload_err:
            error_msg = f"Failed to upload logs to S3: {upload_err}"
            print_status(action, "error", error_msg)
            logging.error(error_msg, exc_info=True)
            raise Exception("Failed to upload zip file.") # Trigger cleanup
        except FileNotFoundError:
             error_msg = f"Zip file {local_zip_path} not found for upload. This shouldn't happen."
             print_status(action, "error", error_msg)
             logging.error(error_msg)
             raise Exception("Zip file missing for upload.") # Trigger cleanup

    except Exception as e:
        # Catch exceptions raised from sub-functions or this function
        logging.error(f"Log collection failed: {e}", exc_info=True)
        # Status already set by sub-functions or preceding code
        return f"Failed: {e}" # Return error message

    finally:
        # 7. Cleanup local files
        if os.path.exists(local_log_dir):
            print(f"  └── Cleaning up temporary directory: {local_log_dir}")
            try:
                shutil.rmtree(local_log_dir)
                print("    └── Local cleanup complete.")
            except OSError as cleanup_err:
                print(Fore.YELLOW + f"    └── Warning: Could not completely remove temp directory {local_log_dir}: {cleanup_err}")
                logging.warning(f"Could not remove temp dir {local_log_dir}: {cleanup_err}")

# Need to import os, shutil, zipfile, timedelta at the top
import os
import shutil
import zipfile
from datetime import timedelta