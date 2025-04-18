import sys
import time
from datetime import datetime
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError, WaiterError
from colorama import Fore, Style

# Import helper functions and configuration
from helpers import print_status
from config import CONTAINMENT_NACL_NAME, DENY_POLICY_NAME

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

def apply_nacl_containment(ec2_client, vpc_id, subnet_id, target_instance_id):
    """Creates and applies a deny-all NACL to the instance's subnet."""
    action = f"Applying NACL Containment ({CONTAINMENT_NACL_NAME})"
    print_status(action, "pending")
    original_nacl_association_id = None
    original_nacl_id = None

    try:
        # 1. Find the original NACL association for the target subnet
        response = ec2_client.describe_network_acls(
            Filters=[{'Name': 'association.subnet-id', 'Values': [subnet_id]}]
        )
        if not response.get('NetworkAcls'):
            raise Exception(f"Could not find existing NACL for subnet {subnet_id}")

        original_nacl = response['NetworkAcls'][0]
        original_nacl_id = original_nacl['NetworkAclId']
        # Find the specific association ID for the subnet
        for assoc in original_nacl.get('Associations', []):
            if assoc.get('SubnetId') == subnet_id:
                original_nacl_association_id = assoc['NetworkAclAssociationId']
                break
        if not original_nacl_association_id:
             raise Exception(f"Could not find NACL association ID for subnet {subnet_id}")

        print(f"  └── Original NACL ID for subnet {subnet_id}: {original_nacl_id}")
        print(f"  └── Original NACL Association ID: {original_nacl_association_id}")

        # 2. Check if the containment NACL already exists in the VPC
        existing_nacl_id = None
        response_existing = ec2_client.describe_network_acls(
             Filters=[
                 {'Name': 'vpc-id', 'Values': [vpc_id]},
                 {'Name': 'tag:Name', 'Values': [CONTAINMENT_NACL_NAME]}
             ]
        )
        if response_existing.get('NetworkAcls'):
            existing_nacl_id = response_existing['NetworkAcls'][0]['NetworkAclId']
            print(f"  └── Found existing Containment NACL: {existing_nacl_id}")
            containment_nacl_id = existing_nacl_id
        else:
            # 3. Create the new 'Containment NACL' if it doesn't exist
            print(f"  └── Creating new NACL: {CONTAINMENT_NACL_NAME}")
            nacl_response = ec2_client.create_network_acl(
                VpcId=vpc_id,
                TagSpecifications=[
                    {
                        'ResourceType': 'network-acl',
                        'Tags': [{'Key': 'Name', 'Value': CONTAINMENT_NACL_NAME}]
                    }
                ]
            )
            containment_nacl_id = nacl_response['NetworkAcl']['NetworkAclId']
            print(f"  └── Created Containment NACL ID: {containment_nacl_id}")

            # 4. Add deny rules (ingress and egress) to the new NACL
            # Egress Deny Rule (Outbound traffic - IPv4)
            ec2_client.create_network_acl_entry(
                NetworkAclId=containment_nacl_id, RuleNumber=100, Protocol='-1', # All protocols
                RuleAction='deny', Egress=True, CidrBlock='0.0.0.0/0'          # All IPv4 destinations
            )
            print(f"  └── Added Egress DENY ALL IPv4 rule (100) to {containment_nacl_id}")
            # Egress Deny Rule (Outbound traffic - IPv6)
            ec2_client.create_network_acl_entry(
                NetworkAclId=containment_nacl_id, RuleNumber=101, Protocol='-1', # All protocols
                RuleAction='deny', Egress=True, Ipv6CidrBlock='::/0'           # All IPv6 destinations
            )
            print(f"  └── Added Egress DENY ALL IPv6 rule (101) to {containment_nacl_id}")

            # Ingress Deny Rule (Inbound traffic - IPv4)
            ec2_client.create_network_acl_entry(
                NetworkAclId=containment_nacl_id, RuleNumber=100, Protocol='-1', # All protocols
                RuleAction='deny', Egress=False, CidrBlock='0.0.0.0/0'         # All IPv4 sources
            )
            print(f"  └── Added Ingress DENY ALL IPv4 rule (100) to {containment_nacl_id}")
            # Ingress Deny Rule (Inbound traffic - IPv6)
            ec2_client.create_network_acl_entry(
                NetworkAclId=containment_nacl_id, RuleNumber=101, Protocol='-1', # All protocols
                RuleAction='deny', Egress=False, Ipv6CidrBlock='::/0'         # All IPv6 sources
            )
            print(f"  └── Added Ingress DENY ALL IPv6 rule (101) to {containment_nacl_id}")

        # 5. Associate the 'Containment NACL' with the subnet, replacing the original association
        print(f"  └── Associating {containment_nacl_id} with subnet {subnet_id} (replacing association {original_nacl_association_id})")
        replace_response = ec2_client.replace_network_acl_association(
            AssociationId=original_nacl_association_id,
            NetworkAclId=containment_nacl_id
        )
        new_association_id = replace_response['NewAssociationId']
        print(f"  └── New NACL Association ID: {new_association_id}")

        print_status(action, "complete")
        # Return success and original NACL details for potential rollback (though rollback isn't implemented here)
        return True, original_nacl_id, original_nacl_association_id

    except ClientError as e:
        print_status(action, "error", f"Failed during NACL operations: {e}")
        return False, None, None
    except Exception as e:
         print_status(action, "error", f"An unexpected error occurred during NACL ops: {e}")
         return False, None, None

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

    instances_with_role = []
    try:
        paginator = ec2_client.get_paginator('describe_instances')
        # Filter instances directly by the IAM instance profile ARN
        pages = paginator.paginate(Filters=[{'Name': 'iam-instance-profile.arn', 'Values': [profile_arn]}])

        count = 0
        for page in pages:
            for reservation in page.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    instance_id = instance['InstanceId']
                    # Exclude the original target instance from the list
                    if instance_id != excluded_instance_id:
                        # Only consider instances that are running or stopped
                        if instance.get('State', {}).get('Name') in ['running', 'stopped']:
                            instances_with_role.append(instance_id)
                            count += 1

        if instances_with_role:
             # Extract a display name for the profile from the ARN
             profile_name_display = profile_arn.split('/')[-1] if '/' in profile_arn else profile_arn
             print_status(action, "info", f"Found {count} other running/stopped instance(s) using the same profile ({profile_name_display}):")
             for iid in instances_with_role:
                 print(f"  - {iid}")
             print(Fore.YELLOW + "  └── Consider if these instances might also be compromised or affected.")
        else:
            print_status(action, "info", "No other running/stopped instances found using this instance profile.")

        return instances_with_role

    except ClientError as e:
        err_code = e.response.get("Error", {}).get("Code")
        if err_code == 'AccessDenied':
            msg = "Permission denied searching for instances by role profile ARN (ec2:DescribeInstances with filter)."
        elif 'InvalidFilter' in err_code:
            msg = f"Invalid filter used when searching instances by role profile ARN: {e}"
        else:
            msg = f"Could not search for instances by role profile ARN: {e}"
        print_status(action, "error", msg)
        return [] # Return empty list on error
    except Exception as e:
         print_status(action, "error", f"An unexpected error occurred searching instances by role: {e}")
         return []

def get_role_permissions(iam_client, role_name):
    """Lists managed and inline policies attached to the specified IAM role."""
    action = f"Getting Permissions for Role ({role_name})"
    print_status(action, "pending")
    if not role_name:
        print_status(action, "skipped", "No role name provided.")
        return

    try:
        print(f"  Permissions for role '{role_name}':")
        policy_found = False

        # List Managed Policies attached to the role
        try:
            attached_policies_paginator = iam_client.get_paginator('list_attached_role_policies')
            managed_policy_count = 0
            print("  └── Managed Policies:")
            for page in attached_policies_paginator.paginate(RoleName=role_name):
                 if page.get('AttachedPolicies'):
                     for policy in page['AttachedPolicies']:
                         print(f"      - {policy['PolicyName']} ({policy['PolicyArn']})")
                         managed_policy_count += 1
                         policy_found = True
            if managed_policy_count == 0:
                print("      (None found)")
        except ClientError as e:
             err_code = e.response.get("Error", {}).get("Code")
             if err_code == 'NoSuchEntity': # Should not happen if role_name is valid, but check
                  print(Fore.RED + f"      Error: Role '{role_name}' not found when listing managed policies.")
             elif err_code == 'AccessDenied':
                  print(Fore.RED + f"      Permission denied for iam:ListAttachedRolePolicies on role '{role_name}'.")
             else:
                  print(Fore.RED + f"      Error listing managed policies: {e}")

        # List Inline Policies embedded in the role
        try:
            inline_policies_paginator = iam_client.get_paginator('list_role_policies')
            inline_policy_count = 0
            print("  └── Inline Policies:")
            for page in inline_policies_paginator.paginate(RoleName=role_name):
                 if page.get('PolicyNames'):
                     for policy_name in page['PolicyNames']:
                          print(f"      - {policy_name}")
                          # To see the policy content, you'd need another call:
                          # iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)
                          inline_policy_count += 1
                          policy_found = True
            if inline_policy_count == 0:
                 print("      (None found)")
        except ClientError as e:
             err_code = e.response.get("Error", {}).get("Code")
             if err_code == 'NoSuchEntity':
                  print(Fore.RED + f"      Error: Role '{role_name}' not found when listing inline policies.")
             elif err_code == 'AccessDenied':
                  print(Fore.RED + f"      Permission denied for iam:ListRolePolicies on role '{role_name}'.")
             else:
                  print(Fore.RED + f"      Error listing inline policies: {e}")

        if policy_found:
            print_status(action, "complete")
        else:
            # If no policies were found and no errors occurred listing them
            print_status(action, "info", f"No managed or inline policies listed for role '{role_name}'.")

    except Exception as e: # Catch unexpected errors during the process
         print_status(action, "error", f"An unexpected error occurred getting policies for role {role_name}: {e}")


def revoke_role_sessions(iam_client, role_name):
    """
    Applies a deny-all inline policy to the specified role to effectively
    revoke active sessions using those credentials.
    """
    action = f"Revoking Sessions for Role ({role_name})"

    if not role_name:
        print_status(action, "skipped", "No role name provided to revoke sessions for.")
        return

    print(f"\n{Fore.YELLOW}--- Revoke IAM Role Sessions ---")
    print(f"This action will attach or overwrite an INLINE policy named '{DENY_POLICY_NAME}'")
    print(f"to the role '{Fore.CYAN}{role_name}{Style.RESET_ALL}'. This policy denies all actions ('Action': '*', 'Resource': '*')")
    print("effectively preventing any further use of temporary credentials obtained from this role.")
    print(Fore.YELLOW + "This is a critical step if the role's credentials are suspected to be compromised.")
    choice = input(f"Do you want to apply the '{DENY_POLICY_NAME}' policy to role '{role_name}'? (yes/no): ").lower().strip()

    if choice == 'yes':
        print_status(action, "pending")
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
            # Use put_role_policy: creates the policy if it doesn't exist, overwrites it if it does.
            iam_client.put_role_policy(
                RoleName=role_name,
                PolicyName=DENY_POLICY_NAME,
                PolicyDocument=deny_policy_doc
            )
            print_status(action, "complete", f"Applied '{DENY_POLICY_NAME}' deny policy to role '{role_name}'. Active sessions using this role should now be blocked.")
        except ClientError as e:
            err_code = e.response.get("Error", {}).get("Code")
            if err_code == 'NoSuchEntity':
                 msg = f"Role '{role_name}' not found. Cannot apply deny policy."
            elif err_code == 'AccessDenied':
                 msg = f"Permission denied for iam:PutRolePolicy on role '{role_name}'."
            elif err_code == 'LimitExceeded':
                  msg = f"Cannot add inline policy '{DENY_POLICY_NAME}'. Role '{role_name}' may already have the maximum number of inline policies."
            elif err_code == 'MalformedPolicyDocument':
                 # This shouldn't happen with the hardcoded policy, but check anyway
                 msg = f"The generated Deny All policy document is invalid."
            else:
                msg = f"Failed to apply deny policy to role {role_name}: {e}"
            print_status(action, "error", msg)
        except Exception as e:
            print_status(action, "error", f"An unexpected error occurred applying deny policy: {e}")

    else:
        print_status(action,"warning", f"Session revocation SKIPPED for role {role_name}.")
        print(Fore.RED + Style.BRIGHT + "  └── WARNING: If compromise is suspected, it is HIGHLY RECOMMENDED to revoke sessions to prevent further unauthorized actions.")

def get_ebs_volumes(instance_details):
    """Gets EBS volume information attached to the instance from its details."""
    action = "Getting Attached EBS Volumes"
    print_status(action, "pending")
    volumes = [] # List to store dicts like {'VolumeId': 'vol-..', 'DeviceName': '/dev/..', 'SizeGB': None}
    block_device_mappings = instance_details.get('BlockDeviceMappings', [])

    if not block_device_mappings:
        print_status(action, "info", "No block device mappings found for the instance.")
        return []

    print("  Attached EBS Volumes:")
    for mapping in block_device_mappings:
        # Check if the mapping is for an EBS volume and has a VolumeId
        if 'Ebs' in mapping and 'VolumeId' in mapping['Ebs']:
            volume_id = mapping['Ebs']['VolumeId']
            device_name = mapping.get('DeviceName', 'N/A') # Get device name if available
            # Size will be fetched in a separate step
            volumes.append({'VolumeId': volume_id, 'DeviceName': device_name, 'SizeGB': None})
            print(f"  - Volume ID: {volume_id}, Device: {device_name}")
        else:
             # Log if a mapping exists but isn't for a standard EBS volume
             device_name = mapping.get('DeviceName', 'N/A')
             print(f"  - Non-EBS or incomplete mapping found for device: {device_name}")

    if not volumes:
        print_status(action, "info", "No EBS volumes identified in block device mappings.")
        return []
    else:
        print_status(action, "complete")
        return volumes


def describe_and_update_volume_sizes(ec2_client, volumes):
    """
    Takes a list of volume dicts (from get_ebs_volumes), fetches their sizes
    using ec2:DescribeVolumes, and updates the 'SizeGB' key in the dicts.
    Returns the updated list.
    """
    if not volumes:
        return volumes # Return immediately if the list is empty

    action = "Getting EBS Volume Sizes"
    print_status(action, "pending")
    volume_ids = [v['VolumeId'] for v in volumes if v.get('VolumeId')] # Get valid volume IDs
    if not volume_ids:
         print_status(action, "skipped", "No valid volume IDs to describe.")
         return volumes # Return original list if no IDs

    # Create a copy to modify, preserving the original list structure
    updated_volumes = [v.copy() for v in volumes]

    try:
        # Call describe_volumes for all volumes at once
        response = ec2_client.describe_volumes(VolumeIds=volume_ids)
        # Create a mapping from VolumeId to Size for easy lookup
        size_map = {vol['VolumeId']: vol.get('Size') for vol in response.get('Volumes', [])}

        all_found = True
        print("  Volume sizes:")
        for v in updated_volumes:
            vol_id = v.get('VolumeId')
            if vol_id: # Process only if VolumeId exists
                size_gb = size_map.get(vol_id)
                if size_gb is not None:
                     v['SizeGB'] = size_gb
                     print(f"   - {v['VolumeId']} ({v.get('DeviceName', 'N/A')}): {v['SizeGB']} GB")
                else:
                     # Size wasn't found in the response (volume might have been deleted?)
                     v['SizeGB'] = 'Unknown'
                     all_found = False
                     print(Fore.YELLOW + f"  └── Warning: Could not determine size for volume {vol_id}")
            else:
                 v['SizeGB'] = 'N/A' # Mark as N/A if no VolumeId initially

        if all_found:
            print_status(action, "complete")
        else:
             print_status(action, "warning", "Could not determine size for one or more volumes.")

        return updated_volumes

    except ClientError as e:
        err_code = e.response.get("Error", {}).get("Code")
        if err_code == 'AccessDenied':
            msg = "Permission denied for ec2:DescribeVolumes. Sizes will remain unknown."
        elif 'InvalidVolume.NotFound' in str(e):
             msg = "One or more specified volume IDs not found during size lookup. Sizes may be incomplete."
        else:
            msg = f"Could not describe volumes to get sizes: {e}. Sizes will remain unknown."
        print_status(action, "error", msg)
        # Mark sizes as 'Error' in the list before returning
        for v in updated_volumes: v['SizeGB'] = 'Error'
        return updated_volumes
    except Exception as e:
         print_status(action, "error", f"An unexpected error occurred getting volume sizes: {e}. Sizes will remain unknown.")
         for v in updated_volumes: v['SizeGB'] = 'Error'
         return updated_volumes


def snapshot_ebs_volumes(ec2_client, volumes, instance_id):
    """
    Offers to snapshot the provided list of EBS volumes. Creates snapshots
    with descriptive tags and waits for them to complete.
    """
    action = "Snapshotting EBS Volumes"
    if not volumes:
        print_status(action, "skipped", "No EBS volumes provided to snapshot.")
        return

    # Filter for volumes that actually have a VolumeId
    valid_volumes = [v for v in volumes if v.get('VolumeId')]
    if not valid_volumes:
        print_status(action, "skipped", "No valid EBS volumes found to snapshot.")
        return

    print(f"\n{Fore.YELLOW}--- EBS Volume Snapshots ---")
    print("Snapshots are crucial for forensic analysis. They capture the state of the disk at this point in time.")
    print("The following volumes were found:")
    for v in valid_volumes:
        size_display = f"{v.get('SizeGB', 'Unknown')} GB" if v.get('SizeGB') is not None else "Unknown Size"
        print(f"  - {v['VolumeId']} ({v.get('DeviceName', 'N/A')}) - {size_display}")
    choice = input("Do you want to create snapshots of these volumes? (yes/no): ").lower().strip()

    if choice == 'yes':
        print_status(action, "pending")
        snapshot_ids = [] # List to store IDs of successfully initiated snapshots
        snapshot_start_time = time.time()
        today_date = datetime.utcnow().strftime('%Y%m%d') # For tagging
        created_count = 0
        error_count = 0

        try:
            for volume in valid_volumes:
                vol_id = volume['VolumeId']
                # Clean up device name for use in tags/description (replace non-alphanumeric)
                device_name_raw = volume.get('DeviceName', 'unknown_device')
                device_name_cleaned = ''.join(c if c.isalnum() or c in ['-', '_'] else '_' for c in device_name_raw)

                # Create descriptive elements for the snapshot
                description = f"Incident Response snapshot for instance {instance_id}, volume {vol_id}, device {device_name_raw}"
                # Construct a base tag name, ensuring it's within AWS length limits (255 chars)
                snapshot_tag_name_base = f"IR-{instance_id}-{device_name_cleaned}-snapshot-{today_date}"
                snapshot_tag_name = snapshot_tag_name_base[:255]

                print(f"  └── Initiating snapshot for {vol_id} (Device: {device_name_raw})...")
                try:
                    snap_response = ec2_client.create_snapshot(
                        VolumeId=vol_id,
                        Description=description,
                        TagSpecifications=[{
                            'ResourceType': 'snapshot',
                            'Tags': [
                                {'Key': 'Name', 'Value': snapshot_tag_name},
                                {'Key': 'IncidentResponseSourceInstance', 'Value': instance_id},
                                {'Key': 'SourceVolumeId', 'Value': vol_id},
                                {'Key': 'CreationTool', 'Value': 'AWS_IR_Containment_Script'} # Add tool tag
                            ]
                        }]
                    )
                    snapshot_id = snap_response['SnapshotId']
                    snapshot_ids.append(snapshot_id)
                    print(f"      └── Snapshot initiated: {snapshot_id}")
                    created_count += 1
                except ClientError as snap_err:
                    print(Fore.RED + f"      └── ERROR creating snapshot for {vol_id}: {snap_err}")
                    error_count += 1
                    # Continue to the next volume even if one fails

            # --- Wait for snapshots to complete (only if some were initiated) ---
            if snapshot_ids:
                print(f"\n  └── Waiting for {len(snapshot_ids)} snapshot(s) to complete...")
                print(Fore.YELLOW + "      This can take a significant amount of time depending on volume size and AWS activity.")
                waiter = ec2_client.get_waiter('snapshot_completed')
                all_completed_successfully = True # Track overall success of the waiting phase

                try:
                    waiter.wait(
                        SnapshotIds=snapshot_ids,
                        WaiterConfig={
                            'Delay': 30,  # Check status every 30 seconds
                            'MaxAttempts': 120 # Wait up to 60 minutes (30s * 120 attempts)
                        }
                    )
                    # After the waiter finishes, double-check the final state of each snapshot
                    # as the waiter only confirms a terminal state (completed or error)
                    print("  └── Checking final snapshot statuses...")
                    final_statuses = ec2_client.describe_snapshots(SnapshotIds=snapshot_ids)
                    for snap in final_statuses.get('Snapshots', []):
                        snap_id = snap['SnapshotId']
                        state = snap['State']
                        if state == 'error':
                             print(Fore.RED + f"      └── Snapshot {snap_id} FAILED: {snap.get('StateMessage', 'Unknown error')}")
                             all_completed_successfully = False
                        elif state == 'completed':
                              print(Fore.GREEN + f"      └── Snapshot {snap_id} COMPLETED.")
                        else: # Should not happen if waiter exited cleanly, but log if it does
                             print(Fore.YELLOW + f"      └── Snapshot {snap_id} in unexpected final state: {state}")
                             all_completed_successfully = False # Treat unexpected as not fully successful

                    snapshot_duration = time.time() - snapshot_start_time
                    if all_completed_successfully:
                        print(f"  └── All {len(snapshot_ids)} initiated snapshots completed successfully in ~{snapshot_duration:.0f} seconds.")
                        print_status(action, "complete")
                    else:
                         print_status(action, "error", f"One or more initiated snapshots did not complete successfully after ~{snapshot_duration:.0f} seconds.")

                except WaiterError as wait_error:
                     # This catches timeouts or API errors during the wait
                     print_status(action, "error", f"Error or timeout waiting for snapshots (they might still be running or have failed): {wait_error}")
                     print(Fore.YELLOW + "      └── Please check the AWS console for the final status of snapshots: " + ", ".join(snapshot_ids))
                except ClientError as desc_err:
                     # This catches errors trying to describe the final statuses
                     print_status(action, "error", f"Could not describe final snapshot statuses after waiting: {desc_err}")
                     print(Fore.YELLOW + "      └── Please check the AWS console for the final status of snapshots: " + ", ".join(snapshot_ids))

            elif created_count == 0 and error_count > 0:
                 # Case where all snapshot creations failed
                 print_status(action, "error", "Failed to initiate snapshot creation for any volumes.")
            elif created_count == 0 and error_count == 0:
                 # Should not happen if valid_volumes was not empty, but handle defensively
                 print_status(action, "skipped", "No snapshots were initiated (unexpected state).")
            # If created_count > 0 and error_count > 0, the waiting block handles the initiated ones.

        except Exception as e: # Catch unexpected errors in the main snapshot loop
            print_status(action, "error", f"An unexpected error occurred during the snapshotting process: {e}")

    else:
        print_status(action, "skipped", "Snapshot creation declined by user.")


def stop_instance(ec2_client, instance_id):
    """Offers to stop the EC2 instance and waits for it to reach the stopped state."""
    action = f"Stopping EC2 Instance {instance_id}"

    # --- Check current instance state before prompting ---
    try:
        instance_status_response = ec2_client.describe_instance_status(
            InstanceIds=[instance_id],
            IncludeAllInstances=True # Important to get status even if not 'running'
        )
        current_state = None
        if instance_status_response.get('InstanceStatuses'):
            current_state = instance_status_response['InstanceStatuses'][0]['InstanceState']['Name']

        # If already stopped or stopping, inform the user and skip the prompt
        if current_state == 'stopped':
            print(f"\n{Fore.BLUE}--- Stop EC2 Instance ---")
            print_status(action, "info", f"Instance {instance_id} is already stopped.")
            return # Exit the function, no action needed
        elif current_state == 'stopping':
            print(f"\n{Fore.BLUE}--- Stop EC2 Instance ---")
            print_status(action, "info", f"Instance {instance_id} is already in the process of stopping.")
            return # Exit the function, no action needed
        elif current_state not in ['running', 'pending']:
             # If it's in an unexpected state (e.g., terminated, shutting-down), skip stop
             print(f"\n{Fore.BLUE}--- Stop EC2 Instance ---")
             print_status(action, "warning", f"Instance {instance_id} is in state '{current_state}'. Skipping stop option.")
             return

    except ClientError as status_err:
         # Log error getting status, but proceed to ask anyway. The stop call will fail if not stoppable.
         print(Fore.YELLOW + f"Warning: Could not get current instance status before prompting stop: {status_err}")

    # --- Prompt user to stop ---
    print(f"\n{Fore.YELLOW}--- Stop EC2 Instance ---")
    print("Stopping the instance prevents further malicious activity (like C2 communication or data exfiltration)")
    print("and can also help reduce costs if the instance was compromised for resource abuse (e.g., crypto mining).")
    print(f"Instance {instance_id} will be STOPPED, not TERMINATED. Data on EBS volumes persists.")
    choice = input(f"Do you want to stop instance {instance_id} now? (yes/no): ").lower().strip()

    if choice == 'yes':
        print_status(action, "pending")
        try:
            # Initiate the stop operation
            stop_response = ec2_client.stop_instances(InstanceIds=[instance_id])

            # Log the state change information from the response
            if 'StoppingInstances' in stop_response and stop_response['StoppingInstances']:
                state_change = stop_response['StoppingInstances'][0]
                current_state_resp = state_change.get('CurrentState', {}).get('Name', 'Unknown')
                previous_state_resp = state_change.get('PreviousState', {}).get('Name', 'Unknown')
                print(f"  └── Stop request sent. Instance transitioning from {previous_state_resp} to {current_state_resp}.")
            else:
                 # Log if the response format is unexpected, though the call might have worked
                 print(Fore.YELLOW + "  └── Stop request sent, but response format was unexpected.")

            # --- Wait for the instance to reach the 'stopped' state ---
            print(f"  └── Waiting for instance {instance_id} to reach the 'stopped' state...")
            waiter = ec2_client.get_waiter('instance_stopped')
            waiter.wait(
                InstanceIds=[instance_id],
                WaiterConfig={'Delay': 15, 'MaxAttempts': 40} # Check every 15s for up to 10 mins
            )
            print(Fore.GREEN + f"  └── Instance {instance_id} confirmed stopped.")
            print_status(action, "complete")

        except ClientError as e:
            err_code = e.response.get("Error", {}).get("Code")
            # Handle specific errors related to stopping instances
            if 'IncorrectInstanceState' in err_code or 'UnsupportedOperation' in err_code:
                 msg = f"Instance {instance_id} is not in a stoppable state (e.g., already stopped, terminated, or stopping)."
            elif 'AccessDenied' in err_code:
                 msg = f"Permission denied for ec2:StopInstances on {instance_id}."
            else:
                msg = f"Failed to stop instance {instance_id}: {e}"
            print_status(action, "error", msg)
        except WaiterError as wait_err:
             # Handle timeout or errors during the waiting period
             print_status(action, "error", f"Instance stop initiated, but timed out or error occurred while waiting for confirmation: {wait_err}")
             print(Fore.YELLOW + f"      └── Instance {instance_id} might still be stopping. Please verify its status in the AWS console.")
        except Exception as e:
            print_status(action, "error", f"An unexpected error occurred stopping instance: {e}")
    else:
        print_status(action,"warning", "Instance stop declined by user.")
        print(Fore.RED + Style.BRIGHT + "  └── WARNING: Leaving a potentially compromised instance running poses security risks and may incur costs. It is strongly advised to stop the instance unless there's a specific reason not to.")


# --- Pre-flight Check Function ---

def perform_preflight_checks(session, instance_id, instance_details, vpc_id, subnet_id, instance_role_name, attached_volumes):
    """
    Performs non-mutating checks to verify permissions and resource states
    before attempting containment actions.
    Returns: tuple (bool: overall_success, list: issues_found)
    """
    action = "Performing Pre-flight Checks"
    print_status(action, "pending")
    issues_found = []
    overall_success = True # Assume success initially

    # Initialize clients needed for checks
    try:
        ec2 = session.client('ec2')
        iam = session.client('iam')
        # Add other clients if needed for specific checks (e.g., autoscaling, elb)
    except Exception as e:
        msg = f"Failed to create Boto3 clients for pre-flight checks: {e}"
        print_status(action, "error", msg)
        issues_found.append(msg)
        return False, issues_found

    # --- Check EC2 Instance State ---
    try:
        status_response = ec2.describe_instance_status(InstanceIds=[instance_id], IncludeAllInstances=True)
        if status_response.get('InstanceStatuses'):
            state = status_response['InstanceStatuses'][0]['InstanceState']['Name']
            if state not in ['running', 'stopped', 'pending']: # Stoppable states
                 warning_msg = f"Instance {instance_id} is in state '{state}', which might interfere with some actions (like stop)."
                 print(Fore.YELLOW + f"  └── Pre-flight Warning: {warning_msg}")
                 issues_found.append(warning_msg)
                 # Not necessarily a failure, but a warning
        else:
             warning_msg = f"Could not retrieve current status for instance {instance_id}."
             print(Fore.YELLOW + f"  └── Pre-flight Warning: {warning_msg}")
             issues_found.append(warning_msg)
    except ClientError as e:
        error_msg = f"Permission denied or error checking instance status (ec2:DescribeInstanceStatus): {e}"
        print(Fore.RED + f"  └── Pre-flight ERROR: {error_msg}")
        issues_found.append(error_msg)
        overall_success = False
    except Exception as e:
        error_msg = f"Unexpected error checking instance status: {e}"
        print(Fore.RED + f"  └── Pre-flight ERROR: {error_msg}")
        issues_found.append(error_msg)
        overall_success = False


    # --- Check NACL Permissions ---
    try:
        # Check describe permission needed before replace
        ec2.describe_network_acls(Filters=[{'Name': 'association.subnet-id', 'Values': [subnet_id]}], MaxResults=5) # Corrected MaxResults
        # Check create permission (best effort by trying describe on VPC)
        ec2.describe_network_acls(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}], MaxResults=5) # Corrected MaxResults
        # Note: Cannot directly check CreateNetworkAclEntry or ReplaceNetworkAclAssociation without trying them.
        print(f"  └── Pre-flight: Basic NACL describe checks passed for subnet {subnet_id}.")
    except ClientError as e:
        error_msg = f"Permission denied or error describing NACLs (ec2:DescribeNetworkAcls): {e}. NACL containment might fail."
        print(Fore.RED + f"  └── Pre-flight ERROR: {error_msg}")
        issues_found.append(error_msg)
        overall_success = False
    except Exception as e:
        error_msg = f"Unexpected error during NACL pre-flight check: {e}"
        print(Fore.RED + f"  └── Pre-flight ERROR: {error_msg}")
        issues_found.append(error_msg)
        overall_success = False

    # --- Check Termination Protection Modify Permission ---
    try:
        # Check describe permission as proxy for modify
        ec2.describe_instance_attribute(InstanceId=instance_id, Attribute='disableApiTermination')
        print(f"  └── Pre-flight: Basic check for termination protection attribute passed.")
    except ClientError as e:
        error_msg = f"Permission denied or error describing instance attributes (ec2:DescribeInstanceAttribute): {e}. Enabling termination protection might fail."
        print(Fore.RED + f"  └── Pre-flight ERROR: {error_msg}")
        issues_found.append(error_msg)
        overall_success = False # Consider this critical
    except Exception as e:
        error_msg = f"Unexpected error during termination protection pre-flight check: {e}"
        print(Fore.RED + f"  └── Pre-flight ERROR: {error_msg}")
        issues_found.append(error_msg)
        overall_success = False

    # --- Check IAM Role Permissions (if role exists) ---
    if instance_role_name:
        try:
            # Check permissions needed for get_role_permissions and revoke_role_sessions
            iam.list_attached_role_policies(RoleName=instance_role_name, MaxItems=1)
            iam.list_role_policies(RoleName=instance_role_name, MaxItems=1)
            # Cannot easily check PutRolePolicy without trying it, but list checks are a good indicator.
            print(f"  └── Pre-flight: Basic IAM policy listing checks passed for role {instance_role_name}.")
        except ClientError as e:
            error_msg = f"Permission denied or error listing policies for role {instance_role_name} (iam:ListAttachedRolePolicies/iam:ListRolePolicies): {e}. Role analysis/revocation might fail."
            print(Fore.RED + f"  └── Pre-flight ERROR: {error_msg}")
            issues_found.append(error_msg)
            overall_success = False # Role actions are important
        except Exception as e:
            error_msg = f"Unexpected error during IAM role pre-flight check: {e}"
            print(Fore.RED + f"  └── Pre-flight ERROR: {error_msg}")
            issues_found.append(error_msg)
            overall_success = False

    # --- Check EBS Volume/Snapshot Permissions ---
    volume_ids = [v['VolumeId'] for v in attached_volumes if v.get('VolumeId')]
    if volume_ids:
        try:
            # Check describe volumes permission
            ec2.describe_volumes(VolumeIds=volume_ids[:1]) # Check only first volume to limit API calls
            # Check describe snapshots permission (needed for waiter)
            # Attempting to describe a non-existent snapshot is one way, but might clutter logs.
            # A simpler check is just to assume DescribeSnapshots is needed if CreateSnapshot is.
            # Cannot check CreateSnapshot without trying it.
            print(f"  └── Pre-flight: Basic EBS volume describe checks passed for volumes: {', '.join(volume_ids)}.")
        except ClientError as e:
            error_msg = f"Permission denied or error describing volumes (ec2:DescribeVolumes): {e}. Volume analysis/snapshotting might fail."
            print(Fore.RED + f"  └── Pre-flight ERROR: {error_msg}")
            issues_found.append(error_msg)
            overall_success = False # Snapshots are critical
        except Exception as e:
            error_msg = f"Unexpected error during EBS volume pre-flight check: {e}"
            print(Fore.RED + f"  └── Pre-flight ERROR: {error_msg}")
            issues_found.append(error_msg)
            overall_success = False

    # --- Check Stop Instance Permission ---
    try:
        # Describe status is already checked above, which is a good indicator for StopInstances permission.
        # We could try a dry-run stop, but it might be overly complex here.
        # Relying on the earlier DescribeInstanceStatus check.
        pass # Assuming DescribeInstanceStatus check is sufficient proxy
    except Exception as e:
        # This block is unlikely to be hit unless DescribeInstanceStatus logic changes
        error_msg = f"Unexpected error during stop instance pre-flight check: {e}"
        print(Fore.RED + f"  └── Pre-flight ERROR: {error_msg}")
        issues_found.append(error_msg)
        overall_success = False


    # --- Final Pre-flight Status ---
    if overall_success and not issues_found:
        print_status(action, "complete", "All critical pre-flight checks passed.")
    elif overall_success and issues_found:
         print_status(action, "warning", "Pre-flight checks passed, but warnings were noted (see above).")
    else:
         print_status(action, "error", "One or more critical pre-flight checks failed (see above).")

    return overall_success, issues_found


# --- Log Collection and Upload ---
import logging # Ensure logging is imported if not already at top level
import zipfile
import os
from datetime import timedelta

def _create_s3_bucket(s3_client, bucket_name, region):
    """Creates an S3 bucket if it doesn't exist."""
    try:
        # Use head_bucket to check existence and permissions
        s3_client.head_bucket(Bucket=bucket_name)
        print(f"  └── S3 Bucket '{bucket_name}' already exists.")
        logging.info(f"S3 Bucket '{bucket_name}' already exists.")
        return True
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code")
        if error_code == '404' or error_code == 'NoSuchBucket': # Not found, try to create
            print(f"  └── S3 Bucket '{bucket_name}' not found. Attempting to create...")
            logging.info(f"S3 Bucket '{bucket_name}' not found. Attempting to create...")
            try:
                # Handle regions other than us-east-1 which require LocationConstraint
                if region == 'us-east-1':
                    s3_client.create_bucket(Bucket=bucket_name)
                else:
                    s3_client.create_bucket(
                        Bucket=bucket_name,
                        CreateBucketConfiguration={'LocationConstraint': region}
                    )
                print(f"  └── Successfully created S3 bucket '{bucket_name}' in region {region}.")
                logging.info(f"Successfully created S3 bucket '{bucket_name}' in region {region}.")
                # Optional: Add bucket policy or block public access settings here if needed
                return True
            except ClientError as create_err:
                msg = f"Failed to create S3 bucket '{bucket_name}': {create_err}"
                print_status("Create S3 Bucket", "error", msg)
                logging.error(msg, exc_info=True)
                return False
            except Exception as create_exc:
                msg = f"Unexpected error creating S3 bucket '{bucket_name}': {create_exc}"
                print_status("Create S3 Bucket", "error", msg)
                logging.error(msg, exc_info=True)
                return False
        elif error_code == '403':
            msg = f"Permission denied checking or creating S3 bucket '{bucket_name}' (s3:HeadBucket or s3:CreateBucket)."
            print_status("Create S3 Bucket", "error", msg)
            logging.error(msg)
            return False
        else: # Other unexpected ClientError
            msg = f"Error checking S3 bucket '{bucket_name}': {e}"
            print_status("Create S3 Bucket", "error", msg)
            logging.error(msg, exc_info=True)
            return False
    except Exception as e: # Catch other potential errors like invalid bucket name format
         msg = f"Unexpected error during S3 bucket check/creation for '{bucket_name}': {e}"
         print_status("Create S3 Bucket", "error", msg)
         logging.error(msg, exc_info=True)
         return False


def _get_cloudwatch_logs(logs_client, instance_id, start_time_ms, end_time_ms, local_log_dir):
    """Attempts to find and download relevant CloudWatch logs."""
    print_status("Fetching CloudWatch Logs", "pending")
    log_groups_found = []
    logs_downloaded = False
    # Heuristics to find relevant log groups (adjust as needed)
    log_group_prefixes = [f'/aws/ec2/{instance_id}', f'/aws/ssm/{instance_id}', '/var/log/', 'messages', 'syslog', instance_id]

    try:
        paginator = logs_client.get_paginator('describe_log_groups')
        print("  └── Searching for relevant CloudWatch Log Groups...")
        for page in paginator.paginate():
            for group in page.get('logGroups', []):
                group_name = group['logGroupName']
                # Check if group name contains instance ID or common log paths
                if any(prefix in group_name for prefix in log_group_prefixes):
                    log_groups_found.append(group_name)
                    print(f"      Found potentially relevant group: {group_name}")

        if not log_groups_found:
            print_status("Fetching CloudWatch Logs", "info", "No potentially relevant CloudWatch Log Groups found based on common patterns.")
            logging.info("No potentially relevant CloudWatch Log Groups found.")
            return False # Indicate no logs were downloaded

        print(f"  └── Attempting to fetch logs from {len(log_groups_found)} group(s) for the last 30 days...")
        for group_name in log_groups_found:
            print(f"      Processing group: {group_name}")
            group_file_path = os.path.join(local_log_dir, f"cloudwatch_{group_name.replace('/', '_')}.log")
            try:
                # Use filter_log_events for simplicity, might miss streams without events in range
                log_event_paginator = logs_client.get_paginator('filter_log_events')
                event_pages = log_event_paginator.paginate(
                    logGroupName=group_name,
                    startTime=start_time_ms,
                    endTime=end_time_ms
                )
                with open(group_file_path, 'w', encoding='utf-8') as f:
                    event_count = 0
                    for page in event_pages:
                        for event in page.get('events', []):
                            f.write(f"{datetime.fromtimestamp(event['timestamp']/1000).isoformat()} - {event['message']}\n")
                            event_count += 1
                    if event_count > 0:
                        print(f"      └── Downloaded {event_count} events to {os.path.basename(group_file_path)}")
                        logs_downloaded = True
                    else:
                        print(f"      └── No events found in the specified time range for {group_name}.")
                        # Clean up empty file
                        try:
                            os.remove(group_file_path)
                        except OSError:
                            pass # Ignore if file couldn't be removed
            except ClientError as e:
                 print(Fore.YELLOW + f"      └── Warning: Could not fetch logs from {group_name}: {e}")
                 logging.warning(f"Could not fetch logs from {group_name}: {e}", exc_info=True)
            except Exception as e:
                 print(Fore.YELLOW + f"      └── Warning: Unexpected error fetching logs from {group_name}: {e}")
                 logging.warning(f"Unexpected error fetching logs from {group_name}: {e}", exc_info=True)

        if logs_downloaded:
            print_status("Fetching CloudWatch Logs", "complete", f"Downloaded logs saved in {local_log_dir}")
        else:
             print_status("Fetching CloudWatch Logs", "info", "Completed search, but no relevant log events found/downloaded.")

        return logs_downloaded

    except ClientError as e:
        msg = f"Permission denied or error describing log groups (logs:DescribeLogGroups or logs:FilterLogEvents): {e}"
        print_status("Fetching CloudWatch Logs", "error", msg)
        logging.error(msg, exc_info=True)
        return False
    except Exception as e:
        msg = f"Unexpected error fetching CloudWatch logs: {e}"
        print_status("Fetching CloudWatch Logs", "error", msg)
        logging.error(msg, exc_info=True)
        return False

def _check_ssm_agent(ssm_client, instance_id):
    """Checks if SSM Agent is potentially running on the instance."""
    print_status("Checking SSM Agent Status", "pending")
    try:
        response = ssm_client.describe_instance_information(
            Filters=[{'Key': 'InstanceIds', 'Values': [instance_id]}]
        )
        instance_info = response.get('InstanceInformationList', [])
        if instance_info:
            ping_status = instance_info[0].get('PingStatus')
            agent_version = instance_info[0].get('AgentVersion', 'Unknown')
            if ping_status == 'Online':
                msg = f"SSM Agent is Online (Version: {agent_version}). Manual system log retrieval via SSM might be possible."
                print_status("Checking SSM Agent Status", "info", msg)
                logging.info(msg)
                return True
            else:
                msg = f"SSM Agent status is {ping_status} (Version: {agent_version}). System log retrieval via SSM likely not possible."
                print_status("Checking SSM Agent Status", "warning", msg)
                logging.warning(msg)
                return False
        else:
            msg = f"Instance {instance_id} not found in SSM or not managed by SSM."
            print_status("Checking SSM Agent Status", "info", msg)
            logging.info(msg)
            return False
    except ClientError as e:
        msg = f"Permission denied or error checking SSM status (ssm:DescribeInstanceInformation): {e}"
        print_status("Checking SSM Agent Status", "error", msg)
        logging.error(msg, exc_info=True)
        return False
    except Exception as e:
        msg = f"Unexpected error checking SSM status: {e}"
        print_status("Checking SSM Agent Status", "error", msg)
        logging.error(msg, exc_info=True)
        return False


def collect_and_upload_logs(session, instance_id, account_id, region, action_summary):
    """
    Orchestrates log collection (CloudWatch, SSM check), action summary generation,
    and upload to S3.
    """
    action = f"Log Collection for {instance_id}"
    print(f"\n{Fore.CYAN}--- Log Collection & Upload ---")
    print("This step attempts to collect CloudWatch logs potentially related to the instance")
    print("from the last 30 days and upload them to a dedicated S3 bucket.")
    print(Fore.YELLOW + "Note: System-level logs (e.g., /var/log/messages) are NOT automatically collected via SSM due to complexity and reliability issues. Check SSM Agent status below.")

    choice = input(f"Do you want to attempt log collection and upload? ({Fore.YELLOW}yes/no{Style.RESET_ALL}): ").lower().strip()
    if choice != 'yes':
        print_status(action, "skipped", "Log collection declined by user.")
        logging.info("Log collection skipped by user.")
        return

    print_status(action, "pending")
    logging.info(f"Starting log collection process for instance {instance_id}.")

    # --- Setup ---
    s3_client = session.client('s3')
    logs_client = session.client('logs')
    ssm_client = session.client('ssm')
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    # Sanitize instance ID for use in names
    safe_instance_id = instance_id.replace(':','-').replace('/','-')
    # Ensure account_id is available, fallback if needed (though should be present after validation)
    if not account_id:
        # Attempt to get account ID if not provided (should be available from validate_credentials)
        try:
            account_id = session.client('sts').get_caller_identity().get('Account', 'unknown-account')
            logging.warning(f"Account ID was not passed directly, retrieved as {account_id}")
        except Exception as sts_err:
             logging.error(f"Failed to retrieve account ID via STS for bucket naming: {sts_err}")
             account_id = "unknown-account" # Fallback

    # Use a shorter bucket name format: ir-logs-<account_id>-<timestamp>
    bucket_name = f"ir-logs-{account_id}-{timestamp}"
    # Ensure bucket name is compliant (lowercase, no underscores, 3-63 chars)
    bucket_name = bucket_name.lower().replace('_','-')[:63] # Basic sanitization and length check
    logging.info(f"Generated S3 bucket name: {bucket_name}")

    local_log_dir = f"ir_logs_{safe_instance_id}_{timestamp}"
    zip_filename = f"{local_log_dir}.zip"
    s3_key = f"{safe_instance_id}/{zip_filename}" # Keep instance ID in the S3 key path
    overall_success = True
    logs_collected = False

    try:
        # Create local directory for logs
        os.makedirs(local_log_dir, exist_ok=True)
        logging.info(f"Created local directory for logs: {local_log_dir}")

        # --- Create S3 Bucket ---
        # Note: SSM Agent check is now performed earlier in the main script
        if not _create_s3_bucket(s3_client, bucket_name, region):
            overall_success = False # Bucket creation is critical
            raise Exception("Failed to create or verify S3 bucket.") # Stop further processing

        # --- Get CloudWatch Logs ---
        end_time = datetime.now()
        start_time = end_time - timedelta(days=30)
        start_time_ms = int(start_time.timestamp() * 1000)
        end_time_ms = int(end_time.timestamp() * 1000)

        logs_collected = _get_cloudwatch_logs(logs_client, instance_id, start_time_ms, end_time_ms, local_log_dir)

        # --- Package Logs ---
        # --- Generate and Write Action Summary ---
        summary_file_path = os.path.join(local_log_dir, "action_summary.txt")
        summary_generated = False # Initialize flag
        logging.info(f"Attempting to generate action summary report at {summary_file_path}")
        try:
            with open(summary_file_path, 'w', encoding='utf-8') as f:
                f.write(f"Containment Action Summary for Instance: {instance_id}\n")
                f.write(f"Report Generated: {datetime.now().isoformat()}\n")
                f.write("="*40 + "\n")
                # Sort actions for consistent reporting (optional, requires action_summary to be passed)
                if action_summary:
                    for action_key in sorted(action_summary.keys()):
                        summary_item = action_summary[action_key]
                        f.write(f"Action: {action_key}\n")
                        f.write(f"  Status: {summary_item.get('status', 'Unknown')}\n")
                        details = summary_item.get('details')
                        if details: # Only write details if they exist
                             # Handle potential multi-line details nicely
                             details_str = str(details).replace('\n', '\n    ')
                             f.write(f"  Details: {details_str}\n")
                        f.write("-" * 20 + "\n")
                else:
                    f.write("Action summary data was not provided to the log collection function.\n")
            logging.info("Action summary report generated successfully.")
            summary_generated = True # Set flag on success
        except Exception as summary_err:
            logging.error(f"Failed to generate action summary report: {summary_err}", exc_info=True)
            print(Fore.YELLOW + f"Warning: Failed to generate action summary report: {summary_err}")
            # summary_generated remains False


        # --- Package Logs and Summary ---
        # Package if logs were collected OR if the summary was generated
        if logs_collected or summary_generated:
            print_status("Packaging Logs & Summary", "pending")
            logging.info(f"Packaging items from {local_log_dir} into {zip_filename}")
            try:
                with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
                    # Add action summary first if it exists
                    if summary_generated and os.path.exists(summary_file_path):
                         zipf.write(summary_file_path, arcname="action_summary.txt")
                         logging.info("Added action_summary.txt to zip archive.")
                    # Add collected logs
                    if logs_collected:
                        for root, _, files in os.walk(local_log_dir):
                            for file in files:
                                file_path = os.path.join(root, file)
                                # Avoid adding the summary file again if it's iterated here
                                if os.path.basename(file_path) != "action_summary.txt":
                                    # Add file to zip, using arcname to avoid full path in zip
                                    zipf.write(file_path, arcname=os.path.join(os.path.basename(root), file))
                print_status("Packaging Logs & Summary", "complete", f"Created {zip_filename}")
                logging.info(f"Successfully created log/summary archive {zip_filename}")

                # --- Upload to S3 ---
                print_status("Uploading Logs to S3", "pending")
                logging.info(f"Uploading {zip_filename} to s3://{bucket_name}/{s3_key}")
                try:
                    s3_client.upload_file(zip_filename, bucket_name, s3_key)
                    print_status("Uploading Logs to S3", "complete", f"Successfully uploaded to s3://{bucket_name}/{s3_key}")
                    logging.info(f"Successfully uploaded logs to s3://{bucket_name}/{s3_key}")
                except ClientError as e:
                    msg = f"Failed to upload logs to S3 (s3:PutObject permission?): {e}"
                    print_status("Uploading Logs to S3", "error", msg)
                    logging.error(msg, exc_info=True)
                    overall_success = False
                except Exception as e:
                    msg = f"Unexpected error uploading logs to S3: {e}"
                    print_status("Uploading Logs to S3", "error", msg)
                    logging.error(msg, exc_info=True)
                    overall_success = False

            except Exception as e:
                msg = f"Failed to package logs: {e}"
                print_status("Packaging Logs", "error", msg)
                logging.error(msg, exc_info=True)
                overall_success = False
        else:
            logging.info("Skipping packaging and upload as no CloudWatch logs were downloaded and action summary failed to generate.")
            print("  └── Skipping packaging and upload as no CloudWatch logs were downloaded and action summary failed.")


    except Exception as e:
        # Catch errors like makedirs failure or the exception from bucket creation
        logging.error(f"Error during log collection setup or main process: {e}", exc_info=True)
        overall_success = False

    finally:
        # --- Cleanup Local Files ---
        try:
            if os.path.exists(zip_filename):
                logging.info(f"Cleaning up local zip file: {zip_filename}")
                os.remove(zip_filename)
            if os.path.exists(local_log_dir):
                logging.info(f"Cleaning up local log directory: {local_log_dir}")
                # Remove downloaded log files first
                for item in os.listdir(local_log_dir):
                    item_path = os.path.join(local_log_dir, item)
                    if os.path.isfile(item_path):
                        os.remove(item_path)
                # Remove the directory itself
                os.rmdir(local_log_dir)
        except Exception as cleanup_err:
            logging.warning(f"Could not fully clean up local log files/directory: {cleanup_err}")
            print(Fore.YELLOW + f"Warning: Could not fully clean up local log files/directory: {cleanup_err}")

    # --- Final Status ---
    if overall_success and logs_collected:
        print_status(action, "complete", f"Log collection finished. Logs uploaded to s3://{bucket_name}/{s3_key}")
    elif overall_success and not logs_collected:
         print_status(action, "complete", "Log collection process finished, but no CloudWatch logs were found/downloaded to upload.")
    else:
        print_status(action, "error", f"Log collection process encountered errors. Check logs. Bucket '{bucket_name}' may contain partial/no data.")

    print(Fore.YELLOW + f"Reminder: Remember to analyze the logs in s3://{bucket_name}/{s3_key} and delete the bucket '{bucket_name}' when no longer needed.")
    logging.info(f"Log collection function finished. Bucket: {bucket_name}, Key: {s3_key}")
    print(Fore.RED + Style.BRIGHT + "  └── WARNING: Leaving a potentially compromised instance running poses security risks and may incur costs. It is strongly advised to stop the instance unless there's a specific reason not to.")