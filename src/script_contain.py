#!/usr/bin/env python3

import boto3
import sys
import time
import getpass
from datetime import datetime
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError, WaiterError
from colorama import init, Fore, Style

# Initialize colorama for cross-platform colored text
init(autoreset=True)

# --- Configuration ---
CONTAINMENT_NACL_NAME = "Containment-NACL-IncidentResponse"
DENY_POLICY_NAME = "DenyAllPolicyForIncidentResponse" # Inline policy name for role session revocation

# --- Helper Functions ---
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

def print_status(action, status, error_message=None):
    """Prints a formatted status line."""
    if status == "pending":
        print(f"{action}: " + Fore.YELLOW + "PENDING...")
    elif status == "complete":
        print(f"{action}: " + Fore.GREEN + "COMPLETE")
    elif status == "error":
        print(f"{action}: " + Fore.RED + "ERROR")
        if error_message:
            print(Fore.RED + f"  └── Error Details: {error_message}")
    elif status == "skipped":
         print(f"{action}: " + Fore.BLUE + "SKIPPED")
    elif status == "info":
        print(f"{action}: " + Fore.BLUE + f"INFO - {error_message}") # Reusing error_message for info text
    elif status == "warning":
        print(f"{action}: " + Fore.YELLOW + f"WARNING - {error_message}") # Reusing error_message for warning text

def get_aws_credentials():
    """Prompts user for temporary AWS credentials."""
    print(Fore.CYAN + "\n--- AWS Credentials ---")
    print("Please enter your temporary AWS credentials.")
    aws_access_key_id = input("AWS Access Key ID: ").strip()
    aws_secret_access_key = getpass.getpass("AWS Secret Access Key: ").strip() # Use getpass for secret
    aws_session_token = getpass.getpass("AWS Session Token (leave blank if none): ").strip()
    region_name = input("AWS Region (e.g., us-east-1): ").strip()

    if not all([aws_access_key_id, aws_secret_access_key, region_name]):
        print(Fore.RED + "Error: Access Key ID, Secret Access Key, and Region cannot be empty.")
        sys.exit(1)

    if not aws_session_token:
        aws_session_token = None # Handle case where session token is not needed/provided

    return aws_access_key_id, aws_secret_access_key, aws_session_token, region_name

def validate_credentials(session):
    """Checks basic credential validity and some key permissions."""
    action = "Validating Credentials"
    print_status(action, "pending")
    missing_permissions = []
    try:
        sts_client = session.client('sts')
        caller_id = sts_client.get_caller_identity()
        print(Fore.GREEN + f"  └── Successfully authenticated as: {caller_id['Arn']}")

        # Basic Permission Check (Not exhaustive, but checks common read actions)
        iam_client = session.client('iam')
        ec2_client = session.client('ec2')
        try:
            ec2_client.describe_instances(MaxResults=5) # Check EC2 read
        except ClientError as e:
            if e.response['Error']['Code'] == 'UnauthorizedOperation':
                missing_permissions.append("ec2:DescribeInstances")
            # Handle specific validation error for MaxResults if needed, though less common here
            elif 'Unknown parameter' in str(e) and 'MaxResults' in str(e):
                 print(Fore.YELLOW + "Warning: Boto3 version might have slight variations in DescribeInstances pagination parameters. Continuing...")
            else:
                # Let other unexpected ClientErrors propagate if not handled specifically
                print(Fore.YELLOW + f"Warning during EC2 check: {e}")


        try:
            # *** CORRECTED PARAMETER NAME HERE ***
            iam_client.list_roles(MaxItems=1) # Check IAM read (Use MaxItems)
        except ClientError as e:
             if e.response['Error']['Code'] == 'UnauthorizedOperation':
                 missing_permissions.append("iam:ListRoles (or similar read permissions)")
             else:
                 # Let other unexpected ClientErrors propagate
                 print(Fore.YELLOW + f"Warning during IAM check: {e}")


        if not missing_permissions:
            print_status(action, "complete")
            return True, None
        else:
            error_msg = f"Missing required permissions: {', '.join(missing_permissions)}. Full functionality may be limited."
            print_status(action,"warning", error_msg) # Changed from error to warning
            # Decide if you want to exit or continue with limited functionality
            cont = input("Continue anyway? (y/n): ").lower()
            if cont != 'y':
                 sys.exit(1)
            return False, missing_permissions # Indicate partial success but continuing

    except (NoCredentialsError, PartialCredentialsError):
        print_status(action, "error", "AWS credentials not found or incomplete.")
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
    """Lists running or stopped EC2 instances."""
    action = "Listing EC2 Instances"
    print_status(action, "pending")
    instances_map = {}
    try:
        paginator = ec2_client.get_paginator('describe_instances')
        pages = paginator.paginate(Filters=[{'Name': 'instance-state-name', 'Values': ['running', 'stopped']}])

        print("\nAvailable EC2 Instances (Running or Stopped):")
        print("-" * 40)
        count = 0
        for page in pages:
            for reservation in page.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    instance_id = instance['InstanceId']
                    instance_state = instance['State']['Name']
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
            print_status(action, "skipped")
            return None

        print("-" * 40)
        print_status(action, "complete")
        return instances_map
    except ClientError as e:
        print_status(action, "error", f"Failed to list EC2 instances: {e}")
        return None
    except Exception as e:
        print_status(action, "error", f"An unexpected error occurred listing instances: {e}")
        return None

def select_target_instance(instances_map):
    """Asks user to select the target instance."""
    if not instances_map:
        print(Fore.RED + "No instances available to select.")
        sys.exit(1)

    while True:
        target_id = input(f"\nEnter the Instance ID ({Fore.YELLOW}e.g., i-012345abcdef{Style.RESET_ALL}) to quarantine: ").strip()
        if target_id in instances_map:
            print(f"Selected instance: {target_id}")
            return target_id, instances_map[target_id]
        else:
            print(Fore.RED + "Invalid Instance ID. Please choose from the list above.")

def apply_nacl_containment(ec2_client, vpc_id, subnet_id, target_instance_id):
    """Creates and applies a deny-all NACL to the instance's subnet."""
    action = "Performing NACL Containment"
    print_status(action, "pending")
    original_nacl_association_id = None
    original_nacl_id = None

    try:
        # 1. Find the original NACL association for the subnet
        response = ec2_client.describe_network_acls(
            Filters=[{'Name': 'association.subnet-id', 'Values': [subnet_id]}]
        )
        if not response.get('NetworkAcls'):
            raise Exception(f"Could not find existing NACL for subnet {subnet_id}")

        original_nacl = response['NetworkAcls'][0]
        original_nacl_id = original_nacl['NetworkAclId']
        for assoc in original_nacl.get('Associations', []):
            if assoc.get('SubnetId') == subnet_id:
                original_nacl_association_id = assoc['NetworkAclAssociationId']
                break
        if not original_nacl_association_id:
             raise Exception(f"Could not find NACL association ID for subnet {subnet_id}")

        print(f"  └── Original NACL ID for subnet {subnet_id}: {original_nacl_id}")
        print(f"  └── Original NACL Association ID: {original_nacl_association_id}")


        # 2. Check if containment NACL already exists
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

            # 4. Add deny rules (ingress and egress)
            # Egress Deny Rule (Outbound)
            ec2_client.create_network_acl_entry(
                NetworkAclId=containment_nacl_id, RuleNumber=100, Protocol='-1', # All protocols
                RuleAction='deny', Egress=True, CidrBlock='0.0.0.0/0'          # All IPv4
            )
            print(f"  └── Added Egress DENY ALL rule to {containment_nacl_id}")
            # Ingress Deny Rule (Inbound)
            ec2_client.create_network_acl_entry(
                NetworkAclId=containment_nacl_id, RuleNumber=100, Protocol='-1', # All protocols
                RuleAction='deny', Egress=False, CidrBlock='0.0.0.0/0'         # All IPv4
            )
            print(f"  └── Added Ingress DENY ALL rule to {containment_nacl_id}")


        # 5. Associate the new 'Containment NACL' with the subnet
        print(f"  └── Associating {containment_nacl_id} with subnet {subnet_id} (replacing association {original_nacl_association_id})")
        replace_response = ec2_client.replace_network_acl_association(
            AssociationId=original_nacl_association_id,
            NetworkAclId=containment_nacl_id
        )
        new_association_id = replace_response['NewAssociationId']
        print(f"  └── New NACL Association ID: {new_association_id}")

        print_status(action, "complete")
        return True, original_nacl_id, original_nacl_association_id

    except ClientError as e:
        print_status(action, "error", f"Failed during NACL operations: {e}")
        return False, None, None
    except Exception as e:
         print_status(action, "error", f"An unexpected error occurred during NACL ops: {e}")
         return False, None, None

def enable_termination_protection(ec2_client, instance_id):
    """Enables termination protection on the instance."""
    action = "Enabling Termination Protection"
    print_status(action, "pending")
    try:
        ec2_client.modify_instance_attribute(
            InstanceId=instance_id,
            DisableApiTermination={'Value': True}
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
    action = "Checking Auto Scaling Group Membership"
    print_status(action, "pending")
    try:
        response = autoscaling_client.describe_auto_scaling_instances(InstanceIds=[instance_id])
        asg_instances = response.get('AutoScalingInstances', [])
        if asg_instances:
            asg_name = asg_instances[0]['AutoScalingGroupName']
            print_status(action,"info", f"Instance is part of Auto Scaling Group: {Fore.YELLOW}{asg_name}")
            print(Fore.YELLOW + "  └── WARNING: Auto Scaling might replace this instance if health checks fail due to containment.")
        else:
            print_status(action, "info", "Instance is NOT part of any Auto Scaling Group.")
    except ClientError as e:
        if e.response['Error']['Code'] == 'AccessDeniedException':
             print_status(action, "error", "Permission denied for describe-auto-scaling-instances.")
        elif e.response['Error']['Code'] == 'AccessDenied': # Handle general AccessDenied as well
             print_status(action, "error", "Permission denied checking ASG membership.")
        else:
             print_status(action, "error", f"Could not check ASG status: {e}")
    except Exception as e:
         print_status(action, "error", f"An unexpected error occurred checking ASG: {e}")

def check_load_balancers(elb_client, elbv2_client, instance_id):
    """Checks if the instance is registered with Classic Load Balancers or Application/Network Load Balancers."""
    action = "Checking Load Balancer Membership"
    print_status(action, "pending")
    found_lb = False

    # Check ELBv2 (ALB/NLB) Target Groups
    try:
        paginator_tg = elbv2_client.get_paginator('describe_target_groups')
        for page_tg in paginator_tg.paginate():
            for tg in page_tg.get('TargetGroups', []):
                tg_arn = tg['TargetGroupArn']
                try:
                    # Check target health for the specific instance
                    response_health = elbv2_client.describe_target_health(
                        TargetGroupArn=tg_arn,
                        Targets=[{'Id': instance_id}]
                    )
                    if response_health.get('TargetHealthDescriptions'):
                        # If the list is not empty, the instance is registered (regardless of health state)
                        lb_arns = tg.get('LoadBalancerArns', [])
                        lb_names = [arn.split('/')[-2] if '/' in arn else arn.split(':')[-1] for arn in lb_arns] # Extract LB names/identifiers
                        print_status(action, "info", f"Instance is registered with Target Group: {Fore.YELLOW}{tg['TargetGroupName']} ({tg_arn})")
                        if lb_names:
                            print(f"  └── Associated Load Balancer(s): {', '.join(lb_names)}")
                        print(Fore.YELLOW + "  └── WARNING: Load Balancer health checks may fail, potentially removing the instance from service.")
                        found_lb = True
                except ClientError as e:
                    if e.response['Error']['Code'] == 'TargetGroupNotFoundException':
                        continue # Ignore if TG deleted during pagination
                    elif e.response['Error']['Code'] == 'InvalidTargetException':
                        continue # Instance not registered with this TG
                    elif e.response['Error']['Code'] == 'AccessDeniedException':
                        print(Fore.YELLOW + f"  └── Permission denied for elbv2:DescribeTargetHealth on {tg_arn}.")
                        # Stop checking this TG, maybe try others
                    elif e.response['Error']['Code'] == 'AccessDenied': # Handle general AccessDenied as well
                         print(Fore.YELLOW + f"  └── Permission denied checking Target Group health on {tg_arn}.")
                    else:
                        print(Fore.YELLOW + f"  └── Could not check health for Target Group {tg_arn}: {e}")
    except ClientError as e:
        if e.response['Error']['Code'] == 'AccessDeniedException':
             print_status(action, "error", "Permission denied for elbv2:DescribeTargetGroups.")
        elif e.response['Error']['Code'] == 'AccessDenied':
             print_status(action, "error", "Permission denied listing Target Groups.")
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
                lb_instance_ids = [inst['InstanceId'] for inst in lb.get('Instances', [])]
                if instance_id in lb_instance_ids:
                     print_status(action, "info", f"Instance is registered with Classic Load Balancer: {Fore.YELLOW}{lb_name}")
                     print(Fore.YELLOW + "  └── WARNING: Load Balancer health checks may fail, potentially removing the instance from service.")
                     found_lb = True
    except ClientError as e:
        if e.response['Error']['Code'] == 'AccessDeniedException':
             print_status(action, "error", "Permission denied for elasticloadbalancing:DescribeLoadBalancers.")
        elif e.response['Error']['Code'] == 'AccessDenied':
            print_status(action, "error", "Permission denied listing Classic LBs.")
        elif e.response['Error']['Code'] != 'LoadBalancerNotFound': # Ignore if LB deleted during check
             print(Fore.YELLOW + f"  └── Could not list Classic Load Balancers: {e}")
    except Exception as e:
         print(Fore.YELLOW + f"  └── An unexpected error occurred checking Classic LBs: {e}")


    if not found_lb:
        print_status(action, "info", "Instance does not appear to be registered with any checked Load Balancers.")


# *** CORRECTED FUNCTION TO FIND ACTUAL ROLE NAME ***
def get_instance_role_info(ec2_client, iam_client, instance_details):
    """
    Gets the IAM Role name attached via an Instance Profile.
    Handles cases where Instance Profile name and Role name differ.
    Returns: tuple (actual_role_name, instance_profile_arn)
    """
    action = "Getting Attached IAM Role"
    print_status(action, "pending")
    instance_profile_details = instance_details.get('IamInstanceProfile')

    if not instance_profile_details or 'Arn' not in instance_profile_details:
        print_status(action, "info", "Instance does not have an IAM Instance Profile attached.")
        return None, None # Return None for both role_name and profile_arn

    instance_profile_arn = instance_profile_details['Arn']
    instance_profile_name = None
    actual_role_name = None

    # --- Extract Instance Profile Name from ARN ---
    try:
        # ARN format: arn:partition:service:region:account-id:resource-type/resource-id
        # Handle potential path differences if any
        if '/' in instance_profile_arn:
            instance_profile_name = instance_profile_arn.split('/')[-1]
        else: # Handle case where ARN might not have a path (less common for instance profiles)
            instance_profile_name = instance_profile_arn.split(':')[-1]
        print(f"  └── Found Instance Profile Name: {instance_profile_name}")
    except IndexError:
        print_status(action, "error", f"Could not parse Instance Profile name from ARN: {instance_profile_arn}")
        return None, instance_profile_arn # Return profile ARN even if name parsing failed

    if not instance_profile_name: # Check if parsing failed
         print_status(action, "error", f"Could not determine Instance Profile name from ARN: {instance_profile_arn}")
         return None, instance_profile_arn

    # --- Get Instance Profile details to find the actual Role Name ---
    try:
        profile_response = iam_client.get_instance_profile(InstanceProfileName=instance_profile_name)

        if profile_response and 'InstanceProfile' in profile_response and 'Roles' in profile_response['InstanceProfile'] and profile_response['InstanceProfile']['Roles']:
            # Assume the first role listed is the one we want
            actual_role_name = profile_response['InstanceProfile']['Roles'][0]['RoleName']
            print(f"  └── Found underlying IAM Role Name: {Fore.CYAN}{actual_role_name}")
            print_status(action, "complete") # Mark as complete since we found the role name
            # Return the ACTUAL role name and the profile ARN
            return actual_role_name, instance_profile_arn
        else:
            # This case means the profile exists but has no roles - unusual but possible
            print_status(action, "warning", f"Instance Profile '{instance_profile_name}' exists but contains no associated IAM Roles.")
            return None, instance_profile_arn # No role name found

    except ClientError as e:
        err_code = e.response.get("Error", {}).get("Code")
        if err_code == 'NoSuchEntity':
             print_status(action, "error", f"Could not find IAM Instance Profile details for '{instance_profile_name}'. The profile might not exist or permissions are missing for iam:GetInstanceProfile.")
        elif err_code == 'AccessDenied':
             print_status(action, "error", f"Permission denied for iam:GetInstanceProfile on profile '{instance_profile_name}'. Cannot determine actual Role name.")
        else:
            print_status(action, "error", f"Error calling iam:GetInstanceProfile for '{instance_profile_name}': {e}")
        return None, instance_profile_arn # Return profile ARN even on error finding role name
    except Exception as e:
         print_status(action, "error", f"An unexpected error occurred getting profile details: {e}")
         return None, instance_profile_arn

def check_imds_version(ec2_client, instance_details):
    """Checks if the instance uses IMDSv1 or IMDSv2."""
    action = "Checking IMDS Version"
    print_status(action, "pending")
    metadata_options = instance_details.get('MetadataOptions', {})
    http_tokens = metadata_options.get('HttpTokens')
    http_endpoint = metadata_options.get('HttpEndpoint')

    if http_endpoint == 'disabled':
        print_status(action, "info", "IMDS is disabled on this instance.")
    elif http_tokens == 'required':
        print_status(action, "info", f"Instance is configured to use IMDSv2 ({Fore.GREEN}HttpTokens=required{Style.RESET_ALL}).")
        print(Fore.GREEN + "  └── Thankfully not IMDSv1.")
    elif http_tokens == 'optional':
        print_status(action, "info", f"Instance is configured to allow IMDSv1 ({Fore.RED}HttpTokens=optional{Style.RESET_ALL}).")
        print(Fore.RED + Style.BRIGHT + "  └── CONCERN: ROLE COULD BE USED WITHIN ENVIRONMENT IF CREDENTIALS WERE STOLEN VIA IMDSv1. REVIEW ROLE ACTIVITY LOGS.")
    else:
         print_status(action, "info", f"Could not definitively determine IMDS version (HttpTokens={http_tokens}, HttpEndpoint={http_endpoint}). Review instance metadata options manually.")

def find_instances_with_same_role(ec2_client, profile_arn, excluded_instance_id):
    """Finds other instances using the same IAM instance profile."""
    action = "Finding Other Instances with Same Role Profile" # Clarified name
    print_status(action, "pending")
    if not profile_arn:
        print_status(action, "skipped", "No role profile ARN to check.")
        return []

    instances_with_role = []
    try:
        paginator = ec2_client.get_paginator('describe_instances')
        # Filter by the Instance Profile ARN
        pages = paginator.paginate(Filters=[{'Name': 'iam-instance-profile.arn', 'Values': [profile_arn]}])

        count = 0
        for page in pages:
            for reservation in page.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    instance_id = instance['InstanceId']
                    if instance_id != excluded_instance_id: # Don't list the target instance itself
                        # Check if instance is running or stopped
                        if instance.get('State', {}).get('Name') in ['running', 'stopped']:
                            instances_with_role.append(instance_id)
                            count += 1

        if instances_with_role:
             profile_name_display = profile_arn.split('/')[-1] if '/' in profile_arn else profile_arn
             print_status(action, "info", f"Found {count} other running/stopped instance(s) using the same profile ({profile_name_display}):")
             for iid in instances_with_role:
                 print(f"  - {iid}")
        else:
            print_status(action, "info", "No other running/stopped instances found using this instance profile.")

        return instances_with_role

    except ClientError as e:
        err_code = e.response.get("Error", {}).get("Code")
        if err_code == 'AccessDenied':
            print_status(action, "error", "Permission denied searching for instances by role profile ARN (ec2:DescribeInstances with filter).")
        elif 'InvalidFilter' in err_code:
            print_status(action, "error", f"Invalid filter used when searching instances by role profile ARN: {e}")
        else:
            print_status(action, "error", f"Could not search for instances by role profile ARN: {e}")
        return []
    except Exception as e:
         print_status(action, "error", f"An unexpected error occurred searching instances by role: {e}")
         return []

def get_role_permissions(iam_client, role_name):
    """Lists managed and inline policies attached to the role."""
    action = f"Getting Permissions for Role ({role_name})"
    print_status(action, "pending")
    if not role_name:
        print_status(action, "skipped", "No role name provided.")
        return

    try:
        print(f"  Permissions for role '{role_name}':")
        policy_found = False
        # Managed Policies
        try:
            attached_policies_paginator = iam_client.get_paginator('list_attached_role_policies')
            managed_policy_count = 0
            for page in attached_policies_paginator.paginate(RoleName=role_name):
                 if page.get('AttachedPolicies'):
                     if managed_policy_count == 0: print("  └── Managed Policies:")
                     for policy in page['AttachedPolicies']:
                         print(f"      - {policy['PolicyName']} ({policy['PolicyArn']})")
                         managed_policy_count += 1
                         policy_found = True
            if managed_policy_count == 0:
                print("  └── No attached managed policies found.")
        except ClientError as e:
             err_code = e.response.get("Error", {}).get("Code")
             if err_code == 'NoSuchEntity': # Should not happen if role_name is correct, but handle defensively
                  print(Fore.RED + f"      Error: Role '{role_name}' not found when listing managed policies.")
             elif err_code == 'AccessDenied':
                  print(Fore.RED + f"      Permission denied for iam:ListAttachedRolePolicies on role '{role_name}'.")
             else:
                  print(Fore.RED + f"      Error listing managed policies: {e}")


        # Inline Policies
        try:
            inline_policies_paginator = iam_client.get_paginator('list_role_policies')
            inline_policy_count = 0
            for page in inline_policies_paginator.paginate(RoleName=role_name):
                 if page.get('PolicyNames'):
                     if inline_policy_count == 0: print("  └── Inline Policies:")
                     for policy_name in page['PolicyNames']:
                          print(f"      - {policy_name}")
                          # Optionally get policy document: iam_client.get_role_policy(...)
                          inline_policy_count += 1
                          policy_found = True
            if inline_policy_count == 0:
                 print("  └── No inline policies found.")
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
            # If no policies found but no errors occurred either
            print_status(action, "info", f"No managed or inline policies listed for role '{role_name}'.")


    except Exception as e: # Catch unexpected errors during pagination or logic
         print_status(action, "error", f"An unexpected error occurred getting policies for role {role_name}: {e}")


def revoke_role_sessions(iam_client, role_name):
    """Applies a deny-all inline policy to effectively revoke active sessions."""
    action = f"Revoking Sessions for Role ({role_name})"

    if not role_name:
        print_status(action, "skipped", "No role to revoke sessions for.")
        return

    print(f"\n{Fore.YELLOW}--- Revoke IAM Role Sessions ---")
    print(f"This will attach an INLINE policy named '{DENY_POLICY_NAME}'")
    print(f"to the role '{Fore.CYAN}{role_name}{Style.RESET_ALL}', effectively preventing it from doing anything else.")
    print("This is a critical step if the role credentials might be compromised.")
    choice = input("Do you want to revoke sessions for this role? (yes/no): ").lower().strip()

    if choice == 'yes':
        print_status(action, "pending")
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
            # Use put_role_policy which creates or overwrites the inline policy
            iam_client.put_role_policy(
                RoleName=role_name,
                PolicyName=DENY_POLICY_NAME,
                PolicyDocument=deny_policy_doc
            )
            print_status(action, "complete", f"Applied '{DENY_POLICY_NAME}' deny policy to role '{role_name}'.")
        except ClientError as e:
            err_code = e.response.get("Error", {}).get("Code")
            if err_code == 'NoSuchEntity':
                 msg = f"Role '{role_name}' not found. Cannot apply deny policy."
            elif err_code == 'AccessDenied':
                 msg = f"Permission denied for iam:PutRolePolicy on role '{role_name}'."
            elif err_code == 'LimitExceeded':
                  msg = f"Cannot add inline policy '{DENY_POLICY_NAME}'. Role '{role_name}' may already have the maximum number of inline policies."
            elif err_code == 'MalformedPolicyDocument':
                 msg = f"The generated Deny All policy document is invalid (should not happen)."
            else:
                msg = f"Failed to apply deny policy to role {role_name}: {e}"
            print_status(action, "error", msg)
        except Exception as e:
            print_status(action, "error", f"An unexpected error occurred applying deny policy: {e}")

    else:
        print_status(action,"warning", f"Sessions NOT revoked for role {role_name}.")
        print(Fore.RED + Style.BRIGHT + "  └── WARNING: IT IS HIGHLY RECOMMENDED TO REVOKE SESSIONS IF COMPROMISE IS SUSPECTED.")

def get_ebs_volumes(instance_details):
    """Gets EBS volume information attached to the instance."""
    action = "Getting Attached EBS Volumes"
    print_status(action, "pending")
    volumes = []
    block_device_mappings = instance_details.get('BlockDeviceMappings', [])
    if not block_device_mappings:
        print_status(action, "info", "No block device mappings found for the instance.")
        return []

    print("  Attached EBS Volumes:")
    for mapping in block_device_mappings:
        if 'Ebs' in mapping and 'VolumeId' in mapping['Ebs']:
            volume_id = mapping['Ebs']['VolumeId']
            device_name = mapping.get('DeviceName', 'N/A')
            # Size will be fetched later
            volumes.append({'VolumeId': volume_id, 'DeviceName': device_name, 'SizeGB': None})
            print(f"  - Volume ID: {volume_id}, Device: {device_name}")
        else:
             # Handle cases where mapping might exist but not be EBS or lack VolumeId
             device_name = mapping.get('DeviceName', 'N/A')
             print(f"  - Non-EBS or incomplete mapping found for device: {device_name}")


    if not volumes:
        print_status(action, "info", "No EBS volumes identified in block device mappings.")
        return []
    else:
        print_status(action, "complete")
        return volumes


def describe_and_update_volume_sizes(ec2_client, volumes):
    """Updates volume list with sizes using describe_volumes."""
    if not volumes:
        return volumes # No volumes to describe

    action = "Getting EBS Volume Sizes"
    print_status(action, "pending")
    volume_ids = [v['VolumeId'] for v in volumes]
    updated_volumes = volumes[:] # Create a copy to modify

    try:
        response = ec2_client.describe_volumes(VolumeIds=volume_ids)
        size_map = {vol['VolumeId']: vol.get('Size') for vol in response.get('Volumes', [])}

        temp_volumes = []
        all_found = True
        for v in updated_volumes:
            vol_id = v['VolumeId']
            size_gb = size_map.get(vol_id)
            if size_gb is not None:
                 v['SizeGB'] = size_gb
            else:
                 v['SizeGB'] = 'Unknown'
                 all_found = False
                 print(Fore.YELLOW + f"  └── Warning: Could not determine size for volume {vol_id}")
            temp_volumes.append(v)

        updated_volumes = temp_volumes

        if all_found:
            print_status(action, "complete")
        else:
             print_status(action, "warning", "Could not determine size for all volumes.")

        print("  Volume sizes:")
        for v in updated_volumes:
             print(f"   - {v['VolumeId']} ({v['DeviceName']}): {v['SizeGB']} GB")

        return updated_volumes
    except ClientError as e:
        err_code = e.response.get("Error", {}).get("Code")
        if err_code == 'AccessDenied':
            msg = "Permission denied for ec2:DescribeVolumes. Sizes will be unknown."
        elif 'InvalidVolume.NotFound' in str(e):
             msg = "One or more specified volume IDs not found. Sizes may be incomplete."
        else:
            msg = f"Could not describe volumes to get sizes: {e}. Sizes will be unknown."
        print_status(action, "error", msg)
        # Return original volumes list without sizes populated
        for v in updated_volumes: v['SizeGB'] = 'Error'
        return updated_volumes # Return the list marked with error
    except Exception as e:
         print_status(action, "error", f"An unexpected error occurred getting volume sizes: {e}. Sizes will be unknown.")
         for v in updated_volumes: v['SizeGB'] = 'Error'
         return updated_volumes


def snapshot_ebs_volumes(ec2_client, volumes, instance_id):
    """Offers to snapshot EBS volumes and performs the action if requested."""
    action = "Snapshotting EBS Volumes"
    if not volumes:
        print_status(action, "skipped", "No EBS volumes attached to snapshot.")
        return

    # Filter out volumes where size couldn't be determined if needed, or proceed anyway
    valid_volumes = [v for v in volumes if v.get('VolumeId')]
    if not valid_volumes:
        print_status(action, "skipped", "No valid EBS volumes found to snapshot.")
        return


    print(f"\n{Fore.YELLOW}--- EBS Volume Snapshots ---")
    print("Snapshots are crucial for forensic analysis.")
    choice = input("Do you want to create snapshots of all attached EBS volumes? (yes/no): ").lower().strip()

    if choice == 'yes':
        print_status(action, "pending")
        snapshot_ids = []
        snapshot_details = {} # Store volume ID against snapshot ID for waiter
        snapshot_start_time = time.time()
        today_date = datetime.utcnow().strftime('%Y%m%d')
        created_count = 0

        try:
            for volume in valid_volumes:
                vol_id = volume['VolumeId']
                # Clean device name for description/tags - handle potential None or complex names
                device_name_raw = volume.get('DeviceName', 'unknown_device')
                device_name_cleaned = ''.join(c if c.isalnum() or c in ['-', '_'] else '_' for c in device_name_raw)

                description = f"Incident Response snapshot for instance {instance_id}, volume {vol_id}, device {device_name_raw}"
                # Ensure tag name is valid (max 256 chars, allowed chars)
                snapshot_tag_name_base = f"compromised-{instance_id}-{device_name_cleaned}-snapshot-{today_date}"
                snapshot_tag_name = snapshot_tag_name_base[:255] # Truncate if too long

                print(f"  └── Creating snapshot for {vol_id} (Device: {device_name_raw})...")
                try:
                    snap_response = ec2_client.create_snapshot(
                        VolumeId=vol_id,
                        Description=description,
                        TagSpecifications=[{
                            'ResourceType': 'snapshot',
                            'Tags': [
                                {'Key': 'Name', 'Value': snapshot_tag_name},
                                {'Key': 'IncidentResponseSourceInstance', 'Value': instance_id},
                                {'Key': 'SourceVolumeId', 'Value': vol_id}
                            ]
                        }]
                    )
                    snapshot_id = snap_response['SnapshotId']
                    snapshot_ids.append(snapshot_id)
                    snapshot_details[snapshot_id] = {'VolumeId': vol_id, 'Status': 'pending'}
                    print(f"      └── Snapshot initiated: {snapshot_id}")
                    created_count += 1
                except ClientError as snap_err:
                    print(Fore.RED + f"      └── Error creating snapshot for {vol_id}: {snap_err}")
                    # Continue to next volume

            # Wait for snapshots to complete if any were successfully initiated
            if snapshot_ids:
                print(f"\n  └── Waiting for {len(snapshot_ids)} snapshot(s) to complete... (This can take time depending on volume size)")
                waiter = ec2_client.get_waiter('snapshot_completed')
                all_completed_successfully = True # Track overall success
                try:
                    waiter.wait(
                        SnapshotIds=snapshot_ids,
                        WaiterConfig={
                            'Delay': 30,  # Check every 30 seconds
                            'MaxAttempts': 120 # Wait up to 60 minutes
                        }
                    )
                    # Verify final statuses as waiter only waits for terminal state (completed or error)
                    final_statuses = ec2_client.describe_snapshots(SnapshotIds=snapshot_ids)
                    for snap in final_statuses.get('Snapshots', []):
                        if snap['State'] == 'error':
                             print(Fore.RED + f"      └── Snapshot {snap['SnapshotId']} failed: {snap.get('StateMessage', 'Unknown error')}")
                             all_completed_successfully = False
                        elif snap['State'] == 'completed':
                              print(Fore.GREEN + f"      └── Snapshot {snap['SnapshotId']} completed.")
                        else: # Should ideally not happen if waiter finished
                             print(Fore.YELLOW + f"      └── Snapshot {snap['SnapshotId']} in unexpected final state: {snap['State']}")
                             all_completed_successfully = False # Treat unexpected as not fully complete

                    if all_completed_successfully:
                        snapshot_duration = time.time() - snapshot_start_time
                        print(f"  └── All initiated snapshots completed successfully in ~{snapshot_duration:.0f} seconds.")
                        print_status(action, "complete")
                    else:
                         print_status(action, "error", "One or more initiated snapshots did not complete successfully.")

                except WaiterError as wait_error: # Catch waiter timeout or API errors during wait
                     print_status(action, "error", f"Error or timeout waiting for snapshots (they might still be running or failed): {wait_error}")
                except ClientError as desc_err: # Catch error describing final statuses
                     print_status(action, "error", f"Could not describe final snapshot statuses: {desc_err}")

            elif created_count == 0:
                 print_status(action, "error", "No snapshots were successfully initiated.")
            # If snapshot_ids is empty but created_count > 0, means errors happened during creation loop

        except Exception as e: # Catch unexpected errors in the main loop
            print_status(action, "error", f"An unexpected error occurred during snapshotting process: {e}")

    else:
        print_status(action, "skipped", "Snapshot creation declined by user.")

def stop_instance(ec2_client, instance_id):
    """Offers to stop the EC2 instance."""
    action = "Stopping EC2 Instance"
    # Check current instance state first
    try:
        instance_status = ec2_client.describe_instance_status(InstanceIds=[instance_id], IncludeAllInstances=True)
        current_state = None
        if instance_status.get('InstanceStatuses'):
            current_state = instance_status['InstanceStatuses'][0]['InstanceState']['Name']

        if current_state == 'stopped':
            print(f"\n{Fore.BLUE}--- Stop EC2 Instance ---")
            print_status(action, "info", f"Instance {instance_id} is already stopped.")
            return # Skip asking if already stopped
        elif current_state == 'stopping':
            print(f"\n{Fore.BLUE}--- Stop EC2 Instance ---")
            print_status(action, "info", f"Instance {instance_id} is already stopping.")
            return # Skip asking if already stopping
        elif current_state not in ['running', 'pending']: # Should not happen if listed, but check
             print(f"\n{Fore.BLUE}--- Stop EC2 Instance ---")
             print_status(action, "warning", f"Instance {instance_id} is in state '{current_state}'. Skipping stop option.")
             return

    except ClientError as status_err:
         print(Fore.YELLOW + f"Warning: Could not get current instance status before prompting stop: {status_err}")
         # Proceed with asking anyway, stop call will fail if not running

    print(f"\n{Fore.YELLOW}--- Stop EC2 Instance ---")
    print("Stopping the instance prevents further malicious activity and reduces cost.")
    print(f"Instance {instance_id} will be STOPPED, not TERMINATED.")
    choice = input("Do you want to stop this instance now? (yes/no): ").lower().strip()

    if choice == 'yes':
        print_status(action, "pending")
        try:
            response = ec2_client.stop_instances(InstanceIds=[instance_id])
            # Check response structure for state changes
            if 'StoppingInstances' in response and response['StoppingInstances']:
                current_state_resp = response['StoppingInstances'][0].get('CurrentState', {}).get('Name', 'Unknown')
                previous_state_resp = response['StoppingInstances'][0].get('PreviousState', {}).get('Name', 'Unknown')
                print(f"  └── Stop request sent. Instance transitioning from {previous_state_resp} to {current_state_resp}.")
                # Optional: Add waiter for instance_stopped if confirmation is needed
                print(f"  └── Waiting for instance {instance_id} to reach stopped state...")
                waiter = ec2_client.get_waiter('instance_stopped')
                waiter.wait(InstanceIds=[instance_id], WaiterConfig={'Delay': 15, 'MaxAttempts': 40}) # Wait up to 10 mins
                print(Fore.GREEN + f"  └── Instance {instance_id} confirmed stopped.")
                print_status(action, "complete")
            else:
                 print_status(action, "warning", "StopInstances API call succeeded but response format unexpected.")

        except ClientError as e:
            err_code = e.response.get("Error", {}).get("Code")
            if 'IncorrectInstanceState' in err_code:
                 msg = f"Instance {instance_id} is not in a stoppable state (e.g., already stopped/stopping)."
            elif 'AccessDenied' in err_code:
                 msg = f"Permission denied for ec2:StopInstances on {instance_id}."
            else:
                msg = f"Failed to stop instance {instance_id}: {e}"
            print_status(action, "error", msg)
        except WaiterError as wait_err:
             print_status(action, "error", f"Instance stop initiated, but timed out or error waiting for confirmation: {wait_err}")
        except Exception as e:
            print_status(action, "error", f"An unexpected error occurred stopping instance: {e}")
    else:
        print_status(action,"warning", "Instance stop declined by user.")
        print(Fore.RED + Style.BRIGHT + "  └── WARNING: If this instance was compromised (e.g., crypto miner), it could be incurring significant costs while running. It is highly advised to stop the instance soon.")


# --- Main Execution ---
def main():
    print_header()

    # 1. Get Credentials
    access_key, secret_key, session_token, region = get_aws_credentials()

    # 2. Create Boto3 Session & Clients
    try:
        session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            aws_session_token=session_token,
            region_name=region
        )
        # Initialize clients needed
        ec2 = session.client('ec2')
        iam = session.client('iam') # Needed for role lookup
        autoscaling = session.client('autoscaling')
        elb = session.client('elb') # Classic ELB
        elbv2 = session.client('elbv2') # ALB/NLB

    except Exception as e:
        print(Fore.RED + f"Failed to create Boto3 session: {e}")
        sys.exit(1)

    # 3. Validate Credentials (Basic Check)
    validated, missing_perms = validate_credentials(session)
    # Script continues even if validation has missing perms, but warns user

    print("\n" + Fore.CYAN + "--- Starting Containment Process ---")

    # 4. List Instances
    instances = list_ec2_instances(ec2)
    if not instances:
        print(Fore.YELLOW + "Exiting as no instances were found.")
        sys.exit(0)

    # 5. Select Target Instance
    target_instance_id, target_instance_details = select_target_instance(instances)
    vpc_id = target_instance_details.get('VpcId')
    subnet_id = target_instance_details.get('SubnetId')

    if not vpc_id or not subnet_id:
        print(Fore.RED + f"Error: Could not determine VPC ID ({vpc_id}) or Subnet ID ({subnet_id}) for instance {target_instance_id}.")
        sys.exit(1)

    print(f"\nTargeting Instance: {Fore.YELLOW}{target_instance_id}{Style.RESET_ALL} in VPC: {vpc_id}, Subnet: {subnet_id}")
    print("-" * 70)


    # --- Containment and Information Gathering ---

    # 6. Apply NACL Containment
    nacl_success, _, _ = apply_nacl_containment(ec2, vpc_id, subnet_id, target_instance_id)
    # We don't exit on NACL failure, maybe user wants other steps

    # 7. Enable Termination Protection
    enable_termination_protection(ec2, target_instance_id)

    # 8. Check Auto Scaling Groups
    check_autoscaling_groups(autoscaling, target_instance_id)

    # 9. Check Load Balancers
    check_load_balancers(elb, elbv2, target_instance_id)

    # 10. Get IAM Role Name and Profile ARN
    # *** Pass the iam client here ***
    instance_role_name, instance_profile_arn = get_instance_role_info(ec2, iam, target_instance_details)

    # 11. Check IMDS Version
    check_imds_version(ec2, target_instance_details)

    # --- Role Specific Actions (if actual role name was found) ---
    if instance_role_name: # Check if we successfully got the *actual* role name
        # 12. Find Other Instances with Same Role Profile
        # Note: This step correctly uses the *profile ARN* for searching instances.
        find_instances_with_same_role(ec2, instance_profile_arn, target_instance_id)

        # 13. Get Role Permissions (Uses the actual role name)
        get_role_permissions(iam, instance_role_name)

        # 14. Offer to Revoke Role Sessions (Uses the actual role name)
        revoke_role_sessions(iam, instance_role_name)
    else:
        # This executes if get_instance_role_info returned None for the role_name
        print("\n" + Fore.BLUE + "Skipping IAM role permission/revocation checks as the specific IAM Role name could not be determined.")


    # --- EBS Volume Actions ---
    print("\n" + Fore.CYAN + "--- EBS Volume Analysis ---")
    # 15. Get EBS Volume Info
    attached_volumes = get_ebs_volumes(target_instance_details)

    # 15b. Get EBS Volume Sizes (Requires describe_volumes)
    attached_volumes_with_size = describe_and_update_volume_sizes(ec2, attached_volumes)


    # 16. Offer to Snapshot Volumes
    snapshot_ebs_volumes(ec2, attached_volumes_with_size, target_instance_id)


    # --- Final Action ---
    # 17. Offer to Stop the Instance
    stop_instance(ec2, target_instance_id)


    print("\n" + Fore.CYAN + Style.BRIGHT + "=" * 70)
    print(Fore.CYAN + Style.BRIGHT + "=== Containment Script Finished ===")
    print(f"Review the output above for status of actions on instance {target_instance_id}.")
    print(Fore.YELLOW + "Remember to follow your organization's Incident Response procedures for further analysis and remediation.")
    print(Fore.YELLOW + "Cleanup Reminder: Manually review/delete the created NACL ({CONTAINMENT_NACL_NAME}) and the Deny policy ({DENY_POLICY_NAME}) if applied to the role, once remediation is complete.".format(
        CONTAINMENT_NACL_NAME=CONTAINMENT_NACL_NAME, DENY_POLICY_NAME=DENY_POLICY_NAME
    ))
    print(Fore.CYAN + Style.BRIGHT + "=" * 70)


if __name__ == "__main__":
    main()