# AWS EC2 Instance Containment Script

**Author:** Bradley Carpenter
**Purpose:** To rapidly contain a potentially compromised EC2 instance within an AWS environment by isolating it, preserving evidence, and preventing further unauthorized actions.

**🛑 EXTREME CAUTION ADVISED 🛑**

**Disclaimer:** This script performs significant, potentially disruptive actions on your AWS environment, including modifying Network ACLs, Instance Attributes, IAM Roles, and Instance State. **It is intended SOLELY for use by experienced AWS practitioners and Incident Responders during active security incidents.**

*   **DO NOT run this script unless you are authorized, understand its full impact, and have tested it in a non-production environment.**
*   **Incorrect use can lead to loss of connectivity, data inaccessibility (if cleanup is improper), or interference with legitimate operations.**
*   **Always prioritize following your organization's established and tested Incident Response procedures.** This script should be considered a potential tool within that framework, not a replacement for it.
*   The author assumes **NO LIABILITY** for any damages or disruptions caused by the use or misuse of this script. **USE AT YOUR OWN RISK.**

## Containment Strategy & Steps

The script employs a multi-faceted strategy to contain a potentially compromised EC2 instance. It guides the user through the following automated steps:

1.  **Credential Input, Validation & Account Confirmation:**
    *   **Action:** Prompts for temporary AWS credentials. Uses `getpass` to hide sensitive input. Authenticates using `sts:GetCallerIdentity`, displays the AWS Account ID and attempts to display the Account Alias (`iam:ListAccountAliases`). **Crucially, it then prompts the user to confirm (`yes/no`) if the identified account is the correct target before proceeding.** Performs basic checks for essential EC2 and IAM read permissions.
    *   **Rationale:** Ensures the script authenticates correctly and targets the intended AWS account, preventing accidental actions in the wrong environment. Displaying the alias adds user-friendliness. Basic permission checks provide early feedback. Temporary credentials limit exposure.

2.  **Instance Identification:**
    *   **Action:** Lists running or stopped EC2 instances in the specified region (`ec2:DescribeInstances`). Prompts the user to select the target instance ID. Gathers essential details like VPC ID and Subnet ID from the selected instance's metadata.
    *   **Rationale:** Accurately identifies the instance to be contained based on user input. VPC and Subnet IDs are crucial for network isolation.

3.  **Pre-flight Checks:**
    *   **Action:** Before modifying resources, the script performs several non-mutating checks using `describe` or `list` API calls. It verifies the instance state, basic permissions for NACL changes, termination protection modification, IAM role policy listing, and EBS volume description.
    *   **Rationale:** This step aims to identify potential permission issues or problematic resource states *before* attempting irreversible actions, reducing the chance of mid-script failures. If critical checks fail, the script exits. If warnings are found, the user is prompted whether to continue.

4.  **Network Isolation (NACL Containment):**
    *   **Action:**
        *   Identifies the current Network ACL (NACL) associated with the instance's subnet (`ec2:DescribeNetworkAcls`).
        *   Creates a new, dedicated "Containment NACL" (or reuses one if it exists) tagged with a specific name (`ec2:CreateNetworkAcl`, `ec2:CreateTags`).
        *   Adds explicit DENY ALL rules for both Ingress (inbound) and Egress (outbound) traffic for **both IPv4 (`0.0.0.0/0`) and IPv6 (`::/0`)** to this Containment NACL (`ec2:CreateNetworkAclEntry`).
        *   Replaces the subnet's original NACL association with this new, restrictive Containment NACL (`ec2:ReplaceNetworkAclAssociation`).
    *   **Rationale:** This is the primary network containment step. By blocking all IPv4 and IPv6 traffic at the subnet level via the NACL, it prevents the instance from communicating with any other resource (internal or external), stopping potential command-and-control (C2) communication, data exfiltration, or lateral movement over the network.

5.  **Prevent Accidental Deletion (Termination Protection):**
    *   **Action:** Enables the "Termination Protection" attribute on the instance (`ec2:ModifyInstanceAttribute`).
    *   **Rationale:** Protects the instance (and its evidence) from being accidentally terminated through the AWS console or API during the investigation.

6.  **Situational Awareness (Information Gathering):**
    *   **Action:** Checks if the instance belongs to an Auto Scaling Group (`autoscaling:DescribeAutoScalingInstances`) or is registered with Load Balancers (Classic: `elasticloadbalancing:DescribeLoadBalancers`; ALB/NLB: `elasticloadbalancing:DescribeTargetGroups`, `elasticloadbalancing:DescribeTargetHealth`).
    *   **Rationale:** Provides context. If part of an ASG or behind an LB, containment actions (like stopping the instance or network isolation) might trigger health check failures, potentially leading the ASG/LB to replace the instance. This awareness helps anticipate such behavior.

7.  **IAM Role Assessment:**
    *   **Action:**
        *   Identifies the IAM Instance Profile attached to the instance (`ec2:DescribeInstances` data).
        *   Retrieves the actual underlying IAM Role name associated with the profile (`iam:GetInstanceProfile`).
        *   Checks the instance's metadata options to determine if IMDSv1 is enabled (`ec2:DescribeInstances` data).
        *   Lists other instances using the same Instance Profile ARN (`ec2:DescribeInstances` with filter).
        *   Lists the permissions (managed and inline policies) attached to the identified IAM Role (`iam:ListAttachedRolePolicies`, `iam:ListRolePolicies`).
    *   **Rationale:** Understanding the instance's IAM role is critical.
        *   Knowing the role name allows for targeted actions like session revocation.
        *   IMDSv1 check highlights the risk of credential theft if the instance was compromised.
        *   Finding other instances with the same role identifies potential blast radius or lateral movement if the role credentials were compromised.
        *   Listing permissions reveals what actions an attacker *could* have performed with the stolen credentials.

8.  **Revoke Active IAM Role Sessions:**
    *   **Action:** Prompts the user to attach (or overwrite) a DENY ALL inline policy to the identified IAM Role (`iam:PutRolePolicy`).
    *   **Rationale:** If the instance's IAM credentials were compromised (e.g., via IMDSv1), this step invalidates those credentials *immediately*. The DENY ALL policy prevents the stolen credentials from being used to perform any further actions in the AWS account, effectively stopping ongoing misuse of that specific role. This is a crucial step to prevent further damage.

9.  **Preserve Evidence (EBS Snapshots):**
    *   **Action:**
        *   Identifies EBS volumes attached to the instance (`ec2:DescribeInstances` data).
        *   Retrieves volume sizes (`ec2:DescribeVolumes`).
        *   Prompts the user to create snapshots of these volumes (`ec2:CreateSnapshot`, `ec2:CreateTags`).
        *   Waits for the snapshots to complete (`ec2:DescribeSnapshots`).
    *   **Rationale:** EBS snapshots create point-in-time copies of the instance's disks. These snapshots are essential for forensic analysis, allowing investigators to examine the filesystem, memory (if captured), and logs without altering the original (potentially still running or stopped) instance.

10. **Check SSM Agent Status:**
    *   **Action:** Checks the status of the SSM Agent on the target instance (`ssm:DescribeInstanceInformation`).
    *   **Rationale:** Provides context on whether SSM might be usable for later, more detailed investigation or remediation actions *before* the instance is stopped (which would likely sever SSM connectivity).

11. **Stop Instance Execution:**
    *   **Action:** Checks the current instance state (`ec2:DescribeInstanceStatus`). If running or pending, prompts the user to stop the instance (`ec2:StopInstances`). Waits for the instance to reach the 'stopped' state.
    *   **Rationale:** Stopping the instance halts all processes running on it, preventing any further malicious activity originating *from* the instance (like C2 callbacks, data processing, attacks on other systems). It also helps reduce costs if the instance was compromised for resource abuse (e.g., crypto mining).

12. **Log Collection & Upload (Optional):**
    *   **Action:** Prompts the user whether to attempt log collection. If confirmed:
        *   Creates a uniquely named S3 bucket (`s3:CreateBucket`, `s3:HeadBucket`).
        *   Searches for potentially relevant CloudWatch Log groups based on instance ID and common paths (`logs:DescribeLogGroups`).
        *   Downloads log events from the last 30 days from found groups (`logs:FilterLogEvents`).
        *   Generates an `action_summary.txt` file detailing the steps taken/skipped/failed by the script during its execution.
        *   Packages downloaded logs and the action summary into a `.zip` archive locally.
        *   Uploads the zip archive to the created S3 bucket (`s3:PutObject`).
        *   Cleans up local log files, summary file, and zip archive.
    *   **Rationale:** Provides a best-effort automated way to gather potentially relevant CloudWatch logs and a summary of the script's actions, centralizing them in S3 for easier analysis and auditing.

## Project Structure

The project is organized into the following directories:

*   `src/`: Contains the core Python source code for the containment script.
    *   `containment_script.py`: Main script entry point.
    *   `aws_interactions.py`: Functions for AWS API calls.
    *   `helpers.py`: UI and utility functions.
    *   `config.py`: Configuration constants.
    *   `__init__.py`: Makes `src` a Python package.
*   `terraform/`: Contains Terraform code (`main.tf`) to provision a basic test environment (VPC, Subnet, EC2 instance with Role).
*   `docs/`: Contains documentation files.
    *   `script_flowchart.md`: Mermaid flowchart of the script logic.
    *   `test_plan.docx`: Test plan document (Word format).
    *   `test_plan.txt`: Test plan document (Plain text format).
*   `examples/`: Contains example output files.
    *   `example_action_summary.txt`: Sample action summary report.
    *   `example_output.log`: Sample execution log file.
*   `README.md`: This file.
*   `requirements.txt`: Python dependencies.
*   `.gitignore`: Specifies intentionally untracked files for Git.

## Configuration

The following constants can be adjusted in `config.py`:

*   `CONTAINMENT_NACL_NAME`: The name assigned to the Network ACL created for containment. Default: `"Containment-NACL-IncidentResponse"`
*   `DENY_POLICY_NAME`: The name assigned to the inline IAM policy used to revoke role sessions. Default: `"DenyAllPolicyForIncidentResponse"`

## Required AWS Permissions & Rationale

The script requires credentials with sufficient permissions to perform its tasks. Below is a breakdown of the necessary permissions and why they are needed:

*   **`sts:GetCallerIdentity`**:
    *   **Why:** To verify that the provided credentials are valid and to display the identity being used.
*   **EC2 Permissions:**
    *   `ec2:DescribeInstances`: **Why:** To list instances for selection, get instance details (VPC, subnet, IAM profile, metadata options), and find other instances with the same role.
    *   `ec2:DescribeInstanceStatus`: **Why:** To check if the instance is already stopped before attempting to stop it again.
    *   `ec2:DescribeNetworkAcls`: **Why:** To find the original NACL of the subnet and check if the containment NACL already exists.
    *   `ec2:CreateNetworkAcl`: **Why:** To create the dedicated containment NACL if it doesn't exist.
    *   `ec2:CreateNetworkAclEntry`: **Why:** To add the DENY ALL ingress and egress rules to the containment NACL.
    *   `ec2:ReplaceNetworkAclAssociation`: **Why:** To associate the containment NACL with the instance's subnet, replacing the original one.
    *   `ec2:ModifyInstanceAttribute`: **Why:** To enable termination protection on the instance.
    *   `ec2:DescribeVolumes`: **Why:** To get the size of attached EBS volumes before snapshotting.
    *   `ec2:CreateSnapshot`: **Why:** To create the EBS snapshots for forensic evidence.
    *   `ec2:DescribeSnapshots`: **Why:** To monitor the status of snapshot creation and wait for completion.
    *   `ec2:StopInstances`: **Why:** To stop the execution of the compromised instance.
    *   `ec2:CreateTags`: **Why:** To tag the created containment NACL and EBS snapshots for easier identification and cleanup.
*   **IAM Permissions:**
    *   `iam:ListAccountAliases`: **Why:** (Optional but Recommended) To retrieve and display the AWS Account Alias during the initial account confirmation step, making it easier for the user to verify the target account. The script can proceed without this permission but won't display the alias.
    *   `iam:ListRoles`: **Why:** Used in the initial credential validation check to verify basic IAM read access.
    *   `iam:GetInstanceProfile`: **Why:** To get details of the instance profile attached to the EC2 instance, specifically to find the name of the associated IAM Role.
    *   `iam:ListAttachedRolePolicies`: **Why:** To list the AWS managed policies attached to the identified IAM role.
    *   `iam:ListRolePolicies`: **Why:** To list the inline policies embedded within the identified IAM role.
    *   `iam:PutRolePolicy`: **Why:** To attach the DENY ALL inline policy to the identified IAM role, effectively revoking its active sessions.
*   **Auto Scaling Permissions:**
    *   `autoscaling:DescribeAutoScalingInstances`: **Why:** To check if the instance is managed by an Auto Scaling group.
*   **Elastic Load Balancing Permissions:**
    *   `elasticloadbalancing:DescribeLoadBalancers`: **Why:** To check if the instance is registered with Classic Load Balancers.
    *   `elasticloadbalancing:DescribeTargetGroups`: **Why:** To find Target Groups associated with Application/Network Load Balancers.
    *   `elasticloadbalancing:DescribeTargetHealth`: **Why:** To check if the instance is registered as a target in those Target Groups.
*   **CloudWatch Logs Permissions (for optional log collection):**
    *   `logs:DescribeLogGroups`: **Why:** To search for log groups potentially related to the instance.
    *   `logs:FilterLogEvents`: **Why:** To download log events from the identified groups within the specified time range.
*   **S3 Permissions (for optional log collection):**
    *   `s3:CreateBucket`: **Why:** To create a dedicated S3 bucket to store the collected logs.
    *   `s3:HeadBucket`: **Why:** To check if the uniquely named bucket already exists before attempting creation.
    *   `s3:PutObject`: **Why:** To upload the packaged log archive to the created S3 bucket.
*   **SSM Permissions (for optional log collection - status check only):**
    *   `ssm:DescribeInstanceInformation`: **Why:** To check the status of the SSM Agent on the instance, providing context on whether manual system log retrieval via SSM might be feasible later.

**Note:** This list is based on the script's functionality. Depending on your environment's specific configuration (e.g., KMS encryption on volumes, complex tagging requirements), additional permissions might be necessary. **It is strongly recommended to use temporary credentials with the least privilege required.**

### Example IAM Policy for Assumed Role

For enhanced security, instead of using IAM user credentials directly, it's recommended to create a dedicated IAM Role that users can assume when they need to run this script. This role should have a trust policy allowing specific users or groups to assume it. Attach the following IAM policy (or a customized version based on your needs and the optional features you intend to use) to that role.

**Important:**
*   Review these permissions carefully and remove any that are not strictly necessary for your use case (e.g., if you never use the log collection feature, remove the `logs:`, `s3:`, and `ssm:` permissions).
*   Consider adding resource constraints (e.g., limiting `s3:CreateBucket` or `iam:PutRolePolicy` to specific resource ARNs or paths) if possible within your operational context, although this can be complex for a generic containment script.
*   This policy grants significant permissions. Restrict who can assume the role that uses this policy very carefully.

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "CoreValidation",
            "Effect": "Allow",
            "Action": [
                "sts:GetCallerIdentity",
                "iam:ListAccountAliases",
                "iam:ListRoles"
            ],
            "Resource": "*"
        },
        {
            "Sid": "EC2ContainmentActions",
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeInstances",
                "ec2:DescribeInstanceStatus",
                "ec2:DescribeNetworkAcls",
                "ec2:CreateNetworkAcl",
                "ec2:CreateNetworkAclEntry",
                "ec2:ReplaceNetworkAclAssociation",
                "ec2:ModifyInstanceAttribute",
                "ec2:DescribeVolumes",
                "ec2:CreateSnapshot",
                "ec2:DescribeSnapshots",
                "ec2:StopInstances",
                "ec2:CreateTags"
            ],
            "Resource": "*"
        },
        {
            "Sid": "IAMRoleActions",
            "Effect": "Allow",
            "Action": [
                "iam:GetInstanceProfile",
                "iam:ListAttachedRolePolicies",
                "iam:ListRolePolicies",
                "iam:PutRolePolicy"
            ],
            "Resource": "*"
        },
        {
            "Sid": "ASGELBInfoGathering",
            "Effect": "Allow",
            "Action": [
                "autoscaling:DescribeAutoScalingInstances",
                "elasticloadbalancing:DescribeLoadBalancers",
                "elasticloadbalancing:DescribeTargetGroups",
                "elasticloadbalancing:DescribeTargetHealth"
            ],
            "Resource": "*"
        },
        {
            "Sid": "OptionalLogCollection",
            "Effect": "Allow",
            "Action": [
                "logs:DescribeLogGroups",
                "logs:FilterLogEvents",
                "s3:CreateBucket",
                "s3:HeadBucket",
                "s3:PutObject",
                "ssm:DescribeInstanceInformation"
            ],
            "Resource": "*"
        }
    ]
}
```

## Prerequisites

Before running the script, ensure you have the following:

1.  **Python 3:** Installed on the machine where you will run the script.
2.  **Python Libraries:** Install required libraries using pip and the `requirements.txt` file:
    ```bash
    pip install -r requirements.txt
    ```
    (This installs `boto3` and `colorama`).
3.  **AWS Credentials:** Temporary AWS access keys (Access Key ID, Secret Access Key, Session Token) with the permissions listed in the "Required AWS Permissions" section. **Do not use long-term IAM user credentials.** Obtain temporary credentials via mechanisms like IAM Roles, AWS SSO, or `sts:AssumeRole`.
4.  **Authorization & Understanding:** Explicit authorization to perform containment actions in the target AWS account and a thorough understanding of the script's actions and potential impact.

## How to Use the Script (Direct Execution)

Follow these steps to run the containment script directly against an existing EC2 instance:

1.  **Navigate to Project Root:** Open your terminal or command prompt and change to the **root directory** of this project (the directory containing the `src/`, `terraform/`, etc. folders).
2.  **(Optional but Recommended) Activate Virtual Environment:** If you use Python virtual environments:
    ```bash
    # Example Activation (Windows cmd.exe)
    # venv\Scripts\activate.bat
    # Example Activation (Bash/Zsh/PowerShell)
    # source venv/bin/activate
    ```
3.  **Run the Script:** Execute the script as a Python module from the project root directory:
    ```bash
    python -m src.containment_script
    ```
    *(A log file named `containment_script_YYYYMMDD_HHMMSS.log` will be created in the project root directory)*
4.  **Enter Credentials:** The script will prompt you for your temporary AWS Access Key ID, Secret Access Key, Session Token, and the target AWS Region. Input is hidden for secrets.
5.  **Confirm Account:** After successful authentication, the script will display the AWS Account ID and Alias (if permissions allow) and ask you to confirm (`yes/no`) that this is the correct account you intend to operate in. **This is a critical safety check.**
6.  **Select Instance:** If the account is confirmed, the script lists running/stopped instances. Enter the full Instance ID (e.g., `i-012345abcdef`) of the target instance.
7.  **Pre-flight Check:** The script runs checks for permissions and resource states. If critical issues are found, it exits. If warnings are found, it prompts whether to continue.
8.  **Confirm Actions:** If pre-flight checks pass (or warnings are accepted), the script proceeds through containment steps, asking for confirmation (`yes/no`) before critical actions like:
    *   Applying the DENY ALL policy to revoke IAM Role sessions.
    *   Creating EBS snapshots.
    *   Stopping the EC2 instance.
    Read the prompts carefully and type `yes` to confirm or `no` to skip a specific action.
9.  **Confirm Log Collection (Optional):** The script will ask if you want to attempt to collect CloudWatch logs and upload them to a new S3 bucket.
10. **Review Output & Log File:** Once the script finishes, review the entire console output log *and* the generated `.log` file to understand which actions were completed successfully, skipped, or encountered errors. If log collection was performed, note the S3 bucket name provided.

## Optional: Setting up a Test Environment with Terraform

If you want to test the script in a controlled environment without using existing instances, a basic Terraform configuration is provided in the `terraform/` directory.

**What the Terraform Code Deploys:**

*   A new **VPC** with a public subnet.
*   An **Internet Gateway** and **Route Table** for basic internet connectivity to the subnet.
*   A **Security Group** allowing inbound SSH (port 22) from anywhere (0.0.0.0/0) - **Note:** This is for testing convenience; restrict this in production.
*   An **IAM Role** (`test-containment-instance-role`) for the EC2 instance with a basic trust policy allowing EC2 to assume it.
*   An **IAM Instance Profile** (`test-containment-instance-profile`) linking the role to EC2.
*   An **EC2 Instance** (using a recent Amazon Linux 2 AMI) launched into the public subnet, associated with the created Security Group and Instance Profile.

**Terraform Setup Steps:**

1.  **Install Terraform:** Follow instructions at [https://learn.hashicorp.com/tutorials/terraform/install-cli](https://learn.hashicorp.com/tutorials/terraform/install-cli).
2.  **Configure AWS Credentials for Terraform:** Use environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, etc.) or other standard methods. Ensure these credentials have permissions to create the resources listed above (VPC, Subnet, IGW, Route Table, Security Group, IAM Role/Profile, EC2 Instance).
3.  **Navigate to Terraform Directory:**
    ```bash
    cd terraform
    ```
4.  **Initialize Terraform:**
    ```bash
    terraform init
    ```
5.  **(Optional) Review Plan:**
    ```bash
    terraform plan
    ```
6.  **Apply Configuration:**
    ```bash
    terraform apply
    ```
    Type `yes` when prompted. Note the `instance_id` output by Terraform - you will use this ID when running the Python containment script.
7.  **Run the Python Script:** Follow the steps in the "How to Use the Script (Direct Execution)" section above, using the `instance_id` provided by Terraform when prompted.
8.  **DESTROY Test Environment:** After testing, **it is crucial to destroy the Terraform resources** to avoid costs:
    ```bash
    terraform destroy
    ```
    Type `yes` when prompted.

## Limitations & Known Issues

*   **Multi-ENI Instances:** The script primarily focuses on the subnet associated with the instance's primary network interface (as reported by `DescribeInstances`). If the instance has multiple Elastic Network Interfaces (ENIs) in different subnets, network containment will only be applied to the identified subnet, leaving other interfaces potentially active. Manual NACL changes would be needed for other subnets.
*   **Specialized Access Methods:** Applying the strict NACL might block legitimate forensic access methods like SSM Session Manager or EC2 Instance Connect if they rely on network paths now denied by the NACL. Consider your forensic access strategy beforehand.
*   **Resource-Based Policies:** Revoking IAM role sessions (Step 7) only affects identity-based permissions. It does *not* prevent access granted to the role ARN via resource-based policies (e.g., S3 bucket policies).
*   **KMS Permissions:** If target EBS volumes are encrypted with customer-managed KMS keys, the credentials running the script might need additional `kms:CreateGrant`, `kms:DescribeKey`, etc., permissions to successfully create snapshots.
*   **Spot Instances:** Attempting to stop a Spot instance may result in its termination, depending on its interruption behavior configuration. The script does not explicitly check for Spot instance types.
*   **Error Handling & State:** While basic error handling exists, complex AWS state issues or API throttling might cause script failure. The script does not have built-in rollback capabilities; manual cleanup is required if it exits unexpectedly mid-process.
*   **Resource Limits:** Actions might fail if AWS account limits are reached (e.g., max snapshots, max inline policies).

## Troubleshooting

*   **Permission Errors (`AccessDenied`, `UnauthorizedOperation`):** Ensure the temporary credentials used have *all* the permissions listed under "Required AWS Permissions". Check CloudTrail logs for the specific API call that failed.
*   **Resource State Errors (`IncorrectInstanceState`, `InvalidVolume.NotFound`):** The target resource might not be in a state compatible with the action (e.g., trying to stop an already stopped instance, snapshotting a volume that was just deleted). Check the AWS console for the resource's current status.
*   **Throttling Errors:** If you encounter throttling exceptions, you may need to wait and retry, or request service limit increases if performing actions at scale (though this script targets single instances).
*   **Timeout Errors (Waiters):** Waiters for snapshot completion or instance stopping might time out if the operation takes longer than expected. The operation might still complete successfully in AWS. Verify the status in the AWS console. Check the generated `.log` file for detailed error messages.

## Important Cleanup Steps (Manual)

After the incident is resolved and forensic analysis is complete, **manual cleanup is essential**:

1.  **Restore Original NACL:**
    *   Identify the original NACL ID and the *new* association ID created by the script (logged in the script output/log file).
    *   Use the AWS Console or CLI (`aws ec2 replace-network-acl-association --association-id <new_association_id> --network-acl-id <original_nacl_id>`) to re-associate the original NACL with the subnet.
    *   Optionally, delete the `Containment-NACL-IncidentResponse` NACL itself if no longer needed (`aws ec2 delete-network-acl --network-acl-id <containment_nacl_id>`).
2.  **Remove Deny Policy from Role:**
    *   If role sessions were revoked, navigate to the affected IAM Role in the AWS Console.
    *   Find and delete the inline policy named `DenyAllPolicyForIncidentResponse` (or your custom name) to restore the role's original permissions.
3.  **Disable Termination Protection:**
    *   If the instance needs to be terminated, disable termination protection via the EC2 console or CLI (`aws ec2 modify-instance-attribute --instance-id <instance_id> --no-disable-api-termination`).
4.  **Review/Delete Snapshots:** Manage or delete the created EBS snapshots according to your organization's data retention and incident handling policies.
5.  **Review/Delete Log Bucket:** If log collection was performed, review the logs in the generated S3 bucket (name logged in output). Delete the bucket and its contents when no longer needed.

**Always prioritize following your organization's specific incident response and cleanup procedures.**

## License

```
MIT License

Copyright (c) 2025 Bradley Carpenter

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.