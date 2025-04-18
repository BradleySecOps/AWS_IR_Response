# Configuration constants for the AWS EC2 Instance Containment Script

# Name for the Network ACL created during containment
CONTAINMENT_NACL_NAME = "Containment-NACL-IncidentResponse"

# Name for the inline IAM policy used to revoke role sessions
DENY_POLICY_NAME = "DenyAllPolicyForIncidentResponse"