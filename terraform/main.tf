# --- Provider Configuration ---
# Configure the AWS Provider.
# It's recommended to configure your AWS credentials using environment variables
# (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN [optional])
# or an AWS credentials file (~/.aws/credentials).
provider "aws" {
  region = var.aws_region # Specify the desired AWS region
}

# --- Variables ---
variable "aws_region" {
  description = "The AWS region to deploy resources in."
  type        = string
  default     = "us-east-1" # Change this to your preferred region if needed
}

variable "instance_type" {
  description = "The EC2 instance type to use."
  type        = string
  default     = "t3.micro" # A cost-effective, general-purpose instance type
}

# --- Data Sources ---
# Get the default VPC in the specified region.
data "aws_vpc" "default" {
  default = true
}

# Get all availability zones in the region.
data "aws_availability_zones" "available" {}

# Get a list of default subnets in the default VPC.
data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
  filter {
    name   = "default-for-az"
    values = ["true"]
  }
}

# Find the latest Amazon Linux 2 AMI.
data "aws_ami" "amazon_linux_2" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# --- IAM Role and Policy ---
# Create an IAM role that EC2 instances can assume.
resource "aws_iam_role" "instance_role" {
  name = "test-containment-instance-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })

  tags = {
    Purpose = "Testing EC2 Containment Script"
  }
}

# Attach a read-only S3 policy to the role for testing purposes.
resource "aws_iam_role_policy_attachment" "s3_read_only" {
  role       = aws_iam_role.instance_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess" # Example policy
}

# Create an instance profile to attach the role to EC2 instances.
resource "aws_iam_instance_profile" "instance_profile" {
  name = "test-containment-instance-profile"
  role = aws_iam_role.instance_role.name

  tags = {
    Purpose = "Testing EC2 Containment Script"
  }
} # <--- Added the missing closing brace here

# --- Security Group ---
# Create a security group allowing SSH access (Port 22).
# Note: Your script will apply a NACL, effectively overriding this for network traffic.
resource "aws_security_group" "instance_sg" {
  name        = "test-containment-sg"
  description = "Allow SSH inbound traffic"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # WARNING: Allows SSH from anywhere. Restrict if needed.
    description = "Allow SSH access"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1" # Allow all outbound traffic initially
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name    = "test-containment-sg"
    Purpose = "Testing EC2 Containment Script"
  }
}

# --- Launch Template (Modern approach instead of Launch Configuration) ---
resource "aws_launch_template" "test_lt" {
  name_prefix   = "test-containment-lt-"
  image_id      = data.aws_ami.amazon_linux_2.id
  instance_type = var.instance_type

  iam_instance_profile {
    name = aws_iam_instance_profile.instance_profile.name
  }

  network_interfaces {
    associate_public_ip_address = true # Assign a public IP for easier initial access if needed
    security_groups             = [aws_security_group.instance_sg.id]
  }

  # Enable IMDSv2 (more secure) by default for testing
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # Enforces IMDSv2
    http_put_response_hop_limit = 1
  }

  # Add tags to the instance launched from this template
  tag_specifications {
    resource_type = "instance"
    tags = {
      Name    = "Test-Containment-Instance"
      Purpose = "Testing EC2 Containment Script"
    }
  }
   tag_specifications {
    resource_type = "volume"
    tags = {
      Name    = "Test-Containment-Volume"
      Purpose = "Testing EC2 Containment Script"
    }
  }

  lifecycle {
    create_before_destroy = true
  }
}


# --- Auto Scaling Group ---
# Create an Auto Scaling Group to manage the EC2 instance.
# This helps test the ASG detection part of your script.
resource "aws_autoscaling_group" "test_asg" {
  name_prefix = "test-containment-asg-"
  # Use available default subnets across multiple AZs for resilience (though only 1 instance needed)
  vpc_zone_identifier = data.aws_subnets.default.ids

  desired_capacity = 1
  min_size         = 1
  max_size         = 1

  launch_template {
    id      = aws_launch_template.test_lt.id
    version = "$Latest" # Always use the latest version of the launch template
  }

  # --- CORRECTED TAGS SECTION ---
  # Define tags using individual tag blocks
  tag {
    key                 = "Name"
    value               = "Test-Containment-ASG"
    propagate_at_launch = true # Propagate this tag to instances
  }
  tag {
    key                 = "Purpose"
    value               = "Testing EC2 Containment Script"
    propagate_at_launch = true
  }
  # --- END CORRECTED TAGS SECTION ---


  # Wait for the specified capacity before considering creation complete
  wait_for_capacity_timeout = "5m"

  lifecycle {
    create_before_destroy = true
  }
}

# --- Outputs (Optional) ---
output "instance_role_name" {
  description = "The name of the IAM role created for the instance."
  value       = aws_iam_role.instance_role.name
}

output "asg_name" {
  description = "The name of the Auto Scaling Group created."
  value       = aws_autoscaling_group.test_asg.name
}

output "security_group_id" {
  description = "The ID of the security group created."
  value       = aws_security_group.instance_sg.id
}
