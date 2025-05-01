# --- Provider Configuration ---
provider "aws" {
  region = var.aws_region
}

# --- Variables ---
variable "aws_region" {
  description = "The AWS region to deploy resources in."
  type        = string
  default     = "us-east-1"
}

variable "instance_type" {
  description = "The EC2 instance type to use."
  type        = string
  default     = "t3.micro"
}

variable "vpc_cidr_block" {
  description = "CIDR block for the VPC."
  type        = string
  default     = "10.0.0.0/16"
}

variable "subnet_cidr_block" {
  description = "CIDR block for the public subnet."
  type        = string
  default     = "10.0.1.0/24"
}

# --- Data Sources ---
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

# --- Network Resources ---
# Create a dedicated VPC for the test environment
resource "aws_vpc" "test_vpc" {
  cidr_block = var.vpc_cidr_block
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name    = "Test-Containment-VPC"
    Purpose = "Testing EC2 Containment Script"
  }
}

# Create a public subnet within the VPC
resource "aws_subnet" "test_public_subnet" {
  vpc_id     = aws_vpc.test_vpc.id
  cidr_block = var.subnet_cidr_block
  availability_zone = "${var.aws_region}a" # Use the 'a' AZ for simplicity
  map_public_ip_on_launch = true # Ensure instances get public IPs

  tags = {
    Name    = "Test-Containment-Public-Subnet"
    Purpose = "Testing EC2 Containment Script"
  }
}

# Create an Internet Gateway for the VPC
resource "aws_internet_gateway" "test_igw" {
  vpc_id = aws_vpc.test_vpc.id

  tags = {
    Name    = "Test-Containment-IGW"
    Purpose = "Testing EC2 Containment Script"
  }
}

# Create a Route Table for the public subnet
resource "aws_route_table" "test_public_rt" {
  vpc_id = aws_vpc.test_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.test_igw.id
  }

  tags = {
    Name    = "Test-Containment-Public-RT"
    Purpose = "Testing EC2 Containment Script"
  }
}

# Associate the Route Table with the public subnet
resource "aws_route_table_association" "test_public_assoc" {
  subnet_id      = aws_subnet.test_public_subnet.id
  route_table_id = aws_route_table.test_public_rt.id
}


# --- IAM Role and Policy ---
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

resource "aws_iam_role_policy_attachment" "s3_read_only" {
  role       = aws_iam_role.instance_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess" # Example policy
}

resource "aws_iam_instance_profile" "instance_profile" {
  name = "test-containment-instance-profile"
  role = aws_iam_role.instance_role.name

  tags = {
    Purpose = "Testing EC2 Containment Script"
  }
}

# --- Security Group ---
# Updated to use the new VPC
resource "aws_security_group" "instance_sg" {
  name        = "test-containment-sg"
  description = "Allow SSH inbound traffic"
  vpc_id      = aws_vpc.test_vpc.id # Use the new VPC ID

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

# --- Launch Template ---
# Updated to reference the SG in the new VPC
resource "aws_launch_template" "test_lt" {
  name_prefix   = "test-containment-lt-"
  image_id      = data.aws_ami.amazon_linux_2.id
  instance_type = var.instance_type

  iam_instance_profile {
    name = aws_iam_instance_profile.instance_profile.name
  }

  # Network interface configured within the ASG via subnet selection
  # Security group is associated here
  vpc_security_group_ids = [aws_security_group.instance_sg.id]

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
# Updated to use the new subnet ID
resource "aws_autoscaling_group" "test_asg" {
  name_prefix = "test-containment-asg-"
  # Use the specific subnet created in our VPC
  vpc_zone_identifier = [aws_subnet.test_public_subnet.id]

  desired_capacity = 1
  min_size         = 1
  max_size         = 1

  launch_template {
    id      = aws_launch_template.test_lt.id
    version = "$Latest"
  }

  tag {
    key                 = "Name"
    value               = "Test-Containment-ASG"
    propagate_at_launch = true
  }
  tag {
    key                 = "Purpose"
    value               = "Testing EC2 Containment Script"
    propagate_at_launch = true
  }

  wait_for_capacity_timeout = "5m"

  lifecycle {
    create_before_destroy = true
  }
}

# --- Outputs ---
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

output "vpc_id" {
  description = "The ID of the VPC created."
  value       = aws_vpc.test_vpc.id
}

output "subnet_id" {
  description = "The ID of the public subnet created."
  value       = aws_subnet.test_public_subnet.id
}

# Output the instance ID after the ASG creates it (requires waiting)
# Note: This requires the ASG to successfully launch an instance.
# We can get the instance ID from the ASG's instances attribute after apply.
# However, directly outputting it isn't straightforward as it's dynamic.
# The user will need to find the instance ID via the ASG name or tags after apply.

output "test_instance_instructions" {
  description = "Instructions to find the test instance ID."
  value       = "After apply completes, find the instance ID associated with the ASG '${aws_autoscaling_group.test_asg.name}' or tagged with Name='Test-Containment-Instance'."
}
