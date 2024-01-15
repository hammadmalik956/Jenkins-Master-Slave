variable "aws_region" {
  description = "AWS region where the ECS cluster will be created."
  type        = string
  default     = "us-east-2"  # Replace with your desired AWS region
}

variable "cluster_name" {
  description = "Name for the ECS cluster."
  type        = string
  default     = "sehel-jenkins-ecs-cluster"
}