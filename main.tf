provider "aws" {
  region = var.aws_region
}


data "aws_availability_zones" "available" {}
data "aws_caller_identity" "current" {}

resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
  instance_tenancy = "default"
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id
}

resource "aws_subnet" "public" {
  count                   = 2
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.${count.index + 1}.0/24"
  availability_zone       = data.aws_availability_zones.available.names[count.index % (length(data.aws_availability_zones.available.names))]
  map_public_ip_on_launch = true
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
}

resource "aws_route" "public" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.igw.id
}

resource "aws_route_table_association" "public" {
  count          = 2
  subnet_id      = element(aws_subnet.public.*.id, count.index)
  route_table_id = aws_route_table.public.id
}



resource "aws_security_group" "load_balancer_security_group" {
  vpc_id = aws_vpc.main.id

  ingress {
    from_port        = 3000
    to_port          = 3000
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
  ingress {
    from_port        = 22
    to_port          = 22
    protocol         = "tcp"
    cidr_blocks      = ["58.65.177.66/32"]
    ipv6_cidr_blocks = ["::/0"]
  }


  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
}



data "aws_ami" "ami" {
  most_recent = true
  owners      = ["amazon", "self"]

  filter {
    name   = "name"
    values = ["amzn2-ami-ecs-hvm-*-x86_64-ebs"]
  }
}

data "aws_iam_policy_document" "ecs_agent" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ecs_agent" {
  name               = "ecs-agent"
  assume_role_policy = data.aws_iam_policy_document.ecs_agent.json
}


resource "aws_iam_role_policy_attachment" "ecs_agent" {
  role       = aws_iam_role.ecs_agent.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role"
}

resource "aws_iam_instance_profile" "ecs_agent" {
  name = "sehel-ecs-agentss"
  role = aws_iam_role.ecs_agent.name
}

resource "aws_launch_template" "sehel-ecs-template" {
  name = "sehel-ecs-template" 
  image_id = data.aws_ami.ami.id
  instance_type = "t2.medium"
  key_name = "sehel_terraform_key"
  iam_instance_profile {
    name = aws_iam_instance_profile.ecs_agent.name
  }
   user_data = base64encode(<<EOF
              #!/bin/bash
              echo ECS_CLUSTER=${aws_ecs_cluster.my_ecs_cluster.name} >> /etc/ecs/ecs.config
              EOF
  )
  network_interfaces {
    associate_public_ip_address = true
    delete_on_termination      = true
    security_groups            = [aws_security_group.load_balancer_security_group.id]
  }
}

resource "aws_autoscaling_group" "asg" {
    name                      = "sehel-asg"
    vpc_zone_identifier  = [aws_subnet.public[0].id, aws_subnet.public[1].id]
    launch_template {
        id      = aws_launch_template.sehel-ecs-template.id
        version = "$Latest"
    }
    desired_capacity          = 2
    min_size                  = 1
    max_size                  = 2

    target_group_arns = [aws_lb_target_group.ecs_target_group.arn]
}

resource "aws_ecs_cluster" "my_ecs_cluster" {
    name  = "sehel-cluster"
}

resource "aws_ecs_capacity_provider" "ec2_capacity_provider" {
  name = "EC2CapacityProviderss"
  auto_scaling_group_provider {
    auto_scaling_group_arn = aws_autoscaling_group.asg.arn
    managed_scaling {
      status         = "ENABLED"
      target_capacity = 100
    }
    managed_termination_protection = "DISABLED"
  }
}

resource "aws_ecs_cluster_capacity_providers" "cluster_capacity_provider" {
  cluster_name           = aws_ecs_cluster.my_ecs_cluster.name
  capacity_providers     = [aws_ecs_capacity_provider.ec2_capacity_provider.name]
  default_capacity_provider_strategy {
    capacity_provider = aws_ecs_capacity_provider.ec2_capacity_provider.name
    base             = 0
    weight           = 1
  }
}


resource "aws_lb" "ecs_lb" {
  name               = "sehel-jenkins-ecs-lb"
  internal           = false
  load_balancer_type = "application"
  subnets            = aws_subnet.public.*.id
  security_groups    = [aws_security_group.load_balancer_security_group.id]
}

resource "aws_lb_target_group" "ecs_target_group" {
  name     = "sehel-jenkins-ecs-target-group"
  port     = 3000
  protocol = "HTTP"
  vpc_id   = aws_vpc.main.id
  target_type = "instance"

  health_check {
  healthy_threshold   = "3"
  interval            = "300"
  protocol            = "HTTP"
  matcher             = "200"
  timeout             = "3"
  path                = "/v1/status"
  unhealthy_threshold = "2"
  }
}

resource "aws_lb_listener" "listener" {
  load_balancer_arn = aws_lb.ecs_lb.id
  port              = "3000"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.ecs_target_group.id
  }
}


resource "aws_iam_role_policy_attachment" "ecs_task_execution_attachment" {
  policy_arn = aws_iam_policy.ecs_task_execution_policy.arn
  role       = aws_iam_role.ecs_task_execution_role.name
}


resource "aws_iam_role" "ecs_task_execution_role" {
  name = "sehel-jenkins-ecs-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_policy" "ecs_task_execution_policy" {
  name = "sehel-jenkins-ecs-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "ecr:GetAuthorizationToken",
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:GetRepositoryPolicy",
          "ecr:DescribeRepositories",
          "ecr:ListImages",
          "ecr:DescribeImages",
          "ecr:BatchGetImage",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
      {
        Action = [
          "ecs:RunTask",
          "ecs:StartTask",
          "ecs:StopTask",
          "ecs:ListTasks",
          "ecs:DescribeTasks",
          "ecs:DescribeTaskDefinition",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
      {
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Effect   = "Allow"
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Action = [
          "iam:PassRole",
        ]
        Effect   = "Allow"
        Resource = "arn:aws:iam::*:role/*"
      }
    ]
  })
}

# data "aws_ecr_image" "latest" {
# #   name         = "latest"
#   image_digest = "sha256:latest"
#   repository_name = "sehel-node-application"
# }


resource "aws_ecs_task_definition" "ecs_task_definition" {
  family                   = "sehel-jenkins-ecs-task"
  container_definitions    = jsonencode([
    {
      "name": "sehel-container",
    #   "image": "489994096722.dkr.ecr.us-east-2.amazonaws.com/sehel-node-application:41",
     "image": "489994096722.dkr.ecr.us-east-2.amazonaws.com/sehel-node-application:latest"
     
      "cpu": 256,
      "memory": 512,
      "essential": true,
      "portMappings": [
        {
          "containerPort": 3000,
          "hostPort": 3000
        }
      ]
    }
  ])
  requires_compatibilities = ["EC2"]
  network_mode             = "bridge"
  memory                   = "512"
  cpu                      = "256"
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
}

resource "aws_ecs_service" "ecs_service" {
  name            = "sehel-ecs-service"
  cluster         = aws_ecs_cluster.my_ecs_cluster.id
  task_definition = aws_ecs_task_definition.ecs_task_definition.arn
  scheduling_strategy  = "REPLICA"
  desired_count   = 1
  force_new_deployment = true

  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200
  
  

  capacity_provider_strategy {
   capacity_provider = aws_ecs_capacity_provider.ec2_capacity_provider.name
   weight            = 100
 }



  load_balancer {
    target_group_arn = aws_lb_target_group.ecs_target_group.arn
    container_name   = "sehel-container"
    container_port   = 3000
  }

  depends_on = [aws_lb_listener.listener]
}
