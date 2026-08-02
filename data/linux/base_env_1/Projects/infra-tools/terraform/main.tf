terraform {
  required_version = ">= 1.7"

  backend "s3" {
    bucket         = "datacorp-terraform-state"
    key            = "infra/data-platform/terraform.tfstate"
    region         = "us-west-2"
    dynamodb_table = "terraform-locks"
    encrypt        = true
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.40"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.27"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Team        = "data-engineering"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}

variable "aws_region" {
  type    = string
  default = "us-west-2"
}

variable "environment" {
  type    = string
  default = "staging"
}

module "vpc" {
  source = "./modules/vpc"

  environment = var.environment
  cidr_block  = var.cidr_block
}

module "eks" {
  source = "./modules/eks"

  environment    = var.environment
  vpc_id         = module.vpc.vpc_id
  subnet_ids     = module.vpc.private_subnet_ids
  instance_types = ["m6i.xlarge", "m6i.2xlarge"]
  min_size       = 3
  max_size       = 10
}

module "rds" {
  source = "./modules/rds"

  environment       = var.environment
  vpc_id            = module.vpc.vpc_id
  subnet_ids        = module.vpc.private_subnet_ids
  instance_class    = "db.r6g.large"
  allocated_storage = 100
}
