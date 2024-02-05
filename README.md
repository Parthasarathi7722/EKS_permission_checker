# EKS RBAC Permissions Checker

This Python script lists RBAC (Role-Based Access Control) permissions for an AWS EKS (Elastic Kubernetes Service) cluster. It prompts the user for AWS account details, credentials, region, and the EKS cluster name. The script then queries AWS to retrieve and display RBAC information, including attached policies and permission levels. The results are saved in a CSV file.

## Requirements

- Python 3
- Boto3 library (`pip install boto3`)

## Usage

1. Clone the repository or download the script (`eks_rbac_permissions.py`).

2. Install the required dependencies:

   ```bash
   pip install boto3
