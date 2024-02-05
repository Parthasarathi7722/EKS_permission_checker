# EKS RBAC Permissions Checker

This Python script lists RBAC (Role-Based Access Control) permissions for an AWS EKS (Elastic Kubernetes Service) cluster. It prompts the user for AWS account details, credentials, region, and the EKS cluster name. The script then queries AWS to retrieve and display RBAC information, including attached policies, permission levels, IAM users, and roles attached to the policies. The results are saved in a CSV file.

## Requirements

- Python 3
- Boto3 library (`pip install boto3`)

## Usage

1. Clone the repository or download the script (`eks_rbac_permissions.py`).

2. Install the required dependencies:

   ```bash
   pip install boto3

NOTE:
1. Ensure that your AWS credentials have the necessary permissions to describe EKS clusters, IAM roles, and policies.
2. Make sure to replace the placeholder values in the prompts with your actual AWS account details and EKS cluster name.
3. Adjust the permission_level_mapping dictionary in the script to match your specific AWS managed policies and their corresponding permission levels.
4. The script now includes information about IAM users and roles attached to the policies associated with each EKS cluster role.
Feel free to reach out if you have any questions or encounter issues.

