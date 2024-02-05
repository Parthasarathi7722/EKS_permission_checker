import boto3
import csv

def get_permission_level(policies):
    # Map AWS managed policy names to permission levels
    permission_level_mapping = {
        'AdministratorAccess': 'Admin',
        'PowerUserAccess': 'PowerUser',
        'ReadOnlyAccess': 'ReadOnly',
        # Add more mappings as needed
    }

    for policy in policies:
        if policy in permission_level_mapping:
            return permission_level_mapping[policy]

    return 'Custom'

def list_eks_rbac_permissions(cluster_name, region):
    try:
        # Create an EKS client
        eks_client = boto3.client('eks', region_name=region)

        # Describe the cluster to get the ARN
        cluster_info = eks_client.describe_cluster(name=cluster_name)
        cluster_arn = cluster_info['cluster']['arn']

        # Create an IAM client
        iam_client = boto3.client('iam')

        # List roles associated with the EKS cluster
        roles_response = eks_client.list_role_mappings(
            clusterName=cluster_name
        )

        rbac_permissions = []

        for role_mapping in roles_response['roleMappings']:
            role_arn = role_mapping['roleArn']
            attached_policies = []

            # Get the inline policies attached to the IAM role
            policies_response = iam_client.list_attached_role_policies(
                RoleName=role_arn.split('/')[-1]
            )

            for policy in policies_response.get('AttachedPolicies', []):
                attached_policies.append(policy['PolicyName'])

            permission_level = get_permission_level(attached_policies)

            # Get IAM users and roles attached to the policy
            policy_users = iam_client.list_entities_for_policy(
                PolicyArn=f'arn:aws:iam::{cluster_info["cluster"]["account-id"]}:policy/{attached_policies[0]}'
            )

            users = [user['UserName'] for user in policy_users.get('PolicyUsers', [])]
            roles = [role['RoleName'] for role in policy_users.get('PolicyRoles', [])]

            rbac_permissions.append({
                'Role': role_arn,
                'AttachedPolicies': attached_policies,
                'PermissionLevel': permission_level,
                'Users': users,
                'Roles': roles
            })

        return rbac_permissions

    except Exception as e:
        print(f"Error: {str(e)}")
        return None

def save_to_csv(data, filename='rbac_permissions.csv'):
    try:
        with open(filename, mode='w', newline='') as file:
            writer = csv.DictWriter(file, fieldnames=['Role', 'AttachedPolicies', 'PermissionLevel', 'Users', 'Roles'])
            writer.writeheader()
            for entry in data:
                writer.writerow(entry)
        print(f"\nRBAC permissions saved to {filename}")

    except Exception as e:
        print(f"Error while saving to CSV: {str(e)}")

def main():
    # Prompt user for input
    aws_account = input("Enter your AWS account ID: ")
    aws_access_key = input("Enter your AWS access key ID: ")
    aws_secret_key = input("Enter your AWS secret access key: ")
    aws_region = input("Enter the AWS region where the EKS cluster is located: ")
    eks_cluster_name = input("Enter the name of your EKS cluster: ")

    # Configure AWS credentials
    boto3.setup_default_session(
        aws_access_key_id=aws_access_key,
        aws_secret_access_key=aws_secret_key,
        region_name=aws_region
    )

    # Call the function to list RBAC permissions
    rbac_permissions = list_eks_rbac_permissions(eks_cluster_name, aws_region)

    if rbac_permissions:
        # Print RBAC information
        print(f"\nRBAC Permissions for EKS Cluster '{eks_cluster_name}':\n")
        for permission in rbac_permissions:
            print(f"Role: {permission['Role']}")
            print(f"  Attached Policies: {', '.join(permission['AttachedPolicies'])}")
            print(f"  Permission Level: {permission['PermissionLevel']}")
            print(f"  Users: {', '.join(permission['Users'])}")
            print(f"  Roles: {', '.join(permission['Roles'])}\n---\n")

        # Save RBAC information to CSV
        save_to_csv(rbac_permissions)

if __name__ == "__main__":
    main()
