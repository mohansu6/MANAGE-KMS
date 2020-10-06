import boto3
import json

class kms():
    kms_client = boto3.client('kms', region_name='us-east-1')
    response = kms_client.create_key(
        Description='My KMS Key',
        KeyUsage='ENCRYPT_DECRYPT',
        CustomerMasterKeySpec='RSA_2048',
        Origin='AWS_KMS',
        Tags=[
            {
                'TagKey': 'KeyPurpose',
                'TagValue': 'devops'
            },
        ]
    )

    for keys,values in response.items():
        print(keys,'->',values)
        if 'KeyId' in values:
            KeyID = values['KeyId']


    def create_client_key(self):
        self.response
        print("KMS Asymmetric Key created")

    def create_alias(self):
        # kms_client = boto3.client('kms', region_name='us-east-1')
        response_alias = kms.kms_client.create_alias(
            AliasName='alias/Asymmetric_16',
            TargetKeyId= self.KeyID
        )
        print("Alias name created for Asymmetric key")

    def update_alias(self):
        # kms_client = boto3.client('kms', region_name='us-east-1')
        response_update_alias = kms.kms_client.update_alias(
            AliasName='alias/Asymmetric_16',
            TargetKeyId=self.KeyID
        )
        print("Alias name assigned to new Asymmetric key")

    def set_policy(self):
        # kms_client = boto3.client('kms', region_name='us-east-1')
        response_policy = kms.kms_client.put_key_policy(
            KeyId= self.KeyID,
            PolicyName='default',
            Policy="""{
    "Id": "key-consolepolicy-3",
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "Enable IAM User Permissions",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::212189423464:root"
            },
            "Action": "kms:*",
            "Resource": "*"
        },
        {
            "Sid": "Allow access for Key Administrators",
            "Effect": "Allow",
            "Principal": {
                "AWS": [
                    "arn:aws:iam::212189423464:user/admin",
                    "arn:aws:iam::212189423464:user/mohansu6"
                ]
            },
            "Action": [
                "kms:Create*",
                "kms:Describe*",
                "kms:Enable*",
                "kms:List*",
                "kms:Put*",
                "kms:Update*",
                "kms:Revoke*",
                "kms:Disable*",
                "kms:Get*",
                "kms:Delete*",
                "kms:TagResource",
                "kms:UntagResource",
                "kms:ScheduleKeyDeletion",
                "kms:CancelKeyDeletion"
            ],
            "Resource": "*"
        },
        {
            "Sid": "Allow use of the key",
            "Effect": "Allow",
            "Principal": {
                "AWS": [
                    "arn:aws:iam::212189423464:user/mohansu6",
                    "arn:aws:iam::212189423464:user/admin"
                ]
            },
            "Action": [
                "kms:Encrypt",
                "kms:Decrypt",
                "kms:ReEncrypt*",
                "kms:DescribeKey",
                "kms:GetPublicKey"
            ],
            "Resource": "*"
        },
        {
            "Sid": "Allow attachment of persistent resources",
            "Effect": "Allow",
            "Principal": {
                "AWS": [
                    "arn:aws:iam::212189423464:user/mohansu6",
                    "arn:aws:iam::212189423464:user/admin"
                ]
            },
            "Action": [
                "kms:CreateGrant",
                "kms:ListGrants",
                "kms:RevokeGrant"
            ],
            "Resource": "*",
            "Condition": {
                "Bool": {
                    "kms:GrantIsForAWSResource": "true"
                }
            }
        }
    ]
}""",
            BypassPolicyLockoutSafetyCheck=True
    )
        print("Policy is set")


    # def asymmetric_encrypt(self):
    #     response = kms.kms_client.encrypt(
    #         KeyId=self.KeyID,
    #         Plaintext='Hello World',
    #         # EncryptionContext={
    #         #     'string': 'string'
    #         # },
    #         # GrantTokens=[
    #         #     'string',
    #         # ],
    #         EncryptionAlgorithm='RSAES_OAEP_SHA_256'
    #     )

def main():
    create = kms()
    create.create_client_key()
    create.create_alias()
    create.update_alias()
    create.set_policy()
    # create.asymmetric_encrypt()

if __name__ == "__main__":
    main()





# for keys,values in response.items():
#     print(keys,'->',values)