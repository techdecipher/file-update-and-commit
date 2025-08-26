# terragrunt.hcl
terraform {
  source = "../modules/s3-bucket"
}

customer_master_keys = {
  cmk_administrator_iam_arns = [
    "arn:aws:iam::1234567890:role/s3-role",
  ]
  cmk_user_iam_arns = [
    {
      name       =       [
        "arn:aws:iam::1234567890:role/admin-role",
        "arn:aws:iam::1234567890:role/project-automation-role"
      ]
      conditions = []
    }
  ]
}

source_policy_documents = [
  jsonencode({
    Version   = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyBucketAccessExceptWhitelisted"
        Effect    = "Deny"
        Principal = "*"
        NotAction = [
          "s3:Get",
          "s3:List"
        ]
        Resource  = "arn:aws:s3:::dev"
        Condition = {
          StringNotLike = {
            "aws:PrincipalArn" = [
  "arn:aws:iam::1234567890:role/terraform-role",
  "arn:aws:iam::1234567890:role/Admin-Prod",
  "arn:aws:iam::1234567890:role/project-automation-role"
]
          }
        }
      },
      {
        Sid       = "DenyObjectAccessExceptWhitelisted"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = "arn:aws:s3:::dev/*"
        Condition = {
          StringNotLike = {
            "aws:PrincipalArn" = [
  "arn:aws:iam::1234567890:role/deploy-role",
  "arn:aws:iam::1234567890:role/Admin-NonProd",
  "arn:aws:iam::1234567890:role/project-automation-role"
]
          }
        }
      },
      ,{
        Sid       = "ProjectAccess"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::1234567890:role/project-automation-role" }
        Action    = ["s3:ListBucket"]
        Resource  = "arn:aws:s3:::project"
      }
    ]
  })
]
