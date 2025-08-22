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
      name       =                                                                                                                         [
                        "arn:aws:iam::1234567890:role/admin-role",
                        "arn:aws:iam::1234567890:role/sourav-automation-role",
                        "arn:aws:iam::1234567890:role/delhi-automation-role",
                        "arn:aws:iam::1234567890:role/goa-automation-role",
                        "arn:aws:iam::1234567890:role/shimla-automation-role",
                        "arn:aws:iam::1234567890:role/manali-automation-role",
                        "arn:aws:iam::1234567890:role/sakoli-automation-role",
                        "arn:aws:iam::1234567890:role/tikto-automation-role",
                        "arn:aws:iam::1234567890:role/silo-automation-role"
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
  "arn:aws:iam::1234567890:role/sourav-automation-role",
  "arn:aws:iam::1234567890:role/delhi-automation-role",
  "arn:aws:iam::1234567890:role/goa-automation-role",
  "arn:aws:iam::1234567890:role/shimla-automation-role",
  "arn:aws:iam::1234567890:role/manali-automation-role",
  "arn:aws:iam::1234567890:role/sakoli-automation-role",
  "arn:aws:iam::1234567890:role/tikto-automation-role",
  "arn:aws:iam::1234567890:role/silo-automation-role"
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
  "arn:aws:iam::1234567890:role/sourav-automation-role",
  "arn:aws:iam::1234567890:role/delhi-automation-role",
  "arn:aws:iam::1234567890:role/goa-automation-role",
  "arn:aws:iam::1234567890:role/shimla-automation-role",
  "arn:aws:iam::1234567890:role/manali-automation-role",
  "arn:aws:iam::1234567890:role/sakoli-automation-role",
  "arn:aws:iam::1234567890:role/tikto-automation-role",
  "arn:aws:iam::1234567890:role/silo-automation-role"
]
          }
        }
      },
      ,{
        Sid       = "ProjectAccess"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::1234567890:role/sourav-automation-role" }
        Action    = ["s3:ListBucket"]
        Resource  = "arn:aws:s3:::saurav"
      }
      ,{
        Sid       = "ProjectAccess"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::1234567890:role/delhi-automation-role" }
        Action    = ["s3:ListBucket"]
        Resource  = "arn:aws:s3:::delhi"
      }
      ,{
        Sid       = "ProjectAccess"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::1234567890:role/goa-automation-role" }
        Action    = ["s3:ListBucket"]
        Resource  = "arn:aws:s3:::goa"
      }
      ,{
        Sid       = "ProjectAccess"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::1234567890:role/shimla-automation-role" }
        Action    = ["s3:ListBucket"]
        Resource  = "arn:aws:s3:::shimla"
      }
      ,{
        Sid       = "ProjectAccess"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::1234567890:role/manali-automation-role" }
        Action    = ["s3:ListBucket"]
        Resource  = "arn:aws:s3:::manali"
      }
      ,{
        Sid       = "ProjectAccess"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::1234567890:role/sakoli-automation-role" }
        Action    = ["s3:ListBucket"]
        Resource  = "arn:aws:s3:::sakoli"
      }
      ,{
        Sid       = "ProjectAccess"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::1234567890:role/tikto-automation-role" }
        Action    = ["s3:ListBucket"]
        Resource  = "arn:aws:s3:::tiktok"
      }
      ,{
        Sid       = "ProjectAccess"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::1234567890:role/silo-automation-role" }
        Action    = ["s3:ListBucket"]
        Resource  = "arn:aws:s3:::silo"
      }
    ]
  })
]
