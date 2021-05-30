#!/bin/bash
set -eo pipefail
ARTIFACT_BUCKET=$(cat bucket-name.txt)
sam build
sam deploy --stack-name oAuth-Demo-NodeJS --s3-bucket $ARTIFACT_BUCKET --s3-prefix oAuth-Demo-NodeJS --region us-east-1 --no-confirm-changeset --capabilities CAPABILITY_IAM




