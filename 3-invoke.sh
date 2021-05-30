#!/bin/bash
set -eo pipefail
API_GATEWAY_ID=$(aws cloudformation describe-stack-resource --stack-name oAuth-Demo-NodeJS --logical-resource-id ServerlessRestApi --query 'StackResourceDetail.PhysicalResourceId' --output text)

while true; do
  curl https://${API_GATEWAY_ID}.execute-api.us-east-1.amazonaws.com/Prod/
  echo ""
  sleep 2
done
