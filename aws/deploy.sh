#!/usr/bin/env bash
# Deploy (or update) the wormhole rendezvous mailbox: DynamoDB table + Lambda function URL.
# Idempotent. Usage: aws/deploy.sh   (uses your default AWS profile/region; override with
# AWS_PROFILE / AWS_REGION). Prints the mailbox URL at the end.
#
# Cost: designed to stay inside the AWS always-free tier for personal use — Lambda (1M req/mo
# free), DynamoDB with small *provisioned* capacity (free tier covers 25 RCU/WCU, and the fixed
# capacity also caps worst-case cost if someone abuses the endpoint: it throttles instead of
# billing more).
set -euo pipefail
NAME=${NAME:-wormhole-mailbox}
REGION=${AWS_REGION:-$(aws configure get region || echo us-east-1)}
RCU=${RCU:-10}
WCU=${WCU:-5}
HERE=$(cd "$(dirname "$0")" && pwd)
export AWS_REGION=$REGION AWS_PAGER=""
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
echo "Deploying $NAME to account $ACCOUNT, region $REGION"

# --- DynamoDB --------------------------------------------------------------------------------
if ! aws dynamodb describe-table --table-name "$NAME" >/dev/null 2>&1; then
  echo "Creating table $NAME"
  aws dynamodb create-table --table-name "$NAME" \
    --attribute-definitions AttributeName=np,AttributeType=S \
    --key-schema AttributeName=np,KeyType=HASH \
    --provisioned-throughput ReadCapacityUnits=$RCU,WriteCapacityUnits=$WCU >/dev/null
  aws dynamodb wait table-exists --table-name "$NAME"
fi
if [ "$(aws dynamodb describe-time-to-live --table-name "$NAME" --query TimeToLiveDescription.TimeToLiveStatus --output text)" != "ENABLED" ]; then
  aws dynamodb update-time-to-live --table-name "$NAME" \
    --time-to-live-specification Enabled=true,AttributeName=ttl >/dev/null
fi
TABLE_ARN=$(aws dynamodb describe-table --table-name "$NAME" --query Table.TableArn --output text)

# --- IAM role --------------------------------------------------------------------------------
ROLE=$NAME-role
if ! aws iam get-role --role-name "$ROLE" >/dev/null 2>&1; then
  echo "Creating role $ROLE"
  aws iam create-role --role-name "$ROLE" --assume-role-policy-document '{
    "Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}' >/dev/null
  aws iam attach-role-policy --role-name "$ROLE" \
    --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
  sleep 10 # IAM propagation
fi
aws iam put-role-policy --role-name "$ROLE" --policy-name table-access --policy-document "{
  \"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",
  \"Action\":[\"dynamodb:GetItem\",\"dynamodb:PutItem\",\"dynamodb:UpdateItem\",\"dynamodb:DeleteItem\"],
  \"Resource\":\"$TABLE_ARN\"}]}"
ROLE_ARN=$(aws iam get-role --role-name "$ROLE" --query Role.Arn --output text)

# --- Lambda ----------------------------------------------------------------------------------
ZIP=$(mktemp -d)/fn.zip
(cd "$HERE" && python3 -c "import zipfile,sys; z=zipfile.ZipFile(sys.argv[1],'w',zipfile.ZIP_DEFLATED); z.write('mailbox.py'); z.close()" "$ZIP")
if aws lambda get-function --function-name "$NAME" >/dev/null 2>&1; then
  echo "Updating function code"
  aws lambda update-function-code --function-name "$NAME" --zip-file "fileb://$ZIP" >/dev/null
  aws lambda wait function-updated --function-name "$NAME"
else
  echo "Creating function $NAME"
  for _ in 1 2 3 4 5; do
    aws lambda create-function --function-name "$NAME" --runtime python3.13 --architectures arm64 \
      --handler mailbox.handler --role "$ROLE_ARN" --zip-file "fileb://$ZIP" \
      --memory-size 128 --timeout 10 \
      --environment "Variables={TABLE=$NAME,TTL_SECONDS=1800}" >/dev/null && break
    echo "  (waiting for IAM role to propagate)"; sleep 8
  done
  aws lambda wait function-active-v2 --function-name "$NAME"
fi

# Keep logs from accumulating cost.
aws logs create-log-group --log-group-name "/aws/lambda/$NAME" 2>/dev/null || true
aws logs put-retention-policy --log-group-name "/aws/lambda/$NAME" --retention-in-days 3

# --- Public function URL ----------------------------------------------------------------------
# CORS lets the web sender (a static page on any origin) call the mailbox from the browser.
CORS='AllowOrigins=*,AllowMethods=POST,AllowHeaders=content-type,MaxAge=86400'
if ! aws lambda get-function-url-config --function-name "$NAME" >/dev/null 2>&1; then
  aws lambda create-function-url-config --function-name "$NAME" --auth-type NONE --cors "$CORS" >/dev/null
else
  aws lambda update-function-url-config --function-name "$NAME" --cors "$CORS" >/dev/null
fi
aws lambda add-permission --function-name "$NAME" --statement-id public-url \
  --action lambda:InvokeFunctionUrl --principal "*" --function-url-auth-type NONE >/dev/null 2>&1 || true
aws lambda add-permission --function-name "$NAME" --statement-id public-invoke \
  --action lambda:InvokeFunction --principal "*" >/dev/null 2>&1 || true
URL=$(aws lambda get-function-url-config --function-name "$NAME" --query FunctionUrl --output text)

echo "Smoke test:"
curl -fsS -X POST "$URL" -H 'content-type: application/json' -d '{"op":"ping"}' && echo
echo
echo "Mailbox URL: $URL"
echo "Build with:  WORMHOLE_MAILBOX_URL=$URL cargo build --release"
