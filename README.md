# aws-lambda-authentication-nodejs

This project is to demo how to create a Lambda function in Node.js which performs user authentication using OAuth Authorization Code grant type through AWS Cognito. The details, such as workflows and sequence diagrams can be found at [User authentication through authorization code grant type using AWS Cognito](https://dev.to/jinlianwang/user-authentication-through-authorization-code-grant-type-using-aws-cognito-1f93).

The placeholder for this project is generated using AWS CLI. For an introduction to the AWS SAM specification, the AWS SAM CLI, and serverless application concepts, see the [AWS SAM Developer Guide](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/what-is-sam.html).


## CORS Configuration

CORS has to be enabled on AWS API Gateway, so that it provides OPTIONS method. Authentication endpoints need to return "CORS_ALLOW_ORIGIN" header, for local development, the value shall be ```http://localhost:4200```.
```
CORS_ALLOW_ORIGIN: http://localhost:4200 
```
or for production deployment to S3 bucket:
```
CORS_ALLOW_ORIGIN: http://<s3-bucket>.s3-website-us-east-1.amazonaws.com
```

A redeployment of API Gateway and Lambda functions are necessary after the change, see [template.yml](https://github.com/JinlianWang/aws-lambda-authentication-nodejs/blob/master/template.yml) for details.

## Deploy the application

To build and deploy your application, run the following in your shell to create a S3 bucket: 

```bash
./1-create-bucket.sh
```

and the following to deploy serverless application: 

```bash
./2-deploy-sam.sh 
```

## Testing

Run the following in your shell to call one of the endpoint to return login url: 

```bash
./3-invoke.sh
```

## Cleanup

To delete the application that you created, you can run the following:

```bash
./4-cleanup.sh 
```


