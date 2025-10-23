# Example Lambda function code (e.g., in a file named `lambda_handler.py`)
import psycopg2
import os
import json
import boto3
from botocore.exceptions import ClientError

def handler(event, context):
    db_host = os.environ['DB_HOST']
    db_name = os.environ['DB_NAME'] 
    secret_arn = os.environ['SECRET_ARN']
    new_username = os.environ.get('NEW_USER', 'app_user')

    client = boto3.client('secretsmanager')
    try:
        get_secret_value_response = client.get_secret_value(SecretId=secret_arn)
        credentials = json.loads(get_secret_value_response['SecretString'])
        try:
            conn = psycopg2.connect(
                host=db_host,
                user=credentials['username'],
                password=credentials['password'],
                database=db_name
            )
            cursor = conn.cursor()

            new_username = "app_user"
            new_password = "secure_password" # Consider fetching from Secrets Manager in real scenarios

            cursor.execute(f"CREATE USER {new_username};")
            cursor.execute(f"GRANT ALL PRIVILEGES ON DATABASE {db_name} TO {new_username};")
            cursor.execute(f"GRANT rds_iam TO {new_username};")

            conn.commit()
            cursor.close()
            conn.close()
            print(f"User {new_username} created and privileges granted.")
            return {'Status': 'SUCCESS'}

        except Exception as e:
            print(f"Error: {e}")
            return {'Status': 'FAILED', 'Reason': str(e)}
    except ClientError as e:
        raise e

        



    