#!/usr/bin/env python3
import os

import aws_cdk as cdk

from okletsdoit_cdk.okletsdoit_cdk_stack import OkletsdoitCdkStack


app = cdk.App()
OkletsdoitCdkStack(app, "OkletsdoitCdkStack",


    env=cdk.Environment(account=os.getenv('CDK_DEFAULT_ACCOUNT'), region=os.getenv('CDK_DEFAULT_REGION')),

    )

app.synth()
