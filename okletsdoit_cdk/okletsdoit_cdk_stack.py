from aws_cdk import (
    # Duration,
    RemovalPolicy,
    Stack,
    aws_route53 as route53,
    aws_certificatemanager as acm,
    aws_s3 as s3,
    aws_cloudfront as cloudfront,
    aws_cloudfront_origins as origins,
    aws_route53_targets as targets,
    aws_ssm as ssm,
    CfnOutput
)
from constructs import Construct

class OkletsdoitCdkStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # public hosted zone
        hosted_zone = route53.PublicHostedZone(self, "HostedZone",
            zone_name="aboutdayumtime.com"
        )


        # create bucket with cloudfront distribution for django static files
        s3_bucket_static = s3.Bucket(self, "StaticFilesBucket",
            bucket_name=f"{self.account}-{self.region}-aboutdayumtime-static",
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            encryption=s3.BucketEncryption.S3_MANAGED,
            enforce_ssl=True,
            versioned=False,
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True
        ) 


        origin_access_control = cloudfront.S3OriginAccessControl(self, "OAC",
            origin_access_control_name="aboutdayumtime-static-oac",
        )

        static_origin = origins.S3BucketOrigin.with_origin_access_control(
            bucket=s3_bucket_static,
            origin_access_control=origin_access_control
        )


        static_cf_domain_param = ssm.StringParameter(self, "ProdStaticCloudFrontDistributionDomain",
            parameter_name="/okletsdoit/prod/static_cloudfront_distribution_domain",
            string_value='static.aboutdayumtime.com',
            description="The domain name of the CloudFront distribution for static files in production",
            tier=ssm.ParameterTier.STANDARD
        )


        static_cert = acm.Certificate(self, "Certificate",
            domain_name=static_cf_domain_param.string_value,
            validation=acm.CertificateValidation.from_dns(hosted_zone)
        )


        distribution = cloudfront.Distribution(
            self, 
            "Distribution",
            default_behavior=cloudfront.BehaviorOptions(origin=static_origin),
            domain_names=[static_cf_domain_param.string_value],
            certificate=static_cert,
            enable_logging=False,
        )
        # route53 alias record for cloudfront distribution
        route53.ARecord(self, "AliasRecord",
            zone=hosted_zone,
            record_name="static",
            target=route53.RecordTarget.from_alias(targets.CloudFrontTarget(distribution))
        )
        
        CfnOutput(self, "StaticBucketName",
            value=s3_bucket_static.bucket_name,
            description="The name of the static files S3 bucket"
        )