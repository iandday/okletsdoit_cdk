from typing import Any, cast
from aws_cdk import (
    Duration,
    RemovalPolicy,
    Stack,
    aws_route53 as route53,
    aws_certificatemanager as acm,
    aws_s3 as s3,
    aws_cloudfront as cloudfront,
    aws_cloudfront_origins as origins,
    aws_route53_targets as targets,
    aws_ssm as ssm,
    aws_ec2 as ec2,
    aws_rds as rds,
    aws_lambda as _lambda,
    aws_iam as iam,
    aws_cloudformation as cfn,
    aws_ecs as ecs,
    aws_elasticloadbalancingv2 as elbv2,
    CfnOutput,
    Duration,
    custom_resources as cr,
    aws_secretsmanager as secretsmanager,
    aws_ecs_patterns as ecs_patterns,
)
from constructs import Construct


# Prequisites:
# - Secrets Manager
#     /okletsdoItContainerRegistryToken: containing GitHub Container Registry PAT with read access to ghcr.io/iandday/okletsdoit
# - SSM Parameter
#      /aboutdayumtime/prod/image_version: containing the current production version tag for the container image
# - SSM SecureString Parameters:
#      /aboutdayumtime/prod/authentik_client_secret: containing the Authentik client secret
#      /aboutdayumtime/prod/authentik_client_id: containing the Authentik client ID
#      /aboutdayumtime/prod/authentik_url: containing the Authentik URL
#      /aboutdayumtime/prod/superuser_password: containing the superuser password
#      /aboutdayumtime/prod/superuser_email: containing the superuser email
#      /aboutdayumtime/prod/secret_key: containing the Django secret key


class OkletsdoitCdkStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        db_name = "okletsdoit"
        db_username = "okletsdoit"
        app_domain_name = "aboutdayumtime.com"

        # lookup secrets manager secret for GitHub Container Registry PAT
        ghcr_secret = secretsmanager.Secret.from_secret_name_v2(
            self,
            "GhcrSecret",
            secret_name="okletsdoItContainerRegistryToken",
        )

        # lookup ssm paramter for production version
        production_version_param = ssm.StringParameter.from_string_parameter_name(
            self,
            "ProductionVersionParam",
            string_parameter_name="/aboutdayumtime/prod/image_version",
        )

        # lookup existing public hosted zone
        hosted_zone = route53.PublicHostedZone.from_lookup(
            self, "HostedZone", domain_name="aboutdayumtime.com"
        )

        # VPC for RDS (and other resources)
        vpc: ec2.IVpc = ec2.Vpc(
            self,
            "AppVpc",
            vpc_name="AboutDayumTimeVPC",
            availability_zones=["us-east-1a", "us-east-1c"],
            create_internet_gateway=True,
            nat_gateways=1,
            ip_addresses=ec2.IpAddresses.cidr("10.0.0.0/16"),
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name="private-isolated",
                    subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS,
                    cidr_mask=24,
                ),
                ec2.SubnetConfiguration(
                    name="public", subnet_type=ec2.SubnetType.PUBLIC, cidr_mask=24
                ),
            ],
        )

        db_secret = secretsmanager.Secret(
            self,
            "DBSecret",
            generate_secret_string=secretsmanager.SecretStringGenerator(
                secret_string_template='{"username":"okletsdoit_admin"}',
                generate_string_key="password",
                password_length=24,
                exclude_punctuation=True,
            ),
            secret_name="aboutdayumtime/prod/rds_admin_credentials",
        )

        # Security group for RDS PostgreSQL instance
        rds_sg = ec2.SecurityGroup(
            self,
            "RdsInstanceSecurityGroup",
            vpc=vpc,
            description="Allow PostgreSQL access",
            allow_all_outbound=True,
        )

        rds_sg.add_ingress_rule(
            peer=ec2.Peer.ipv4(vpc.vpc_cidr_block),
            connection=ec2.Port.tcp(5432),
            description="Allow PostgreSQL access from within VPC only",
        )

        db_instance = rds.DatabaseInstance(
            self,
            "PostgresRdsInstance",
            engine=rds.DatabaseInstanceEngine.postgres(
                version=rds.PostgresEngineVersion.VER_17_5
            ),
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
            ),
            security_groups=[rds_sg],
            instance_type=ec2.InstanceType.of(
                ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MICRO
            ),
            multi_az=False,
            allocated_storage=10,
            max_allocated_storage=100,
            storage_encrypted=True,
            backup_retention=Duration.days(7),
            preferred_backup_window="03:00-04:00",
            removal_policy=RemovalPolicy.SNAPSHOT,
            deletion_protection=True,
            credentials=rds.Credentials.from_secret(
                cast(secretsmanager.ISecret, db_secret)
            ),
            database_name=db_name,
            publicly_accessible=False,
            auto_minor_version_upgrade=True,
            iam_authentication=True,
        )

        db_instance.add_rotation_single_user(automatically_after=Duration.days(7))

        db_initializer_lambda = _lambda.DockerImageFunction(
            self,
            "DbInitializerLambda",
            code=_lambda.DockerImageCode.from_image_asset(
                directory="Constructs/db_initializer",
                cmd=["handler.handler"],
            ),
            environment={
                "DB_HOST": db_instance.db_instance_endpoint_address,
                "DB_NAME": db_name,
                "SECRET_ARN": db_secret.secret_arn,
                "NEW_USER": db_username,
            },
            vpc=vpc,
            security_groups=[rds_sg],
            timeout=Duration.minutes(5),
        )

        db_secret.grant_read(db_initializer_lambda)
        db_initializer_lambda.add_to_role_policy(
            iam.PolicyStatement(
                actions=["rds:DescribeDBInstances"],
                effect=iam.Effect.ALLOW,
                resources=[db_instance.instance_arn],
            )
        )

        # Create the custom resource to invoke the Lambda
        db_custom_resource = cr.AwsCustomResource(
            self,
            "DbInitializerCustomResource",
            on_create={
                "service": "Lambda",
                "action": "invoke",
                "parameters": {
                    "FunctionName": db_initializer_lambda.function_name,
                    "InvocationType": "Event",
                },
                "physical_resource_id": cr.PhysicalResourceId.of(
                    "DbInitializerCustomResource"
                ),
            },
            on_update={
                "service": "Lambda",
                "action": "invoke",
                "parameters": {
                    "FunctionName": db_initializer_lambda.function_name,
                    "InvocationType": "Event",
                },
                "physical_resource_id": cr.PhysicalResourceId.of(
                    "DbInitializerCustomResource"
                ),
            },
            policy=cr.AwsCustomResourcePolicy.from_statements(
                [
                    iam.PolicyStatement(
                        actions=["lambda:InvokeFunction"],
                        effect=iam.Effect.ALLOW,
                        resources=[db_initializer_lambda.function_arn],
                    )
                ]
            ),
        )

        # Ensure the custom resource depends on the database instance
        db_custom_resource.node.add_dependency(db_instance)

        # create bucket with cloudfront distribution for django static files
        s3_bucket_static = s3.Bucket(
            self,
            "StaticFilesBucket",
            bucket_name=f"{self.account}-{self.region}-aboutdayumtime-static",
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            encryption=s3.BucketEncryption.S3_MANAGED,
            enforce_ssl=True,
            versioned=False,
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True,
        )

        origin_access_control = cloudfront.S3OriginAccessControl(
            self,
            "OAC",
            origin_access_control_name="aboutdayumtime-static-oac",
        )

        static_origin = origins.S3BucketOrigin.with_origin_access_control(
            bucket=s3_bucket_static, origin_access_control=origin_access_control
        )

        static_cf_domain_param = ssm.StringParameter(
            self,
            "ProdStaticCloudFrontDistributionDomain",
            parameter_name="/aboutdayumtime/prod/static_cloudfront_distribution_domain",
            string_value="static.aboutdayumtime.com",
            description="The domain name of the CloudFront distribution for static files in production",
            tier=ssm.ParameterTier.STANDARD,
        )

        static_cert = acm.Certificate(
            self,
            "Certificate",
            domain_name=static_cf_domain_param.string_value,
            validation=acm.CertificateValidation.from_dns(hosted_zone),
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
        route53.ARecord(
            self,
            "AliasRecord",
            zone=hosted_zone,
            record_name="static",
            target=route53.RecordTarget.from_alias(
                targets.CloudFrontTarget(distribution)
            ),  # type: ignore
        )

        # create bucket for media files
        s3_bucket_media = s3.Bucket(
            self,
            "MediaFilesBucket",
            bucket_name=f"{self.account}-{self.region}-aboutdayumtime-media",
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            encryption=s3.BucketEncryption.S3_MANAGED,
            enforce_ssl=True,
            versioned=False,
            removal_policy=RemovalPolicy.RETAIN,
            auto_delete_objects=False,
        )

        # ECS
        # public ALB for ecs cluster
        alb = elbv2.ApplicationLoadBalancer(
            self,
            "PublicALB",
            vpc=vpc,
            internet_facing=True,
            load_balancer_name="AboutDayumTimePublicALB",
        )

        cluster = ecs.Cluster(
            self, "EcsCluster", vpc=vpc, cluster_name="AboutDayumTimeCluster"
        )

        ecs_task_role = iam.Role(
            self,
            "EcsTaskRole",
            assumed_by=iam.ServicePrincipal("ecs-tasks.amazonaws.com"),
            inline_policies={
                "RdsAccessPolicy": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            actions=["rds:DescribeDBInstances"],
                            effect=iam.Effect.ALLOW,
                            resources=["*"],
                        ),
                        iam.PolicyStatement(
                            actions=["rds-db:connect"],
                            effect=iam.Effect.ALLOW,
                            resources=[
                                f"arn:aws:rds-db:{self.region}:{self.account}:dbuser:*/{db_username}"
                            ],
                        ),
                    ]
                ),
                "SecretsManagerAccessPolicy": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            actions=["secretsmanager:GetSecretValue"],
                            effect=iam.Effect.ALLOW,
                            resources=[db_secret.secret_arn],
                        )
                    ]
                ),
                "S3AccessPolicy": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            actions=[
                                "s3:GetObject",
                                "s3:PutObject",
                                "s3:GetObjectAcl",
                                "s3:ListBucket",
                                "s3:DeleteObject",
                                "s3:PutObjectAcl",
                            ],
                            effect=iam.Effect.ALLOW,
                            resources=[
                                s3_bucket_media.bucket_arn,
                                f"{s3_bucket_media.bucket_arn}/*",
                                s3_bucket_static.bucket_arn,
                                f"{s3_bucket_static.bucket_arn}/*",
                            ],
                        )
                    ]
                ),
                "CloudFrontAccessPolicy": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            actions=["cloudfront:CreateInvalidation"],
                            effect=iam.Effect.ALLOW,
                            resources=[distribution.distribution_arn],
                        )
                    ]
                ),
                "SSMParameterAccessPolicy": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            actions=["ssm:GetParameter"],
                            effect=iam.Effect.ALLOW,
                            resources=[
                                f"arn:aws:ssm:{self.region}:{self.account}:parameter/aboutdayumtime/prod/*"
                            ],
                        )
                    ]
                ),
                "EcsExecuteCommandPolicy": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            actions=[
                                "ssmmessages:CreateControlChannel",
                                "ssmmessages:CreateDataChannel",
                                "ssmmessages:OpenControlChannel",
                                "ssmmessages:OpenDataChannel",
                            ],
                            effect=iam.Effect.ALLOW,
                            resources=["*"],
                        )
                    ]
                ),
            },
        )

        base_secrets: dict[str, ecs.Secret] = {
            "SECRET_KEY": ecs.Secret.from_ssm_parameter(
                ssm.StringParameter.from_secure_string_parameter_attributes(
                    self,
                    "DjangoSecretKeyParam",
                    parameter_name="/aboutdayumtime/prod/secret_key",
                )
            ),
            "DJANGO_SUPERUSER_EMAIL": ecs.Secret.from_ssm_parameter(
                ssm.StringParameter.from_secure_string_parameter_attributes(
                    self,
                    "DjangoSuperuserEmailParam",
                    parameter_name="/aboutdayumtime/prod/superuser_email",
                )
            ),
            "DJANGO_SUPERUSER_PASSWORD": ecs.Secret.from_ssm_parameter(
                ssm.StringParameter.from_secure_string_parameter_attributes(
                    self,
                    "DjangoSuperuserPasswordParam",
                    parameter_name="/aboutdayumtime/prod/superuser_password",
                )
            ),
            "AUTHENTIK_URL": ecs.Secret.from_ssm_parameter(
                ssm.StringParameter.from_secure_string_parameter_attributes(
                    self,
                    "AuthentikUrlParam",
                    parameter_name="/aboutdayumtime/prod/authentik_url",
                )
            ),
            "AUTHENTIK_CLIENT_ID": ecs.Secret.from_ssm_parameter(
                ssm.StringParameter.from_secure_string_parameter_attributes(
                    self,
                    "AuthentikClientIdParam",
                    parameter_name="/aboutdayumtime/prod/authentik_client_id",
                )
            ),
            "AUTHENTIK_CLIENT_SECRET": ecs.Secret.from_ssm_parameter(
                ssm.StringParameter.from_secure_string_parameter_attributes(
                    self,
                    "AuthentikClientSecretParam",
                    parameter_name="/aboutdayumtime/prod/authentik_client_secret",
                )
            ),
        }
        base_environment: dict[str, str] = {
            "DEBUG": "False",
            "DJANGO_LOG_LEVEL": "INFO",
            "ALLOWED_HOSTS": f"{app_domain_name},",
            "TIMEZONE": "America/New_York",
            "DJANGO_SUPERUSER_USERNAME": "admin",
            "RDS_DB_NAME": db_name,
            "RDS_USERNAME": db_username,
            "POSTGRES_USER": db_username,
            "RDS_HOSTNAME": db_instance.db_instance_endpoint_address,
            "POSTGRES_HOST": db_instance.db_instance_endpoint_address,
            "RDS_PORT": "5432",
            "AWS_REGION": self.region,
            "DJANGO_CSRF_TRUSTED_ORIGINS": f"https://{app_domain_name},",
            "AWS_STATIC_BUCKET_NAME": s3_bucket_static.bucket_name,
            "AWS_MEDIA_BUCKET_NAME": s3_bucket_media.bucket_name,
            "AWS_S3_REGION_NAME": self.region,
            "AWS_S3_ENDPOINT_URL": f"https://s3.{self.region}.amazonaws.com",
            "AWS_S3_STATIC_DOMAIN": static_cf_domain_param.string_value,
            "AWS_S3_MEDIA_DOMAIN": f"s3.{self.region}.amazonaws.com/{s3_bucket_media.bucket_name}",
            "AWS_S3_STATIC_DOMAIN_CSP": static_cf_domain_param.string_value,
            "REDIS_URL": "redis://localhost:6379",
            "LOCAL_DEV": "False",
        }

        django_container_image = ecs.ContainerImage.from_registry(
            name=f"ghcr.io/iandday/okletsdoit:{production_version_param.string_value}",
            credentials=cast(secretsmanager.ISecret, ghcr_secret),
        )
        fargate_service = ecs_patterns.ApplicationLoadBalancedFargateService(
            self,
            "FargateService",
            cluster=cluster,
            cpu=2048,
            desired_count=1,
            memory_limit_mib=4096,
            runtime_platform=ecs.RuntimePlatform(
                operating_system_family=ecs.OperatingSystemFamily.LINUX,
                cpu_architecture=ecs.CpuArchitecture.ARM64,
            ),
            enable_execute_command=True,
            public_load_balancer=True,
            load_balancer=alb,
            task_image_options=ecs_patterns.ApplicationLoadBalancedTaskImageOptions(
                image=django_container_image,
                container_name="django-server",
                container_port=8000,
                task_role=ecs_task_role,
                environment=base_environment | {"CONTAINER_ROLE": "server"},
                secrets=base_secrets,
            ),
            domain_name=app_domain_name,
            service_name="AboutDayumTimeService",
            domain_zone=hosted_zone,
            certificate=acm.Certificate(
                self,
                "EcsServiceCertificate",
                domain_name=app_domain_name,
                validation=acm.CertificateValidation.from_dns(hosted_zone),
            ),
            propagate_tags=ecs.PropagatedTagSource.SERVICE,
        )
        fargate_service.target_group.configure_health_check(
            path="/health/",
            port="8000",
            interval=Duration.seconds(30),
            timeout=Duration.seconds(5),
            healthy_threshold_count=2,
            unhealthy_threshold_count=2,
            protocol=elbv2.Protocol.HTTP,
            healthy_http_codes="200,301",
        )

        worker_container = fargate_service.task_definition.add_container(
            "WorkerContainer",
            container_name="django-worker",
            image=django_container_image,
            logging=ecs.LogDrivers.aws_logs(stream_prefix="WorkerContainer"),
            environment=base_environment | {"CONTAINER_ROLE": "worker"},
            secrets=base_secrets,
            essential=True,
        )

        beats_container = fargate_service.task_definition.add_container(
            "BeatsContainer",
            container_name="django-beats",
            image=django_container_image,
            logging=ecs.LogDrivers.aws_logs(stream_prefix="BeatsContainer"),
            environment=base_environment | {"CONTAINER_ROLE": "beats"},
            secrets=base_secrets,
            essential=True,
        )

        redis_container = fargate_service.task_definition.add_container(
            "RedisContainer",
            container_name="redis",
            image=ecs.ContainerImage.from_registry("redis:7.0-alpine"),
            logging=ecs.LogDrivers.aws_logs(stream_prefix="RedisContainer"),
            essential=True,
            port_mappings=[
                ecs.PortMapping(container_port=6379, protocol=ecs.Protocol.TCP)
            ],
            health_check=ecs.HealthCheck(
                command=["CMD-SHELL", "redis-cli ping || exit 1"],
                interval=Duration.seconds(30),
                timeout=Duration.seconds(5),
                retries=3,
                start_period=Duration.seconds(10),
            ),
        )

        worker_container.add_container_dependencies(
            ecs.ContainerDependency(
                container=redis_container,
                condition=ecs.ContainerDependencyCondition.HEALTHY,
            )
        )
        beats_container.add_container_dependencies(
            ecs.ContainerDependency(
                container=redis_container,
                condition=ecs.ContainerDependencyCondition.HEALTHY,
            )
        )
        CfnOutput(
            self,
            "StaticBucketName",
            value=s3_bucket_static.bucket_name,
            description="The name of the static files S3 bucket",
        )
        CfnOutput(
            self,
            "MediaBucketName",
            value=s3_bucket_media.bucket_name,
            description="The name of the media files S3 bucket",
        )
        CfnOutput(
            self,
            "CloudFrontDistributionDomain",
            value=distribution.domain_name,
            description="The domain name of the CloudFront distribution for static files",
        )
        CfnOutput(
            self,
            "MediaBucketArn",
            value=s3_bucket_media.bucket_arn,
            description="The ARN of the media files S3 bucket",
        )
        CfnOutput(
            self,
            "RdsEndpoint",
            value=db_instance.db_instance_endpoint_address,
            description="The endpoint address of the PostgreSQL RDS instance",
        )
        CfnOutput(
            self,
            "RdsSecretArn",
            value=db_instance.secret.secret_arn if db_instance.secret else "",
            description="The ARN of the RDS credentials secret in Secrets Manager",
        )
