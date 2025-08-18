from dataclasses import dataclass
from typing import Optional
from aws_cdk import (
    App,
    Duration,
    Stack,
    RemovalPolicy,
    aws_s3 as s3,
    aws_ecs as ecs,
    aws_ec2 as ec2,
    aws_events as events,
    aws_events_targets as targets,
    aws_ecr as ecr,
    aws_iam as iam,
    aws_rds as rds,
    LegacyStackSynthesizer,
)


@dataclass
class RdsConfig:
    # pylint: disable=too-many-instance-attributes
    database_name: str = "shuttle_db"
    username: str = "shuttle"
    engine_version: rds.PostgresEngineVersion = rds.PostgresEngineVersion.VER_17_4
    instance_type: ec2.InstanceType = ec2.InstanceType.of(
        ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MICRO
    )
    allocated_storage: int = 20
    multi_az: bool = False
    backup_retention_days: Duration = Duration.days(7)
    deletion_protection: bool = False
    secret_name: str = "shuttle-db-secret"


@dataclass
class EcsScheduledTaskResult:
    task_definition: ecs.FargateTaskDefinition
    rule: events.Rule
    cluster: ecs.Cluster
    runtime_container: ecs.ContainerDefinition
    security_group: ec2.SecurityGroup


class EcrRepository(Stack):
    def __init__(self, scope: App, construct_id: str, **kwargs) -> None:
        self.repository_name = kwargs.pop("repository_name")

        kwargs["synthesizer"] = LegacyStackSynthesizer()

        super().__init__(scope, construct_id, **kwargs)

    @property
    def name(self) -> str:
        return self.repository_name

    def create(self):
        # Create a private ECR repository
        return ecr.Repository(
            self,
            "ShuttleScheduledTaskRepo",
            repository_name=self.repository_name,
            image_scan_on_push=True,
            removal_policy=RemovalPolicy.DESTROY,  # For easy cleanup during development
            empty_on_delete=True,  # Allows a CF destroy to destroy images that were pushed
        )


class EcsScheduledTaskStack(Stack):
    def __init__(self, scope: App, construct_id: str, **kwargs) -> None:
        self.cron_schedule = kwargs.pop("cron_schedule", "0 12 * * ? *")
        self.repository = kwargs.pop("repository")
        self.image_uri = kwargs.pop("image_uri")

        kwargs["synthesizer"] = LegacyStackSynthesizer()

        super().__init__(scope, construct_id, **kwargs)

    def create_vpc(self) -> ec2.Vpc:
        vpc = ec2.Vpc(self, "ShuttleVpc", max_azs=2)

        return vpc

    def create_service(self, vpc: ec2.Vpc) -> EcsScheduledTaskResult:
        # Create an ECS cluster
        cluster = ecs.Cluster(self, "ShuttleCluster", vpc=vpc)

        # Create a Fargate task definition
        task_definition = ecs.FargateTaskDefinition(
            self,
            "ShuttleScheduledTaskDefinition",
            memory_limit_mib=512,
            cpu=256,
        )

        # Add the required ECR permissions to the execution role
        task_definition.add_to_execution_role_policy(
            iam.PolicyStatement(actions=["ecr:getAuthorizationToken"], resources=["*"])
        )

        repository_arn = self.repository.repository_arn

        task_definition.add_to_execution_role_policy(
            iam.PolicyStatement(
                actions=["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"],
                resources=[repository_arn],
            )
        )

        # Add container to the task definition
        runtime_container = task_definition.add_container(
            "Runtime",
            image=ecs.ContainerImage.from_registry(self.image_uri),
            logging=ecs.LogDrivers.aws_logs(stream_prefix="scheduled-task"),
        )

        # Create the EventBridge rule with the provided cron schedule
        rule = events.Rule(
            self,
            "ScheduleRule",
            schedule=events.Schedule.expression(f"cron({self.cron_schedule})"),
        )

        security_group = ec2.SecurityGroup(
            self,
            "ShuttleEcsSecurityGroup",
            vpc=vpc,
            description="Security group for Shuttle ECS task",
            allow_all_outbound=True,
        )

        # Add the ECS task as a target for the rule
        rule.add_target(
            targets.EcsTask(
                cluster=cluster,
                task_definition=task_definition,
                subnet_selection=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC),
                security_groups=[security_group],
            )
        )

        return EcsScheduledTaskResult(
            task_definition=task_definition,
            rule=rule,
            cluster=cluster,
            runtime_container=runtime_container,
            security_group=security_group,
        )

    def create_bucket(
        self, bucket_name: str, additional_principals: list[iam.IPrincipal]
    ) -> s3.Bucket:
        # Create S3 bucket with security best practices
        bucket = s3.Bucket(
            self,
            "ShuttleS3Bucket",
            bucket_name=bucket_name,
            object_ownership=s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
            public_read_access=False,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            versioned=True,
            encryption=s3.BucketEncryption.S3_MANAGED,
            removal_policy=RemovalPolicy.DESTROY,  # For easy cleanup during development
        )

        for role in additional_principals:
            bucket.add_to_resource_policy(
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    principals=[role],
                    actions=["s3:ListBucket"],
                    resources=[bucket.bucket_arn],
                )
            )

            bucket.add_to_resource_policy(
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    principals=[role],
                    actions=["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
                    resources=[bucket.arn_for_objects("*")],
                )
            )

        return bucket

    def create_rds(
        self,
        vpc: ec2.Vpc,
        ecs_security_group: ec2.SecurityGroup,
        config: Optional[RdsConfig] = None,
    ):
        if config is None:
            config = RdsConfig()

        # Create a subnet group for the RDS instance
        subnet_group = rds.SubnetGroup(
            self,
            "ShuttleDbSubnetGroup",
            description="Subnet group for Shuttle RDS instance",
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC),
        )

        # Create a security group for the RDS instance
        security_group = ec2.SecurityGroup(
            self,
            "ShuttleDbSecurityGroup",
            vpc=vpc,
            description="Security group for Shuttle RDS instance",
            allow_all_outbound=False,
        )
        security_group.add_ingress_rule(
            peer=ec2.Peer.any_ipv4(),
            connection=ec2.Port.tcp(5432),
            description="Allow public access to RDS on PSQL port",
        )

        credentials = rds.Credentials.from_generated_secret(
            config.username,
            secret_name=config.secret_name,
        )

        # Create the RDS instance
        db_instance = rds.DatabaseInstance(
            self,
            "ShuttleDatabase",
            engine=rds.DatabaseInstanceEngine.postgres(version=config.engine_version),
            instance_type=config.instance_type,
            vpc=vpc,
            subnet_group=subnet_group,
            security_groups=[security_group],
            database_name=config.database_name,
            credentials=credentials,
            allocated_storage=config.allocated_storage,
            multi_az=config.multi_az,
            backup_retention=config.backup_retention_days,
            deletion_protection=config.deletion_protection,
            auto_minor_version_upgrade=True,
            delete_automated_backups=True,
            removal_policy=RemovalPolicy.DESTROY,  # For easy cleanup during development
            publicly_accessible=True,  # Mark the database as publicly accessible
        )

        return db_instance, config
