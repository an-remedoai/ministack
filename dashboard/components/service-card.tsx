import type { ServiceState } from "@/lib/ministack-client";

const SERVICE_LABELS: Record<string, string> = {
  s3: "S3",
  sqs: "SQS",
  sns: "SNS",
  dynamodb: "DynamoDB",
  lambda: "Lambda",
  iam: "IAM",
  sts: "STS",
  secretsmanager: "Secrets Manager",
  logs: "CloudWatch Logs",
  ssm: "SSM",
  events: "EventBridge",
  kinesis: "Kinesis",
  monitoring: "CloudWatch",
  ses: "SES",
  acm: "ACM",
  wafv2: "WAF v2",
  states: "Step Functions",
  ecr: "ECR",
  ecs: "ECS",
  rds: "RDS",
  elasticache: "ElastiCache",
  glue: "Glue",
  athena: "Athena",
  apigateway: "API Gateway",
  firehose: "Firehose",
  route53: "Route 53",
  "cognito-idp": "Cognito IDP",
  "cognito-identity": "Cognito Identity",
  ec2: "EC2",
  elasticmapreduce: "EMR",
  elasticloadbalancing: "ALB/ELBv2",
  elasticfilesystem: "EFS",
  kms: "KMS",
  cloudfront: "CloudFront",
  cloudformation: "CloudFormation",
  eks: "EKS",
};

export function ServiceCard({
  name,
  state,
}: {
  name: string;
  state: ServiceState;
}) {
  const total = Object.values(state.resources).reduce(
    (sum, n) => sum + n,
    0
  );
  const hasResources = total > 0;

  return (
    <a
      href={`/services/${name}`}
      className={`block rounded-lg border p-4 transition-colors hover:border-[var(--blue)] ${
        hasResources
          ? "border-[var(--green)]/30 bg-[var(--green)]/5"
          : "border-[var(--border)] bg-[var(--card)]"
      }`}
    >
      <div className="flex items-center justify-between mb-2">
        <h3 className="font-semibold text-sm">
          {SERVICE_LABELS[name] || name}
        </h3>
        <span
          className={`w-2 h-2 rounded-full ${
            hasResources ? "bg-[var(--green)]" : "bg-[var(--text-muted)]"
          }`}
        />
      </div>
      <div className="text-xs text-[var(--text-muted)]">
        {total === 0 ? (
          "No resources"
        ) : (
          <ul>
            {Object.entries(state.resources).map(([key, count]) => (
              <li key={key}>
                {count} {key}
              </li>
            ))}
          </ul>
        )}
      </div>
    </a>
  );
}
