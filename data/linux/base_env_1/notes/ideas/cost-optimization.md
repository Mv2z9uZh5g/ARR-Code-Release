# Cost Optimization Ideas

## Quick wins
- Switch dev/staging EKS nodes to spot instances (~60% savings)
- Enable S3 Intelligent-Tiering for the processed data bucket
- Reduce Redshift snapshot retention from 35 to 14 days
- Turn off staging cluster overnight and weekends

## Medium effort
- Move to Graviton (ARM) instances for EKS — need to rebuild some images
- Consolidate the 3 small RDS instances into one multi-tenant instance
- Use Reserved Instances for the production Redshift cluster (1-year term)

## Long term
- Evaluate moving cold data to Glacier Deep Archive
- Consider Redshift Serverless for ad-hoc query workloads
- Kafka tiered storage to reduce broker EBS costs

## Current monthly spend (approx)
- EKS compute: $4,200
- RDS: $1,800
- Redshift: $6,500
- S3: $900
- Data transfer: $1,100
- Datadog: $18,000 (!!!)
- Kafka (MSK): $2,800
- Other: $1,500
- Total: ~$36,800/month
