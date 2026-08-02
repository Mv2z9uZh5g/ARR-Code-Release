# Q2 2024 Budget Proposal — Data Engineering

## Summary
Requesting $42,000/month (down from $54,800/month projected without changes)

## Current monthly spend: ~$36,800
## Projected without changes: ~$54,800 (growth + Datadog renewal)

## Proposed budget breakdown

| Category | Current | Proposed | Notes |
|----------|---------|----------|-------|
| EKS compute | $4,200 | $3,400 | Spot instances for staging/dev |
| RDS | $1,800 | $1,800 | No change |
| Redshift | $6,500 | $5,200 | Reserved instance (1yr) |
| S3 | $900 | $1,100 | Growth + 90-day retention |
| Data transfer | $1,100 | $1,200 | Slight growth expected |
| Monitoring (Grafana) | - | $2,800 | Replacing Datadog |
| Monitoring (Datadog) | $18,000 | $9,000 | Phasing out (APM only) |
| Kafka (MSK) | $2,800 | $2,800 | No change |
| Other | $1,500 | $1,700 | New tooling (Kubecost, etc) |
| Headcount tools | - | $13,000 | New hire: laptop, licenses, etc |
| **Total** | **$36,800** | **$42,000** | |

## ROI
- Net savings of $12,800/month by end of Q2 (once Datadog fully decommissioned)
- $153,600 annualized savings

## Approvals needed
- [ ] Sarah Kim (EM)
- [ ] VP Engineering
- [ ] Finance
