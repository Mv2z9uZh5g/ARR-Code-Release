# Runbook: Kafka Consumer Lag Alert

## Alert
**Name:** KafkaConsumerLagHigh
**Threshold:** Consumer group lag > 10,000 messages for > 5 minutes
**Severity:** P3

## Diagnosis

1. Check which consumer group is lagging:
   ```
   kubectl exec -it kafka-tools-0 -n kafka -- \
     kafka-consumer-groups.sh --bootstrap-server $KAFKA_BROKERS \
     --describe --group <consumer-group>
   ```

2. Check if the consumer pods are running:
   ```
   kubectl get pods -n data-pipeline -l app=clickstream-worker
   ```

3. Check consumer logs for errors:
   ```
   kubectl logs -n data-pipeline -l app=clickstream-worker --tail=100
   ```

4. Check Kafka broker health:
   ```
   kubectl exec -it kafka-tools-0 -n kafka -- \
     kafka-broker-api-versions.sh --bootstrap-server $KAFKA_BROKERS
   ```

## Common causes

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| Consumer pods CrashLooping | OOM or config error | Check logs, increase memory |
| Lag increasing steadily | Throughput too low | Scale up consumers |
| Lag spike then stable | Temporary partition rebalance | Usually self-heals |
| All partitions lagging equally | Network issue | Check VPC/security groups |

## Resolution

- If consumer is crashed: fix the root cause and restart
- If throughput issue: scale the deployment (`kubectl scale deployment/clickstream-worker --replicas=N`)
- If Kafka issue: escalate to platform team (#platform-oncall)

## Escalation
- P3: Data engineering on-call (PagerDuty)
- P2: Also notify #data-eng-alerts in Slack
- P1: Page platform team
