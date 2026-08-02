#!/bin/bash
# Quick fix for consumer lag — scale up workers temporarily
# Used during the March 5 incident

kubectl scale deployment/clickstream-worker -n data-pipeline --replicas=5
echo "Scaled to 5 replicas. Monitor lag:"
echo "  watch kubectl exec -it kafka-tools-0 -n kafka -- kafka-consumer-groups.sh --bootstrap-server \$KAFKA_BROKERS --describe --group clickstream-consumer"
echo ""
echo "Remember to scale back down after lag is cleared:"
echo "  kubectl scale deployment/clickstream-worker -n data-pipeline --replicas=3"
