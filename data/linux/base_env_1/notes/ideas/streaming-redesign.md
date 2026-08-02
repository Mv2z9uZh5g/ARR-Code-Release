# Streaming Pipeline Redesign Ideas

Right now we're doing micro-batch every 5 minutes for most of our pipelines.
True streaming would reduce latency to seconds but adds complexity.

## Options

1. **Flink** — most mature, Java/Scala ecosystem, steep learning curve
2. **Kafka Streams** — simpler, but tightly coupled to Kafka
3. **Materialize** — SQL interface on streams, still relatively new
4. **Spark Structured Streaming** — we already know Spark, but resource hungry

## Questions to answer
- Do we actually need sub-second latency? Who benefits?
- What's our operational readiness for a stateful streaming system?
- Can we start with one pipeline (clickstream?) and expand?

## Next steps
- Talk to the product team about latency requirements
- Run a POC with Flink on the clickstream pipeline
- Cost analysis: Flink on EKS vs managed (Amazon Kinesis Data Analytics)

---

Jotted down after the March architecture review. Revisit in Q2.
