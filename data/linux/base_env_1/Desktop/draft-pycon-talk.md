# PyCon Talk: "From Micro-batch to Streaming: A Pragmatic Migration"

## Abstract (submitted)
Most teams don't start with streaming — they outgrow batch processing gradually.
This talk covers how our team migrated a high-volume clickstream pipeline from
5-minute micro-batches to near-real-time processing, the mistakes we made, and
what we'd do differently.

## Outline (DRAFT)

1. Intro & context (3 min)
   - Who we are, what our data platform looks like
   - Why micro-batch worked fine for 2 years

2. The tipping point (3 min)
   - Business requirements changed — needed sub-minute freshness
   - Micro-batch started falling behind during peak hours

3. Choosing the right tool (5 min)
   - Evaluated: Flink, Kafka Streams, Spark Streaming
   - Why we picked Kafka Streams (simplicity + existing Kafka investment)
   - Honest comparison chart

4. The migration (10 min)
   - Running old and new in parallel
   - Validation: comparing outputs between batch and stream
   - Handling late-arriving data
   - Schema evolution mid-migration (oops)

5. What we got wrong (5 min)
   - Underestimated state management complexity
   - Monitoring gaps in the first week
   - Team readiness — streaming needs different debugging skills

6. Results & lessons (4 min)
   - Latency: 5 min → 12 seconds
   - Cost: actually cheaper (fewer large batch VMs)
   - Lesson: start with one pipeline, prove the pattern

## TODO
- [ ] Build demo pipeline for live coding section
- [ ] Create before/after architecture diagrams
- [ ] Gather latency metrics screenshots
- [ ] Practice run with team (week of April 15)
