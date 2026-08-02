#!/usr/bin/env python3
"""Quick script to check partition sizes on the clickstream topic."""

import json
from confluent_kafka import Consumer, TopicPartition

conf = {
    "bootstrap.servers": "localhost:9092",
    "group.id": "debug-check",
    "auto.offset.reset": "earliest",
}

consumer = Consumer(conf)
topic = "user.clickstream.v2"

metadata = consumer.list_topics(topic)
partitions = metadata.topics[topic].partitions

print(f"Topic: {topic}")
print(f"Partitions: {len(partitions)}")
print()

for pid in sorted(partitions.keys()):
    tp = TopicPartition(topic, pid)
    low, high = consumer.get_watermark_offsets(tp, timeout=5)
    print(f"  Partition {pid}: {high - low:,} messages (offsets {low} - {high})")

consumer.close()
