# Database Migration Plan — Q4 2023

## Overview
Migrating from self-managed PostgreSQL on EC2 to Amazon RDS.

## Timeline
- Week 1: Set up RDS instance, configure networking
- Week 2: Set up DMS replication, validate data
- Week 3: Application testing against new instance
- Week 4: Cutover weekend

## Checklist
- [x] RDS instance provisioned (db.r6g.large)
- [x] Security groups configured
- [x] DMS replication task created
- [x] Initial full load completed
- [x] CDC replication running and stable
- [x] Application config updated for dual-write
- [x] Load testing on RDS
- [x] Cutover completed (Nov 18, 2023)
- [x] Old EC2 instance decommissioned (Dec 2, 2023)

## Notes
- Had to increase max_connections on RDS from default 100 to 200
- Cutover took 12 minutes of downtime (within the 15-min window)
- One issue: sequences were off after migration, fixed with setval()
