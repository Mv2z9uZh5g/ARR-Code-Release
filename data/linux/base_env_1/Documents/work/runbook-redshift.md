# Runbook: Redshift Cluster Operations

## Connection details
- Cluster: datacorp-analytics
- Endpoint: datacorp-analytics.c9xyzabc.us-west-2.redshift.amazonaws.com:5439
- Admin access: via AWS SSO (DataEngineer role)

## Common operations

### Check running queries
```sql
SELECT pid, user_name, query, starttime, duration
FROM stv_recents
WHERE status = 'Running'
ORDER BY starttime DESC;
```

### Kill a long-running query
```sql
SELECT pg_terminate_backend(pid);
```

### Check disk usage
```sql
SELECT name, count(*) as num_tables,
       sum(size) as total_size_mb
FROM svv_table_info
GROUP BY name
ORDER BY total_size_mb DESC;
```

### Vacuum and analyze
```sql
VACUUM FULL analytics.daily_user_events;
ANALYZE analytics.daily_user_events;
```

### Check WLM queue status
```sql
SELECT * FROM stv_wlm_service_class_state;
```

## Scaling
- Current: 3x ra3.xlplus nodes
- To resize: AWS Console → Redshift → Clusters → Modify
- Classic resize takes ~30 min, elastic resize takes ~5 min
- Always resize during off-peak hours (after 10 PM Pacific)

## Alerts
- DiskSpacePercentage > 80%: vacuum tables, check for runaway COPY jobs
- QueryDuration > 300s: check stv_recents for the culprit
- ConnectionCount > 400: check for connection leaks in the API
