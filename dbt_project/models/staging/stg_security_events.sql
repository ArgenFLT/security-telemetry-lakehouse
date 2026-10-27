-- Staging view over the Parquet lakehouse (hive-partitioned by event_date).
select
    event_uid,
    "time" as event_time,
    cast(event_date as date) as event_date,
    class_uid,
    class_name,
    activity_name,
    status,
    severity_id,
    device_name,
    device_ip,
    src_ip,
    actor_user_name,
    target_user_name,
    auth_protocol,
    process_name,
    process_cmd_line,
    process_parent_name,
    rule_id,
    rule_description,
    rule_level,
    attack_technique_ids
from read_parquet('{{ var("lakehouse_path") }}/**/*.parquet', hive_partitioning = true)
