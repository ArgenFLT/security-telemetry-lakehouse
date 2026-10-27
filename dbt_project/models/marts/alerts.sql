-- Unified alert stream: one row per detection hit, common columns across detections.
-- detection_name values must match seeds/attack_techniques.csv for coverage reporting.

select
    first_seen as alert_time,
    'Brute force authentication' as detection_name,
    attack_technique_id,
    severity,
    device_name,
    src_ip,
    coalesce(compromised_user, 'multiple') as user_name,
    failed_attempts::varchar || ' failures, ' || distinct_users::varchar || ' users'
        || case when followed_by_success then ', followed by successful logon' else '' end as details
from {{ ref('detect_bruteforce') }}

union all

select
    event_time as alert_time,
    'Encoded PowerShell command' as detection_name,
    attack_technique_id,
    severity,
    device_name,
    cast(null as varchar) as src_ip,
    actor_user_name as user_name,
    'parent=' || coalesce(process_parent_name, 'unknown') as details
from {{ ref('detect_encoded_powershell') }}
