-- Detection: >= N failed authentications from one source IP against one host inside a
-- 10-minute tumbling window (MITRE ATT&CK T1110). If the same source later logs in
-- successfully, the alert is escalated to critical (likely compromised account).
--
-- Known limitation: tumbling windows can split an attack that straddles a boundary.
-- A sliding window is a natural next iteration.

with failures as (

    select
        src_ip,
        device_name,
        time_bucket(interval '10 minutes', event_time) as window_start,
        count(*) as failed_attempts,
        count(distinct target_user_name) as distinct_users,
        min(event_time) as first_seen,
        max(event_time) as last_seen
    from {{ ref('stg_security_events') }}
    where class_name = 'Authentication'
      and status = 'Failure'
      and src_ip is not null
    group by 1, 2, 3
    having count(*) >= {{ var('bruteforce_threshold') }}

),

successes as (

    select
        src_ip,
        device_name,
        event_time as success_time,
        target_user_name as compromised_user
    from {{ ref('stg_security_events') }}
    where class_name = 'Authentication'
      and status = 'Success'
      and src_ip is not null

)

select
    f.window_start,
    f.first_seen,
    f.last_seen,
    f.src_ip,
    f.device_name,
    f.failed_attempts,
    f.distinct_users,
    s.success_time,
    s.compromised_user,
    s.success_time is not null as followed_by_success,
    'T1110' as attack_technique_id,
    case when s.success_time is not null then 'critical' else 'high' end as severity
from failures f
left join successes s
    on s.src_ip = f.src_ip
   and s.device_name = f.device_name
   and s.success_time between f.first_seen and f.last_seen + interval '15 minutes'
qualify row_number() over (
    partition by f.src_ip, f.device_name, f.window_start
    order by s.success_time
) = 1
