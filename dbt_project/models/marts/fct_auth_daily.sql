-- Daily authentication facts per host: volume, failure rate and source diversity.

select
    event_date,
    device_name,
    count(*) as auth_events,
    count(*) filter (where status = 'Success') as successes,
    count(*) filter (where status = 'Failure') as failures,
    round(count(*) filter (where status = 'Failure') * 1.0 / count(*), 4) as failure_rate,
    count(distinct src_ip) as distinct_sources,
    count(distinct target_user_name) as distinct_users
from {{ ref('stg_security_events') }}
where class_name = 'Authentication'
group by 1, 2
