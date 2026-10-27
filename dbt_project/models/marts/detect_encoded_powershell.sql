-- Detection: PowerShell launched with an encoded command (MITRE ATT&CK T1059.001).
-- Severity depends on the parent process: Office applications spawning PowerShell
-- are a classic phishing/macro execution pattern.

with candidates as (

    select
        event_time,
        device_name,
        actor_user_name,
        process_name,
        process_parent_name,
        process_cmd_line,
        lower(process_parent_name) in ('winword.exe', 'excel.exe', 'outlook.exe', 'powerpnt.exe')
            as parent_is_office
    from {{ ref('stg_security_events') }}
    where class_name = 'Process Activity'
      and lower(process_name) = 'powershell.exe'
      and regexp_matches(lower(process_cmd_line), '-(enc|encodedcommand|e)\s+[a-z0-9+/=]{20,}')

)

select
    *,
    'T1059.001' as attack_technique_id,
    case when parent_is_office then 'critical' else 'medium' end as severity
from candidates
