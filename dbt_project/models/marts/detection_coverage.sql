-- Purple-team style coverage view: for each target ATT&CK technique, is there a
-- detection, and has it fired? Rows with coverage_status = 'gap' are the roadmap.

with techniques as (

    select * from {{ ref('attack_techniques') }}

),

hits as (

    select
        attack_technique_id,
        count(*) as alerts_fired,
        min(alert_time) as first_alert,
        max(alert_time) as last_alert
    from {{ ref('alerts') }}
    group by 1

)

select
    t.technique_id,
    t.technique_name,
    t.tactic,
    t.detection_name,
    t.detection_name is not null as has_detection,
    coalesce(h.alerts_fired, 0) as alerts_fired,
    h.first_alert,
    h.last_alert,
    case
        when t.detection_name is null then 'gap'
        when coalesce(h.alerts_fired, 0) = 0 then 'covered_no_hits'
        else 'covered_firing'
    end as coverage_status
from techniques t
left join hits h on h.attack_technique_id = t.technique_id
order by t.tactic, t.technique_id
