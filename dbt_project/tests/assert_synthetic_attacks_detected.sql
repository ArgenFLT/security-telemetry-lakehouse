{{ config(tags=['synthetic']) }}

-- Detection regression test for the bundled synthetic dataset.
-- Returns a row (= test failure) for every injected scenario that was NOT detected.
-- Skip it on real data with: dbt build --exclude tag:synthetic

select 'ssh brute force followed by success' as missing_detection
where not exists (
    select 1 from {{ ref('detect_bruteforce') }}
    where src_ip = '203.0.113.45' and followed_by_success
)

union all

select 'windows brute force against dc-01'
where not exists (
    select 1 from {{ ref('detect_bruteforce') }}
    where src_ip = '198.51.100.77' and device_name = 'dc-01'
)

union all

select 'office-spawned encoded powershell'
where not exists (
    select 1 from {{ ref('detect_encoded_powershell') }}
    where parent_is_office and severity = 'critical'
)
