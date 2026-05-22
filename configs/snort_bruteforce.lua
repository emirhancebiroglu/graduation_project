HOME_NET     = 'any'
EXTERNAL_NET = 'any'

include 'snort_defaults.lua'

stream = { } stream_ip = { } stream_icmp = { }
stream_tcp = { } stream_udp = { } stream_user = { } stream_file = { }

netflow = { }

wizard = default_wizard

references      = default_references
classifications = default_classifications

ips =
{
    variables = default_variables,
    include = '/home/emirhan/bitirme/configs/bruteforce_rules.rules',
}

-- ─── Brute Force Inspector ──────────────────────────
bruteforce_inspector =
{
    threshold    = 0.95,
    model_path   = "/home/emirhan/bitirme/models/bruteforce_model.json",
    window_sec   = 60,
    min_syns     = 5,
}

alert_csv = { file = true }
