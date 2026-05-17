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
    include = '/home/emirhan/bitirme/configs/botnet_c2_rules.rules',
}

-- ─── Botnet C2 Inspector ──────────────────────────────
botnet_c2_inspector =
{
    threshold    = 0.50,
    model_path   = "/home/emirhan/bitirme/models/botnet_c2_model.json",
    window_sec   = 120,
    min_syns     = 3,
}

alert_csv = { file = true }
