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
    include = '/home/emirhan/bitirme/configs/bot_client_rules.rules',
}

-- ─── Bot Client Inspector ─────────────────────────────
bot_client_inspector =
{
    threshold    = 0.95,
    model_path   = "/home/emirhan/bitirme/models/bot_client_model.json",
    window_sec   = 300,
    min_syns     = 3,
}

alert_csv = { file = true }
