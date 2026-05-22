HOME_NET     = 'any'
EXTERNAL_NET = 'any'
include 'snort_defaults.lua'
stream = { } stream_ip = { } stream_icmp = { }
stream_tcp = { } stream_udp = { } stream_user = { } stream_file = { }
netflow = { }
wizard = default_wizard
references      = default_references
classifications = default_classifications
ips = {
    variables = default_variables,
    include = '/home/emirhan/bitirme/configs/dos_aggregator_rules.rules',
}
dos_aggregator =
{
    threshold    = 0.30,
    model_path   = "/home/emirhan/bitirme/models/dos_aggregator_model.json",
    window_sec   = 60,
    min_syns     = 3,
}
alert_csv = { file = true }
