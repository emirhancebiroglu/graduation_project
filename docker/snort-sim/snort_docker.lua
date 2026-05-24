---------------------------------------------------------------------------
-- snort_docker.lua — Docker simulation config
-- Production-equivalent of snort_dos.lua for container validation
---------------------------------------------------------------------------

HOME_NET     = '172.20.0.0/24'
EXTERNAL_NET = 'any'

include '/usr/local/etc/snort/snort_defaults.lua'

stream      = { }
stream_ip   = { }
stream_icmp = { }
stream_tcp  = { }
stream_udp  = { }
stream_user = { }
stream_file = { }

arp_spoof   = { }
back_orifice = { }
dns         = { }
imap        = { }
netflow     = { }
normalizer  = { }
pop         = { }
rpc_decode  = { }
sip         = { }
socks       = { }
ssh         = { }
ssl         = { }
telnet      = { }

cip         = { }
dnp3        = { }
iec104      = { }
mms         = { }
modbus      = { }
opcua       = { }
s7commplus  = { }

dce_smb         = { }
dce_tcp         = { }
dce_udp         = { }
dce_http_proxy  = { }
dce_http_server = { }

gtp_inspect = default_gtp
port_scan   = default_med_port_scan
smtp        = default_smtp

ftp_server = default_ftp_server
ftp_client = { }
ftp_data   = { }

http_inspect  = { }
http2_inspect = { }

file_inspect = { rules_file = 'file_magic.rules' }
file_policy  = { }

js_norm = default_js_norm

appid = { }

wizard = default_wizard

binder =
{
    { when = { proto = 'udp', ports = '53', role='server' },  use = { type = 'dns' } },
    { when = { proto = 'tcp', ports = '53', role='server' },  use = { type = 'dns' } },
    { when = { proto = 'tcp', ports = '111', role='server' }, use = { type = 'rpc_decode' } },
    { when = { proto = 'tcp', ports = '502', role='server' }, use = { type = 'modbus' } },
    { when = { proto = 'tcp', ports = '2404', role='server' }, use = { type = 'iec104' } },
    { when = { service = 'netbios-ssn' },      use = { type = 'dce_smb' } },
    { when = { service = 'ftp' },              use = { type = 'ftp_server' } },
    { when = { service = 'ftp-data' },         use = { type = 'ftp_data' } },
    { when = { service = 'imap' },             use = { type = 'imap' } },
    { when = { service = 'http' },             use = { type = 'http_inspect' } },
    { when = { service = 'http2' },            use = { type = 'http2_inspect' } },
    { when = { service = 'pop3' },             use = { type = 'pop' } },
    { when = { service = 'ssh' },              use = { type = 'ssh' } },
    { when = { service = 'smtp' },             use = { type = 'smtp' } },
    { when = { service = 'ssl' },              use = { type = 'ssl' } },
    { when = { service = 'telnet' },           use = { type = 'telnet' } },
    { use = { type = 'wizard' } }
}

references      = default_references
classifications = default_classifications

ips =
{
    variables = default_variables,
    include   = '/home/emirhan/bitirme/docker/snort-sim/docker_rules.rules',
}

alert_csv = { file = true, limit = 0 }

event_queue =
{
    max_queue    = 1024,
    log          = 1024,
    order_events = 'priority',
}

-- ─── DoS Inspector (per-flow XGBoost, GID:301) ──────────────────
dos_inspector =
{
    threshold   = 0.90,
    max_packets = 8,
    model_path  = "/home/emirhan/bitirme/models/dos_fpr_opt_v3b.json",
}

-- ─── DoS Aggregator (cross-flow SYN rate, GID:303) ──────────────
dos_aggregator =
{
    model_path   = "/home/emirhan/bitirme/models/dos_aggregator_model.json",
    window_sec   = 60,
    threshold    = 0.30,
}

-- ─── PortScan Inspector (GID:302) ───────────────────────────────
portscan_inspector =
{
    threshold    = 0.90,
    model_path   = "/home/emirhan/bitirme/models/portscan_aggregator_model_v4d.json",
    window_sec   = 60,
}

-- ─── Bot Client Inspector (GID:306) ─────────────────────────────
bot_client_inspector =
{
    threshold    = 0.85,
    model_path   = "/home/emirhan/bitirme/models/bot_client_model.json",
    window_sec   = 300,
}

-- ─── Bruteforce Inspector (GID:307) ─────────────────────────────
bruteforce_inspector =
{
    threshold    = 0.85,
    model_path   = "/home/emirhan/bitirme/models/bruteforce_model.json",
    window_sec   = 60,
}
