---------------------------------------------------------------------------
-- snort_combined.lua â€” Combined Run Config
-- Bitirme Projesi: IDS Performans KarÅŸÄ±laÅŸtÄ±rma
-- AynÄ± anda: ml_inspector (LSTM) + xgb_inspector (XGBoost) + Community Rules
---------------------------------------------------------------------------

HOME_NET     = 'any'
EXTERNAL_NET = 'any'

include 'snort_defaults.lua'

-- â”€â”€â”€ Inspection â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
stream = { } stream_ip = { } stream_icmp = { }
stream_tcp = { } stream_udp = { } stream_user = { } stream_file = { }

arp_spoof = { } back_orifice = { } dns = { } imap = { }
netflow = { } normalizer = { } pop = { } rpc_decode = { }
sip = { } socks = { } ssh = { } ssl = { } telnet = { }

cip = { } dnp3 = { } iec104 = { } mms = { }
modbus = { } opcua = { } s7commplus = { }

dce_smb = { } dce_tcp = { } dce_udp = { }
dce_http_proxy = { } dce_http_server = { }

gtp_inspect  = default_gtp
port_scan    = default_med_port_scan
smtp         = default_smtp
ftp_server   = default_ftp_server
ftp_client   = { } ftp_data = { }
http_inspect = { } http2_inspect = { }

file_inspect = { rules_file = 'file_magic.rules' }
file_policy  = { }
js_norm      = default_js_norm
appid        = { }

-- â”€â”€â”€ Bindings â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
wizard = default_wizard

binder =
{
    { when = { proto = 'udp', ports = '53',            role='server' }, use = { type = 'dns' } },
    { when = { proto = 'tcp', ports = '53',            role='server' }, use = { type = 'dns' } },
    { when = { proto = 'tcp', ports = '111',           role='server' }, use = { type = 'rpc_decode' } },
    { when = { proto = 'tcp', ports = '502',           role='server' }, use = { type = 'modbus' } },
    { when = { proto = 'tcp', ports = '2123 2152 3386',role='server' }, use = { type = 'gtp_inspect' } },
    { when = { proto = 'tcp', ports = '2404',          role='server' }, use = { type = 'iec104' } },
    { when = { proto = 'udp', ports = '2222',          role='server' }, use = { type = 'cip' } },
    { when = { proto = 'tcp', ports = '4840',          role='server' }, use = { type = 'opcua' } },
    { when = { proto = 'tcp', ports = '44818',         role='server' }, use = { type = 'cip' } },

    { when = { proto = 'tcp', service = 'dcerpc' },  use = { type = 'dce_tcp' } },
    { when = { proto = 'udp', service = 'dcerpc' },  use = { type = 'dce_udp' } },
    { when = { proto = 'udp', service = 'netflow' }, use = { type = 'netflow' } },

    { when = { service = 'netbios-ssn' },     use = { type = 'dce_smb' } },
    { when = { service = 'dce_http_server' }, use = { type = 'dce_http_server' } },
    { when = { service = 'dce_http_proxy' },  use = { type = 'dce_http_proxy' } },

    { when = { service = 'cip' },       use = { type = 'cip' } },
    { when = { service = 'dnp3' },      use = { type = 'dnp3' } },
    { when = { service = 'dns' },       use = { type = 'dns' } },
    { when = { service = 'ftp' },       use = { type = 'ftp_server' } },
    { when = { service = 'ftp-data' },  use = { type = 'ftp_data' } },
    { when = { service = 'gtp' },       use = { type = 'gtp_inspect' } },
    { when = { service = 'imap' },      use = { type = 'imap' } },
    { when = { service = 'http' },      use = { type = 'http_inspect' } },
    { when = { service = 'http2' },     use = { type = 'http2_inspect' } },
    { when = { service = 'iec104' },    use = { type = 'iec104' } },
    { when = { service = 'mms' },       use = { type = 'mms' } },
    { when = { service = 'modbus' },    use = { type = 'modbus' } },
    { when = { service = 'opcua' },     use = { type = 'opcua' } },
    { when = { service = 'pop3' },      use = { type = 'pop' } },
    { when = { service = 'ssh' },       use = { type = 'ssh' } },
    { when = { service = 'sip' },       use = { type = 'sip' } },
    { when = { service = 'smtp' },      use = { type = 'smtp' } },
    { when = { service = 'socks' },     use = { type = 'socks' } },
    { when = { service = 'ssl' },       use = { type = 'ssl' } },
    { when = { service = 'sunrpc' },    use = { type = 'rpc_decode' } },
    { when = { service = 's7commplus' },use = { type = 's7commplus' } },
    { when = { service = 'telnet' },    use = { type = 'telnet' } },

    { use = { type = 'wizard' } }
}

-- â”€â”€â”€ Detection â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
references      = default_references
classifications = default_classifications

ips =
{
    -- enable_builtin_rules: Snort3 decoder/inspector built-in alert'leri
    -- enable_builtin_rules = true,

    -- combined_rules.rules iÃ§inde community rules include edilir.
    -- LSTM (GID=300) ve XGBoost (GID=301) plugin'lerin get_rules() ile register olur.
    include = '/home/emirhan/bitirme/configs/combined_rules.rules',

    variables = default_variables
}

-- â”€â”€â”€ Outputs â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
-- alert_csv'ye tÃ¼m alertler yazÄ±lÄ±r (GID ile ayÄ±rt edilir)
alert_csv = { file = true }

-- â”€â”€â”€ Tweaks â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
if ( tweaks ~= nil ) then
    include(tweaks .. '.lua')
end

-- â”€â”€â”€ ML Inspector (LSTM) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
ml_inspector =
{
    threshold   = 0.55,
    max_packets = 2,
    model_path  = "/home/emirhan/bitirme/models/fine_tuned_lstm_model.tflite",
}

-- â”€â”€â”€ DoS Inspector (per-flow XGBoost, GID:301) â€” v3b (15 features, CIC+UNSW mixed)
dos_inspector =
{
    threshold   = 0.90,
    max_packets = 8,
    model_path  = "/home/emirhan/bitirme/models/dos_fpr_opt_v3b.json",
}

-- â”€â”€â”€ PortScan Inspector (TCP SYN cross-flow) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
portscan_inspector =
{
    threshold    = 0.90,
    model_path   = "/home/emirhan/bitirme/models/portscan_aggregator_model_v4d.json",
    window_sec   = 60,
    min_packets  = 5,
    min_dst_ports = 30,
}

-- â”€â”€â”€ DoS Aggregator (Cross-flow SYN rate) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
dos_aggregator =
{
    threshold    = 0.30,
    model_path   = "/home/emirhan/bitirme/models/dos_aggregator_model.json",
    window_sec   = 60,
    min_syns     = 3,
}

-- â”€â”€â”€ Botnet C2 Inspector (Cross-flow SYN per dst IP) â”€â”€

-- â”€â”€â”€ Bot Client Inspector (Per-src-IP outgoing SYN) â”€â”€
bot_client_inspector =
{
    threshold    = 0.85,
    model_path   = "/home/emirhan/bitirme/models/bot_client_model.json",
    window_sec   = 300,
    min_syns     = 3,
}

-- â”€â”€â”€ Brute Force Inspector (Per-src-IP SYN, GID:307) â”€â”€
bruteforce_inspector =
{
    threshold    = 0.85,
    model_path   = "/home/emirhan/bitirme/models/bruteforce_model.json",
    window_sec   = 60,
    min_syns     = 5,
}
