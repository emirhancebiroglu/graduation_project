---------------------------------------------------------------------------
-- snort_dos_specialist.lua — DoS Specialist Inspector Config
-- Bitirme Projesi: IDS Performans Karşılaştırma
--
-- DoS Specialist (GID=302) tek başına çalışır.
-- Combined run için snort_combined.lua'ya bu bloğu ekle.
--
-- Kullanım:
--   sudo snort \
--       -c /home/emirhan/bitirme/configs/snort_dos_specialist.lua \
--       --plugin-path /home/emirhan/bitirme/plugins/dos_specialist/build \
--       -r /home/emirhan/bitirme/pcaps/Wednesday-WorkingHours.pcap \
--       -A alert_csv \
--       --daq-dir /usr/local/lib/daq \
--       -l /home/emirhan/bitirme/results/dos_specialist/Wednesday-WorkingHours
---------------------------------------------------------------------------

-- 1. Ağ tanımları
HOME_NET     = 'any'
EXTERNAL_NET = 'any'

include 'snort_defaults.lua'

-- 2. Stream reassembly (flow takibi için zorunlu)
stream      = { }
stream_ip   = { }
stream_icmp = { }
stream_tcp  = { }
stream_udp  = { }
stream_user = { }
stream_file = { }

-- 3. Protokol inspectors (mevcut snort_xgb.lua ile aynı set)
arp_spoof    = { }
back_orifice = { }
dns          = { }
imap         = { }
netflow      = { }
normalizer   = { }
pop          = { }
rpc_decode   = { }
sip          = { }
socks        = { }
ssh          = { }
ssl          = { }
telnet       = { }

cip          = { }
dnp3         = { }
iec104       = { }
mms          = { }
modbus       = { }
opcua        = { }
s7commplus   = { }

dce_smb          = { }
dce_tcp          = { }
dce_udp          = { }
dce_http_proxy   = { }
dce_http_server  = { }

gtp_inspect  = default_gtp
port_scan    = default_med_port_scan
smtp         = default_smtp

ftp_server   = default_ftp_server
ftp_client   = { }
ftp_data     = { }

http_inspect = { }
http2_inspect= { }

file_inspect = { rules_file = 'file_magic.rules' }
file_policy  = { }

js_norm      = default_js_norm
appid        = { }

-- 4. Binder & wizard
wizard  = default_wizard

binder =
{
    { when = { proto = 'udp', ports = '53',         role='server'  }, use = { type = 'dns'            } },
    { when = { proto = 'tcp', ports = '53',         role='server'  }, use = { type = 'dns'            } },
    { when = { proto = 'tcp', ports = '111',        role='server'  }, use = { type = 'rpc_decode'     } },
    { when = { proto = 'tcp', ports = '502',        role='server'  }, use = { type = 'modbus'         } },
    { when = { proto = 'tcp', ports = '2123 2152 3386', role='server' }, use = { type = 'gtp_inspect' } },
    { when = { proto = 'tcp', ports = '2404',       role='server'  }, use = { type = 'iec104'         } },
    { when = { proto = 'udp', ports = '2222',       role='server'  }, use = { type = 'cip'            } },
    { when = { proto = 'tcp', ports = '4840',       role='server'  }, use = { type = 'opcua'          } },
    { when = { proto = 'tcp', ports = '44818',      role='server'  }, use = { type = 'cip'            } },
    { when = { proto = 'tcp', service = 'dcerpc'  },                  use = { type = 'dce_tcp'        } },
    { when = { proto = 'udp', service = 'dcerpc'  },                  use = { type = 'dce_udp'        } },
    { when = { proto = 'udp', service = 'netflow' },                  use = { type = 'netflow'        } },
    { when = { service = 'netbios-ssn'            },                  use = { type = 'dce_smb'        } },
    { when = { service = 'dce_http_server'        },                  use = { type = 'dce_http_server'} },
    { when = { service = 'dce_http_proxy'         },                  use = { type = 'dce_http_proxy' } },
    { when = { service = 'cip'       }, use = { type = 'cip'        } },
    { when = { service = 'dnp3'      }, use = { type = 'dnp3'       } },
    { when = { service = 'dns'       }, use = { type = 'dns'        } },
    { when = { service = 'ftp'       }, use = { type = 'ftp_server' } },
    { when = { service = 'ftp-data'  }, use = { type = 'ftp_data'   } },
    { when = { service = 'gtp'       }, use = { type = 'gtp_inspect'} },
    { when = { service = 'imap'      }, use = { type = 'imap'       } },
    { when = { service = 'http'      }, use = { type = 'http_inspect'} },
    { when = { service = 'http2'     }, use = { type = 'http2_inspect'} },
    { when = { service = 'iec104'    }, use = { type = 'iec104'     } },
    { when = { service = 'mms'       }, use = { type = 'mms'        } },
    { when = { service = 'modbus'    }, use = { type = 'modbus'     } },
    { when = { service = 'opcua'     }, use = { type = 'opcua'      } },
    { when = { service = 'pop3'      }, use = { type = 'pop'        } },
    { when = { service = 'ssh'       }, use = { type = 'ssh'        } },
    { when = { service = 'sip'       }, use = { type = 'sip'        } },
    { when = { service = 'smtp'      }, use = { type = 'smtp'       } },
    { when = { service = 'socks'     }, use = { type = 'socks'      } },
    { when = { service = 'ssl'       }, use = { type = 'ssl'        } },
    { when = { service = 'sunrpc'    }, use = { type = 'rpc_decode' } },
    { when = { service = 's7commplus'}, use = { type = 's7commplus' } },
    { when = { service = 'telnet'    }, use = { type = 'telnet'     } },
    { use = { type = 'wizard' } }
}

-- 5. IPS rules (DoS Specialist GID=302 stub rules — plugin kendi register eder)
references      = default_references
classifications = default_classifications

ips =
{
    -- [VARSAYIM] dos_specialist_rules.rules dosyası GID=302 alertleri için
    -- placeholder. Plugin get_rules() ile kendi kurallarını register eder,
    -- bu dosyada kural tanımlamaya gerek yok — boş da olabilir.
    include  = '/home/emirhan/bitirme/configs/dos_specialist_rules.rules',
    variables = default_variables
}

-- 6. Alert çıktısı (confusion matrix için alert_csv zorunlu)
alert_csv = { file = true, }

-- 7. Tweaks (opsiyonel)
if ( tweaks ~= nil ) then
    include(tweaks .. '.lua')
end

-- =============================================
-- DoS Specialist Inspector (bitirme projesi)
-- GID=302 | mp_2 varyantı | threshold=0.50
-- =============================================
dos_specialist =
{
    threshold   = 0.50,
    max_packets = 2,
    model_path  = "/home/emirhan/bitirme/models/dos_specialist/mp_2_xgb_model.json",
}