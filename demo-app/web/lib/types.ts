export type Engine = "xgboost" | "community";

export type Alert = {
  id: string;
  ts: string;
  engine: Engine;
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  proto: "TCP" | "UDP" | "ICMP";
  gid: number;
  sid: number;
  msg: string;
  score?: number;
};

export type Metrics = {
  total_alerts: number;
  alerts_per_sec: number;
  unique_attackers: number;
  flagged_flows: number;
};

export type ComparisonSnapshot = {
  xgboost: { alerts: number; first_alert_ms: number | null };
  community: { alerts: number; first_alert_ms: number | null };
  pcap_elapsed_ms: number;
};

export type AlertCounts = {
  xgboost_file_count: number;
  community_file_count: number;
};

export type WsMessage =
  | { type: "alert"; engine: Engine; data: Alert }
  | { type: "metric"; engine: Engine; data: Metrics }
  | { type: "status"; data: { snort_running: boolean; pcap_progress: number; error?: string | null } }
  | { type: "comparison"; data: ComparisonSnapshot }
  | { type: "alert_counts"; data: AlertCounts };
