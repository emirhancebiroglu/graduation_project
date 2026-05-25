export type Engine = "xgboost" | "community" | "portscan" | "dos_agg" | "bot" | "bruteforce";
export type CoreEngine = "xgboost" | "community";

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
  ground_truth?: string | null;
  if_score?: number | null;
  if_label?: string | null;
  mitre_technique?: string | null;
  mitre_tactic?: string | null;
};

export type ShapContribution = {
  feature: string;
  description: string;
  raw_value: number;
  shap_value: number;
  direction: "attack" | "benign";
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

export type EngineEvaluation = {
  TP: number;
  TN: number;
  FP: number;
  FN: number;
  accuracy: number;
  precision: number;
  recall: number;
  f1: number;
  fpr: number;
};

export type EvaluationResult = {
  xgboost: EngineEvaluation;
  community: EngineEvaluation;
  total_flows: number;
};

export type WsMessage =
  | { type: "alert"; engine: Engine; data: Alert }
  | { type: "metric"; engine: Engine; data: Metrics }
  | { type: "status"; data: { snort_running: boolean; pcap_progress: number; pcap_replay_wall_s?: number; error?: string | null } }
  | { type: "comparison"; data: ComparisonSnapshot }
  | { type: "alert_counts"; data: AlertCounts }
  | { type: "evaluation"; data: EvaluationResult };
