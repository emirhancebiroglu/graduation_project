export type Engine = "xgboost" | "community" | "portscan" | "dos_agg" | "ddos" | "bot" | "bruteforce";
export type CoreEngine = "xgboost" | "community";

export type ScenarioKey = "dos" | "ddos" | "portscan" | "bruteforce" | "bot";
export type MetricLevel = "flow" | "window";

export type ScenarioConfusion = {
  TP?: number | null;
  FP?: number | null;
  FN?: number | null;
  TN?: number | null;
  TP_windows?: number | null;
  FP_windows?: number | null;
  FN_windows?: number | null;
  TN_windows?: number | null;
};

export type ScenarioMlBlock = {
  alerts: number;
  confusion: ScenarioConfusion;
  accuracy?: number | null;
  precision?: number | null;
  recall?: number | null;
  f1?: number | null;
  fpr?: number | null;
  avg_score?: number | null;
  attacker_ips_detected?: string | null;
  window_recall?: number | null;
  syn_coverage?: number | null;
  target?: string | null;
  dedup_seconds?: number | null;
  attacker_ip_list?: string[] | null;
  windows_per_ip_range?: string | null;
  score_range?: number[] | null;
};

export type ScenarioCommunityBlock = {
  alerts_total_day: number;
  alerts_on_attackers: number;
  fpr: number;
  confusion?: ScenarioConfusion | null;
};

export type ScenarioDisplay = {
  title_key: string;
  attack_label: string;
  dataset_label: string;
  generalization_chip: string;
};

export type ScenarioPayload = {
  key: ScenarioKey;
  pcap_name: string;
  active_engine: Engine;
  metric_level: MetricLevel;
  gt_loader_day: string;
  ml: ScenarioMlBlock;
  community: ScenarioCommunityBlock;
  display: ScenarioDisplay;
};

export type ScenariosListResponse = {
  scenarios: ScenarioPayload[];
  default: ScenarioKey;
};

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
  portscan: EngineEvaluation | null;
  dos_agg: EngineEvaluation | null;
  bot: EngineEvaluation | null;
  bruteforce: EngineEvaluation | null;
  ddos: EngineEvaluation | null;
  community: EngineEvaluation;
  total_flows: number;
};

export type ReplayPhase = "idle" | "running" | "draining" | "complete";

export type WsStatusData = {
  snort_running: boolean;
  pcap_progress: number;
  phase?: ReplayPhase;
  error?: string | null;
};

export type WsMessage =
  | { type: "alert"; engine: Engine; data: Alert }
  | { type: "metric"; engine: Engine; data: Metrics }
  | { type: "status"; data: WsStatusData }
  | { type: "comparison"; data: ComparisonSnapshot }
  | { type: "alert_counts"; data: AlertCounts }
  | { type: "evaluation"; data: EvaluationResult }
  | { type: "alerts_updated"; data: Alert[] };
