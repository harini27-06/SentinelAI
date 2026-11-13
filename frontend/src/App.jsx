import { Fragment, useCallback, useEffect, useRef, useState } from "react";
import { NavLink, Route, Routes, useLocation } from "react-router-dom";
import {
  Activity, AlertTriangle, ArrowDownRight, ArrowUpRight, Bot, Check, ChevronDown, CircleHelp,
  Clock3, Cpu, Database, FileSearch, Filter, Gauge, Globe2, LayoutDashboard,
  LoaderCircle, LockKeyhole, Menu, Play, RefreshCw, Search, Settings as SettingsIcon,
  Shield, ShieldAlert, ShieldCheck, SlidersHorizontal, Sparkles, X,
} from "lucide-react";
import {
  Area, AreaChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import { get, patch, post } from "./services/api";

const navItems = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard, end: true },
  { to: "/endpoints", label: "Endpoints & Agents", icon: Bot },
  { to: "/alerts", label: "Threat Alerts", icon: ShieldAlert },
  { to: "/simulation", label: "Simulation Center", icon: Play },
  { to: "/analysis", label: "AI Analysis", icon: Sparkles },
  { to: "/analytics", label: "Analytics", icon: Activity },
  { to: "/settings", label: "Settings", icon: SettingsIcon },
];

const titleByPath = Object.fromEntries(navItems.map(({ to, label }) => [to, label]));
const scenarios = [
  ["normal_login", "Normal Login Activity", "login_agent"],
  ["brute_force_login", "Brute-Force-Like Login Activity", "login_agent"],
  ["normal_network", "Normal Network Traffic", "network_agent"],
  ["dos_spike", "DoS-Like Traffic Spike", "network_agent"],
  ["api_burst", "Suspicious API Request Burst", "api_agent"],
  ["file_burst", "Unusual File Modification Burst", "file_agent"],
  ["system_activity", "Unusual System Activity", "system_agent"],
  ["novel_combination", "Novel Behavioral Combination", "correlation_agent"],
];
const severityColors = { critical: "red", high: "orange", medium: "yellow", low: "green", info: "blue" };

function listOf(value, ...keys) {
  if (Array.isArray(value)) return value;
  for (const key of keys) if (Array.isArray(value?.[key])) return value[key];
  return [];
}
function numberOf(value, ...keys) {
  for (const key of keys) if (Number.isFinite(Number(value?.[key]))) return Number(value[key]);
  return 0;
}
function metricValue(value, ...keys) {
  return value == null ? "—" : numberOf(value, ...keys);
}
function readable(value) {
  return String(value ?? "—").replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}
function dateOf(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
}
function severityOf(item) {
  return String(item?.severity || item?.risk_level || item?.status || "low").toLowerCase().replaceAll("_", " ").replace(" risk", "");
}

function useResource(loader, dependencies = [], interval = 0) {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const refresh = useCallback(async () => {
    try {
      setError("");
      const result = await loader();
      setData(result);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Unable to load data.");
    } finally {
      setLoading(false);
    }
  // loader is expected to be stable for the lifetime of the page.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, dependencies);
  useEffect(() => {
    refresh();
    if (!interval) return undefined;
    const timer = window.setInterval(refresh, interval);
    return () => window.clearInterval(timer);
  }, [refresh, interval]);
  return { data, error, loading, refresh };
}

function IconButton({ children, onClick, title, disabled = false }) {
  return <button className="icon-button" title={title} aria-label={title} onClick={onClick} disabled={disabled}>{children}</button>;
}
function PageHeader({ eyebrow, title, description, actions }) {
  return <div className="page-header"><div><div className="eyebrow">{eyebrow}</div><h1>{title}</h1><p>{description}</p></div><div className="header-actions">{actions}</div></div>;
}
function ErrorBanner({ error, retry }) {
  if (!error) return null;
  return <div className="error-banner" role="alert"><AlertTriangle size={17} /><span>{error}</span>{retry && <button onClick={retry}>Retry</button>}</div>;
}
function Loading({ label = "Loading data…" }) {
  return <div className="loading"><LoaderCircle className="spin" size={20} />{label}</div>;
}
function Empty({ title = "No data yet", children, action }) {
  return <div className="empty-state"><div className="empty-icon"><Database size={22} /></div><strong>{title}</strong><p>{children}</p>{action}</div>;
}
function Badge({ value, kind = "severity" }) {
  const tone = kind === "severity" ? severityColors[severityOf({ severity: value })] || "blue" : "neutral";
  return <span className={`badge ${tone}`}>{readable(value)}</span>;
}
function Card({ title, icon: Icon, action, children, className = "" }) {
  return <section className={`card ${className}`}><div className="card-heading"><div className="card-title">{Icon && <Icon size={16} />}<h2>{title}</h2></div>{action}</div>{children}</section>;
}
function Metric({ label, value, note, icon: Icon, accent = "blue" }) {
  return <div className={`metric-card ${accent}`}><div className="metric-top"><span>{label}</span><Icon size={17} /></div><strong>{value}</strong><small>{note}</small></div>;
}
function Table({ columns, rows, emptyText = "No matching records" }) {
  if (!rows.length) return <Empty>{emptyText}</Empty>;
  return <div className="table-scroll"><table><thead><tr>{columns.map((column) => <th key={column.key}>{column.label}</th>)}</tr></thead><tbody>
    {rows.map((row, index) => <tr key={row.id || row.event_id || row.alert_id || index}>{columns.map((column) => <td key={column.key}>{column.render ? column.render(row) : (row[column.key] ?? "—")}</td>)}</tr>)}
  </tbody></table></div>;
}
function Pagination({ page, pageSize, total, onPageChange, loading = false }) {
  const pageCount = Math.max(1, Math.ceil(total / pageSize));
  if (pageCount <= 1) return null;
  const firstItem = page * pageSize + 1;
  const lastItem = Math.min((page + 1) * pageSize, total);
  return <div className="pagination">
    <span>Showing {firstItem}-{lastItem} of {total} · Page {page + 1} of {pageCount}</span>
    <div>
      <button type="button" disabled={loading || page === 0} onClick={() => onPageChange(page - 1)}>Previous</button>
      <button type="button" disabled={loading || page + 1 >= pageCount} onClick={() => onPageChange(page + 1)}>Next</button>
    </div>
  </div>;
}
function ChartTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null;
  return <div className="chart-tooltip"><strong>{label}</strong>{payload.map((point) => <div key={point.name}>{point.name}: {point.value}</div>)}</div>;
}

function Shell({ children, health }) {
  const [menuOpen, setMenuOpen] = useState(false);
  const location = useLocation();
  const title = titleByPath[location.pathname] || "Security Operations";
  return <div className="app-shell">
    {menuOpen && <button className="scrim" onClick={() => setMenuOpen(false)} aria-label="Close navigation" />}
    <aside className={`sidebar ${menuOpen ? "open" : ""}`}>
      <div className="brand"><div className="brand-mark"><Shield size={20} /></div><div><strong>sentinel<span>ai</span></strong><small>SECURITY OPERATIONS</small></div><button className="mobile-close" onClick={() => setMenuOpen(false)} aria-label="Close menu"><X size={18} /></button></div>
      <div className="workspace-label">WORKSPACE</div>
      <nav>{navItems.map(({ to, label, icon: Icon, end }) => <NavLink key={to} to={to} end={end} onClick={() => setMenuOpen(false)} className={({ isActive }) => `nav-link ${isActive ? "active" : ""}`}><Icon size={17} /><span>{label}</span>{label === "Threat Alerts" && <span className="nav-indicator" />}</NavLink>)}</nav>
      <div className="sidebar-bottom"><div className="environment"><span className="live-dot" /><div><strong>Local simulation</strong><small>Synthetic events only</small></div></div><div className="sidebar-foot">SENTINELAI <span>v1.0</span></div></div>
    </aside>
    <main className="main-area"><header className="topbar"><div className="topbar-left"><button className="menu-toggle" onClick={() => setMenuOpen(true)} aria-label="Open navigation"><Menu size={19} /></button><div className="breadcrumb">SentinelAI <span>/</span> <strong>{title}</strong></div></div><div className="topbar-right"><span className={`health-pill ${health ? "ok" : "unknown"}`}><span className="live-dot" />{health ? "API connected" : "API unavailable"}</span><div className="avatar">SA</div></div></header>{children}</main>
  </div>;
}

function Dashboard() {
  const stats = useResource(() => get("/dashboard/stats"), [], 15000);
  const events = useResource(() => get("/events?limit=8"), [], 15000);
  const alerts = useResource(() => get("/alerts?limit=6"), [], 15000);
  const models = useResource(() => get("/models/status"), [], 30000);
  const s = stats.data || {};
  const eventRows = listOf(events.data, "items", "events", "results");
  const alertRows = listOf(alerts.data, "items", "alerts", "results");
  const healthValue = s.health || s.system_health || (stats.data ? "Unknown" : "Unavailable");
  const severityData = ["critical", "high", "medium", "low"].map((name) => ({ name: readable(name), value: numberOf(s.alerts_by_severity || s, name, `${name}_alerts`) })).filter((item) => item.value > 0);
  const trend = listOf(s.threat_activity || s.activity_over_time || s.event_trend);
  const modelList = models.data?.models || models.data || {};
  return <div className="page">
    <PageHeader eyebrow="OVERVIEW · LIVE MONITORING" title="Security dashboard" description="A clear view of your synthetic environment and current detection activity." actions={<IconButton title="Refresh dashboard" onClick={() => { stats.refresh(); events.refresh(); alerts.refresh(); models.refresh(); }}><RefreshCw size={17} /></IconButton>} />
    <ErrorBanner error={stats.error || events.error || alerts.error || models.error} retry={() => { stats.refresh(); events.refresh(); alerts.refresh(); models.refresh(); }} />
    <div className="health-banner"><div className="health-symbol"><ShieldCheck size={19} /></div><div><strong>{readable(healthValue)} <span className="separator-dot">·</span> Synthetic monitoring mode</strong><p>Simulated agents analyze synthetic events; no real endpoints are connected.</p></div><span className="health-tag"><span className="live-dot" />SYSTEM HEALTH</span></div>
    <div className="metrics-grid">
      <Metric label="Endpoints" value={metricValue(stats.data, "endpoint_count", "endpoints")} note="Simulated endpoints" icon={Globe2} accent="cyan" />
      <Metric label="Active agents" value={metricValue(stats.data, "active_agents", "agent_count")} note="In-process simulated agents" icon={Bot} accent="green" />
      <Metric label="Events processed" value={metricValue(stats.data, "events_processed", "total_events", "event_count")} note="Persisted event records" icon={Activity} accent="blue" />
      <Metric label="Open alerts" value={metricValue(stats.data, "open_alerts", "alert_count", "total_alerts")} note="Requires analyst review" icon={AlertTriangle} accent="orange" />
    </div>
    <div className="content-grid two">
      <Card title="Threat activity" icon={Activity} action={<span className="card-meta">Recent activity</span>}>
        {trend.length ? <div className="chart-wrap"><ResponsiveContainer width="100%" height={230}><AreaChart data={trend}><defs><linearGradient id="activityFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#38bdf8" stopOpacity={0.28} /><stop offset="95%" stopColor="#38bdf8" stopOpacity={0} /></linearGradient></defs><CartesianGrid stroke="#202a3a" vertical={false} /><XAxis dataKey="date" tickLine={false} axisLine={false} tick={{ fill: "#738198", fontSize: 11 }} /><YAxis tickLine={false} axisLine={false} tick={{ fill: "#738198", fontSize: 11 }} /><Tooltip content={<ChartTooltip />} /><Area type="monotone" dataKey="events" stroke="#38bdf8" fill="url(#activityFill)" strokeWidth={2} /><Area type="monotone" dataKey="alerts" stroke="#fb7185" fill="transparent" strokeWidth={2} /></AreaChart></ResponsiveContainer></div> : <Empty title="Activity will appear here">Run a simulation or send synthetic events to see activity over time.</Empty>}
      </Card>
      <Card title="Alerts by severity" icon={ShieldAlert} action={<span className="card-meta">Current totals</span>}>
        {severityData.length ? <div className="severity-chart"><ResponsiveContainer width="58%" height={205}><PieChart><Pie data={severityData} dataKey="value" nameKey="name" innerRadius={56} outerRadius={78} paddingAngle={4}>{severityData.map((item, index) => <Cell key={item.name} fill={["#fb7185", "#fb923c", "#facc15", "#34d399"][index]} />)}</Pie><Tooltip content={<ChartTooltip />} /></PieChart></ResponsiveContainer><div className="severity-legend">{severityData.map((item) => <div key={item.name}><i className={`legend-dot ${item.name.toLowerCase()}`} /><span>{item.name}</span><strong>{item.value}</strong></div>)}</div></div> : <Empty title="No alerts recorded">Severity counts will populate when events generate alert findings.</Empty>}
      </Card>
    </div>
    <div className="content-grid two lower-grid">
      <Card title="Recent events" icon={Clock3} action={<NavLink className="text-link" to="/analysis">View analysis <ArrowUpRight size={13} /></NavLink>}>
        {events.loading ? <Loading /> : <Table rows={eventRows.slice(0, 6)} columns={[
          { key: "event_type", label: "Event" }, { key: "endpoint_id", label: "Endpoint" },
          { key: "timestamp", label: "Time", render: (row) => dateOf(row.timestamp || row.created_at) },
          { key: "severity", label: "Severity", render: (row) => <Badge value={row.severity || row.outcome || "low"} /> },
        ]} />}
      </Card>
      <Card title="Recent alerts" icon={AlertTriangle} action={<NavLink className="text-link" to="/alerts">All alerts <ArrowUpRight size={13} /></NavLink>}>
        {alerts.loading ? <Loading /> : <Table rows={alertRows.slice(0, 6)} columns={[
          { key: "title", label: "Finding", render: (row) => row.title || row.message || row.alert_type || "Detection alert" },
          { key: "severity", label: "Severity", render: (row) => <Badge value={row.severity || row.risk_level} /> },
          { key: "status", label: "Status", render: (row) => <Badge value={row.status || "open"} kind="neutral" /> },
        ]} />}
      </Card>
    </div>
    <Card title="Detection models" icon={Cpu} className="models-card">
      <div className="model-row">{Object.entries(modelList).map(([key, value]) => {
        const available = typeof value === "object" ? Boolean(value.available) : Boolean(value);
        return <div className="model-item" key={key}><div className={`model-icon ${available ? "available" : ""}`}><Cpu size={17} /></div><div><strong>{readable(typeof value === "object" ? (value.name || key) : key)}</strong><small>{available ? "Artifact available" : "Unavailable · train model to enable"}</small></div><span className={`model-status ${available ? "available" : ""}`}><i />{available ? "Available" : "Unavailable"}</span></div>;
      })}</div>
    </Card>
  </div>;
}

function Endpoints() {
  const [selectedEndpoint, setSelectedEndpoint] = useState("");
  const endpointDetailRef = useRef(null);
  const resource = useResource(async () => {
    const [agentData, endpointData] = await Promise.all([get("/agents"), get("/endpoints")]);
    return { agents: listOf(agentData, "agents"), endpoints: listOf(endpointData, "endpoints") };
  }, []);
  const endpointDetail = useResource(
    () => selectedEndpoint ? get(`/endpoints/${encodeURIComponent(selectedEndpoint)}`) : Promise.resolve(null),
    [selectedEndpoint],
  );
  useEffect(() => {
    if (!selectedEndpoint) return;
    endpointDetailRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  }, [selectedEndpoint]);
  const agents = listOf(resource.data, "agents");
  const endpoints = listOf(resource.data, "endpoints");
  return <div className="page"><PageHeader eyebrow="SIMULATED FLEET" title="Endpoints & agents" description="Agent activity running inside this local application. These are not real endpoint collectors." actions={<IconButton title="Refresh agents" onClick={resource.refresh}><RefreshCw size={17} /></IconButton>} /><ErrorBanner error={resource.error} retry={resource.refresh} />
    <div className="notice blue-notice"><CircleHelp size={17} /><span>SentinelAI currently simulates all agents in one backend process. No computers are connected or protected.</span></div>
    {selectedEndpoint && <div ref={endpointDetailRef} className="endpoint-details-panel"><Card title={`Endpoint details · ${selectedEndpoint}`} icon={FileSearch} action={<IconButton title="Close endpoint details" onClick={() => setSelectedEndpoint("")}><X size={15} /></IconButton>}>{endpointDetail.loading ? <Loading /> : endpointDetail.error ? <ErrorBanner error={endpointDetail.error} retry={endpointDetail.refresh} /> : <div className="endpoint-detail-content">
      <div><strong>{endpointDetail.data?.hostname || selectedEndpoint}</strong><small>endpoint</small></div>
      <div><strong>{readable(endpointDetail.data?.platform || "Simulated")}</strong><small>platform</small></div>
      <div><strong>{readable(endpointDetail.data?.status || "unknown")}</strong><small>status</small></div>
      <div><strong>{numberOf(endpointDetail.data, "event_count")}</strong><small>total events</small></div>
      <div><strong>{listOf(endpointDetail.data, "agent_types").map(readable).join(", ") || "No agents yet"}</strong><small>agents observed</small></div>
      <Card title="Recent events" icon={Activity}><Table rows={listOf(endpointDetail.data, "events").slice(0, 10)} emptyText="No events recorded for this endpoint." columns={[
        { key: "event_type", label: "Event" },
        { key: "agent_type", label: "Agent", render: (row) => readable(row.agent_type) },
        { key: "timestamp", label: "Time", render: (row) => dateOf(row.timestamp) },
        { key: "severity", label: "Severity", render: (row) => <Badge value={row.severity || "info"} /> },
      ]} /></Card>
      <Card title="Related alerts" icon={ShieldAlert}><Table rows={listOf(endpointDetail.data, "alerts").slice(0, 10)} emptyText="No alerts recorded for this endpoint." columns={[
        { key: "title", label: "Alert", render: (row) => row.title || row.message || "Security finding" },
        { key: "severity", label: "Severity", render: (row) => <Badge value={row.severity || "info"} /> },
        { key: "status", label: "Status", render: (row) => <Badge value={row.status || "open"} kind="neutral" /> },
        { key: "created_at", label: "Detected", render: (row) => dateOf(row.created_at || row.timestamp) },
      ]} /></Card>
    </div>}</Card></div>}
    {resource.loading ? <Loading /> : agents.length ? <div className="endpoint-grid">
      {endpoints.length ? endpoints.map((endpoint) => {
        const endpointAgents = agents.filter((agent) => (endpoint.agent_types || []).includes(agent.agent_type));
        return <Card title={endpoint.endpoint_id || endpoint.id} icon={Globe2} key={endpoint.endpoint_id || endpoint.id}>
          <div className="endpoint-summary"><span><Activity size={14} /> {numberOf(endpoint, "event_count")} events · last seen {dateOf(endpoint.last_seen)}</span><Badge value={endpoint.status || "simulated"} kind="neutral" /></div>
          <div className="agent-list">{endpointAgents.length ? endpointAgents.map((agent) => <AgentRow agent={agent} key={agent.agent_id || agent.id} />) : <div className="endpoint-summary">No agent activity recorded for this endpoint.</div>}</div>
          <button className="endpoint-detail-button" onClick={() => setSelectedEndpoint(endpoint.endpoint_id || endpoint.id)}>View endpoint details <ArrowUpRight size={13} /></button>
        </Card>;
      }) : <Card title="Local simulated agents" icon={Bot}><div className="agent-list">{agents.map((agent) => <AgentRow agent={agent} key={agent.agent_id || agent.id} />)}</div></Card>}
    </div> : <Empty title="No agents registered">Agent status will be shown when the backend is available.</Empty>}
  </div>;
}

function AgentRow({ agent }) {
  return <div className="agent-item"><div className="agent-avatar"><Bot size={16} /></div><div className="agent-info"><strong>{readable(agent.name || agent.agent_type || agent.agent_id)}</strong><small>{readable(agent.agent_type || "Agent")} · {numberOf(agent, "events_processed", "event_count")} events · {numberOf(agent, "findings_count")} findings</small></div><span className={`agent-state ${String(agent.status || "").toLowerCase() === "active" ? "active" : ""}`}><i />{readable(agent.status || "unknown")}</span></div>;
}

function Alerts() {
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [page, setPage] = useState(0);
  const pageSize = 25;
  const query = new URLSearchParams({ limit: String(pageSize), offset: String(page * pageSize) });
  if (severity) query.set("severity", severity);
  if (status) query.set("status", status);
  const resource = useResource(() => get(`/alerts?${query.toString()}`), [severity, status, page]);
  const rows = listOf(resource.data, "alerts", "items", "results").filter((alert) => JSON.stringify(alert).toLowerCase().includes(search.toLowerCase()));
  const total = numberOf(resource.data, "total", "count");
  const update = async (alert, newStatus) => {
    try {
      if (newStatus === "false_positive") {
        await post("/feedback", { alert_id: alert.alert_id || alert.id, verdict: "false_positive", notes: "Marked false positive during alert triage." });
      } else {
        await patch(`/alerts/${alert.alert_id || alert.id}`, { status: newStatus });
      }
      await resource.refresh();
    }
    catch (error) { window.alert(error.message); }
  };
  return <div className="page"><PageHeader eyebrow="INVESTIGATION QUEUE" title="Threat alerts" description="Search and triage detections with their recorded severity and investigation status." actions={<IconButton title="Refresh alerts" onClick={resource.refresh}><RefreshCw size={17} /></IconButton>} /><ErrorBanner error={resource.error} retry={resource.refresh} />
    <Card title="Alert queue" icon={ShieldAlert} action={<span className="card-meta">{total} results</span>}><div className="filters"><label className="search-field"><Search size={16} /><input value={search} onChange={(event) => { setSearch(event.target.value); setPage(0); }} placeholder="Search alerts…" /></label><label className="select-field"><Filter size={15} /><select value={severity} onChange={(event) => { setSeverity(event.target.value); setPage(0); }}><option value="">All severities</option>{["critical", "high", "medium", "low"].map((item) => <option key={item} value={item}>{readable(item)}</option>)}</select><ChevronDown size={14} /></label><label className="select-field"><select value={status} onChange={(event) => { setStatus(event.target.value); setPage(0); }}><option value="">All statuses</option>{["open", "acknowledged", "investigating", "resolved", "false_positive", "confirmed"].map((item) => <option key={item} value={item}>{readable(item)}</option>)}</select><ChevronDown size={14} /></label></div>
      {resource.loading ? <Loading /> : <Table rows={rows} emptyText="No alerts match those filters." columns={[
        { key: "title", label: "Alert", render: (row) => <div className="table-primary"><strong>{row.title || row.message || row.alert_type || "Security finding"}</strong><small>{row.detection_method || "Rules-based"}</small></div> },
        { key: "severity", label: "Severity", render: (row) => <Badge value={row.severity || row.risk_level} /> },
        { key: "endpoint_id", label: "Endpoint" },
        { key: "created_at", label: "Detected", render: (row) => dateOf(row.created_at || row.timestamp) },
        { key: "status", label: "Status", render: (row) => <Badge value={row.status || "open"} kind="neutral" /> },
        { key: "actions", label: "Action", render: (row) => <select className="row-action" aria-label="Update alert status" value={row.status || "open"} onChange={(event) => update(row, event.target.value)}><option value="open">Open</option><option value="acknowledged">Acknowledge</option><option value="investigating">Investigating</option><option value="resolved">Resolved</option><option value="false_positive">False positive</option><option value="confirmed">Confirmed</option></select> },
      ]} />}
      {!resource.loading && <Pagination page={page} pageSize={pageSize} total={total} onPageChange={setPage} loading={resource.loading} />}
    </Card>
  </div>;
}

function Simulation() {
  const [scenario, setScenario] = useState(scenarios[0][0]);
  const [agentType, setAgentType] = useState(scenarios[0][2]);
  const [endpoint, setEndpoint] = useState("");
  const [count, setCount] = useState(12);
  const [parameters, setParameters] = useState({
    failure_count: 12, request_rate: 500, unauthorized_requests: 8,
    modification_count: 20, dos_rate: 5000, cpu_percent: 99, memory_percent: 96,
  });
  const [result, setResult] = useState(null);
  const [runError, setRunError] = useState("");
  const [running, setRunning] = useState(false);
  const endpointsResource = useResource(() => get("/endpoints"), []);
  const settingsResource = useResource(() => get("/settings"), []);
  const [historyPage, setHistoryPage] = useState(0);
  const historyPageSize = 20;
  const history = useResource(
    () => get(`/simulations/history?limit=${historyPageSize}&offset=${historyPage * historyPageSize}`),
    [historyPage],
  );
  const endpoints = listOf(endpointsResource.data, "endpoints").map((item) => item.endpoint_id || item.id).filter(Boolean);
  const selectedScenario = scenarios.find(([id]) => id === scenario);
  useEffect(() => {
    const defaultCount = settingsResource.data?.settings?.default_simulation_event_count;
    if (defaultCount) setCount(defaultCount);
  }, [settingsResource.data]);
  const run = async (event) => {
    event.preventDefault();
    setRunning(true); setRunError(""); setResult(null);
    try {
      const payload = await post("/simulations/run", { scenario, endpoint_id: endpoint || undefined, agent_type: agentType, event_count: count, parameters });
      setResult(payload);
      history.refresh();
    } catch (error) { setRunError(error.message); }
    finally { setRunning(false); }
  };
  return <div className="page"><PageHeader eyebrow="SAFE TEST ENVIRONMENT" title="Simulation center" description="Generate synthetic event patterns and submit them through the live detection pipeline." actions={<span className="safe-label"><ShieldCheck size={14} /> SAFE · SYNTHETIC DATA ONLY</span>} />
    <div className="notice amber-notice"><AlertTriangle size={17} /><span>Simulations create synthetic records only. No real attacks, files, credentials, or operating-system processes are touched.</span></div>
    <ErrorBanner error={endpointsResource.error || settingsResource.error || history.error} retry={() => { endpointsResource.refresh(); settingsResource.refresh(); history.refresh(); }} />
    <div className="simulation-grid"><Card title="Configure scenario" icon={SlidersHorizontal}><form className="simulation-form" onSubmit={run}>
      <label>Scenario<select value={scenario} onChange={(event) => { setScenario(event.target.value); setAgentType(scenarios.find(([id]) => id === event.target.value)?.[2] || "correlation_agent"); }}>{scenarios.map(([id, label]) => <option value={id} key={id}>{label}</option>)}</select></label>
      <label>Agent type<select value={agentType} onChange={(event) => setAgentType(event.target.value)}>{["login_agent", "network_agent", "file_agent", "api_agent", "system_agent", "correlation_agent"].map((item) => <option value={item} key={item}>{readable(item)}</option>)}</select></label>
      <label>Target simulated endpoint<select value={endpoint} onChange={(event) => setEndpoint(event.target.value)}><option value="">Auto-assign endpoint</option>{endpoints.map((id) => <option value={id} key={id}>{id}</option>)}</select></label>
      <label>Generated events <div className="range-line"><input type="range" min="1" max="100" value={count} onChange={(event) => setCount(Number(event.target.value))} /><strong>{count}</strong></div></label>
      <div className="parameter-box"><div className="parameter-title">Scenario parameters</div>{scenario.includes("login") && <label>Failed login attempts<input type="number" min="1" max="1000" value={parameters.failure_count} onChange={(event) => setParameters({ ...parameters, failure_count: Number(event.target.value) })} /></label>}{scenario === "normal_network" && <small>Normal synthetic flow features are generated as a reference baseline.</small>}{scenario === "dos_spike" && <label>Network packets / minute<input type="number" min="1" max="1000000000" value={parameters.dos_rate} onChange={(event) => setParameters({ ...parameters, dos_rate: Number(event.target.value) })} /></label>}{scenario === "api_burst" && <><label>Request rate / minute<input type="number" min="1" max="10000" value={parameters.request_rate} onChange={(event) => setParameters({ ...parameters, request_rate: Number(event.target.value) })} /></label><label>Unauthorized requests<input type="number" min="1" max="1000" value={parameters.unauthorized_requests} onChange={(event) => setParameters({ ...parameters, unauthorized_requests: Number(event.target.value) })} /></label></>}{scenario === "file_burst" && <label>Modification burst size<input type="number" min="1" max="1000" value={parameters.modification_count} onChange={(event) => setParameters({ ...parameters, modification_count: Number(event.target.value) })} /></label>}{scenario === "system_activity" && <><label>CPU utilization (%)<input type="number" min="1" max="100" value={parameters.cpu_percent} onChange={(event) => setParameters({ ...parameters, cpu_percent: Number(event.target.value) })} /></label><label>Memory utilization (%)<input type="number" min="1" max="100" value={parameters.memory_percent} onChange={(event) => setParameters({ ...parameters, memory_percent: Number(event.target.value) })} /></label></>}<small>Adjust values to explore detection behavior; results depend on configured rules and available models.</small></div>
      {runError && <ErrorBanner error={runError} />}
      <button className="primary-button" disabled={running || endpointsResource.loading} type="submit">{running ? <><LoaderCircle className="spin" size={17} /> Processing synthetic events…</> : <><Play size={16} /> Run simulation</>}</button>
    </form></Card>
    <Card title="Simulation result" icon={FileSearch}>{running ? <div className="result-loading"><LoaderCircle className="spin" size={24} /><strong>Processing events</strong><span>Events are being evaluated by applicable rules and models.</span></div> : result ? <SimulationResult result={result} /> : <Empty title="Ready to simulate">Select a scenario and run it to see the actual detection outcome and generated alerts.</Empty>}</Card></div>
    <Card title="Simulation history" icon={Clock3} className="history-card">{history.loading ? <Loading /> : <Table rows={listOf(history.data, "simulations", "items", "results")} columns={[
      { key: "scenario", label: "Scenario", render: (row) => readable(row.scenario) },
      { key: "expected_outcome", label: "Expected", render: (row) => <Badge value={row.expected_outcome || "—"} kind="neutral" /> },
      { key: "actual_outcome", label: "Actual", render: (row) => <Badge value={row.actual_outcome || row.outcome || "—"} /> },
      { key: "events_generated", label: "Events", render: (row) => row.events_generated ?? row.event_count ?? "—" },
      { key: "created_at", label: "Run time", render: (row) => dateOf(row.created_at) },
      { key: "evaluation_result", label: "Evaluation", render: (row) => readable(row.evaluation_result || "—") },
    ]} />}<Pagination page={historyPage} pageSize={historyPageSize} total={numberOf(history.data, "total", "count")} onPageChange={setHistoryPage} loading={history.loading} /></Card>
  </div>;
}
function SimulationResult({ result }) {
  const alerts = listOf(result, "alerts");
  const outcome = result.actual_outcome || result.outcome || result.detection_outcome || "Normal";
  return <div className="simulation-result"><div className={`result-outcome ${severityColors[severityOf({ severity: outcome })] || "blue"}`}><ShieldAlert size={20} /><div><small>ACTUAL DETECTION OUTCOME</small><strong>{readable(outcome)}</strong></div></div><div className="result-stats"><div><small>Expected outcome</small><strong>{readable(result.expected_outcome || "—")}</strong></div><div><small>Events generated</small><strong>{result.events_generated ?? result.event_count ?? "—"}</strong></div><div><small>Alerts generated</small><strong>{result.alerts_generated ?? alerts.length}</strong></div><div><small>Processing time</small><strong>{result.processing_duration_ms ?? result.duration_ms ?? "—"} ms</strong></div></div><div className="result-explanation"><strong>Evaluation</strong><span>{readable(result.evaluation_result || "Not evaluated")}</span></div>{alerts.length > 0 && <div className="result-alerts"><strong>Generated findings</strong>{alerts.slice(0, 5).map((alert) => <div key={alert.alert_id || alert.id || alert.title}><Badge value={alert.severity || alert.risk_level} /><span>{alert.title || alert.message || alert.explanation || "Detection finding"}</span></div>)}</div>}<div className="result-method">Detection methods: {listOf(result, "detection_methods", "methods").map(readable).join(", ") || result.detection_method || "Rules and compatible models"}</div></div>;
}

function Analysis() {
  const [page, setPage] = useState(0);
  const pageSize = 25;
  const events = useResource(() => get(`/events?limit=${pageSize}&offset=${page * pageSize}`), [page]);
  const [selectedId, setSelectedId] = useState("");
  const rows = listOf(events.data, "events", "items", "results");
  useEffect(() => {
    const selectedExists = rows.some((event) => (event.event_id || event.id) === selectedId);
    if (rows.length && !selectedExists) setSelectedId(rows[0].event_id || rows[0].id);
  }, [rows, selectedId]);
  const selected = rows.find((event) => (event.event_id || event.id) === selectedId);
  const findings = listOf(selected, "findings", "agent_findings", "detections");
  return <div className="page"><PageHeader eyebrow="EXPLAINABLE DETECTION" title="AI analysis" description="Inspect processed events, supported detection signals, and recorded recommendations." actions={<IconButton title="Refresh events" onClick={events.refresh}><RefreshCw size={17} /></IconButton>} /><ErrorBanner error={events.error} retry={events.refresh} />
    {rows.length ? <div className="analysis-grid"><Card title="Processed events" icon={Database}><div className="event-picker">{rows.map((event) => <button type="button" key={event.event_id || event.id} className={`event-option ${selectedId === (event.event_id || event.id) ? "selected" : ""}`} onClick={() => setSelectedId(event.event_id || event.id)}><span className="event-option-icon"><Activity size={15} /></span><span><strong>{readable(event.event_type || event.type || event.scenario || "Security event")}</strong><small>{event.endpoint_id || "Unknown endpoint"} · {dateOf(event.timestamp || event.created_at)}</small></span><Badge value={event.severity || event.outcome || "low"} /></button>)}</div><Pagination page={page} pageSize={pageSize} total={numberOf(events.data, "total", "count")} onPageChange={setPage} loading={events.loading} /></Card>
      {selected && <div className="analysis-detail"><Card title="Detection explanation" icon={Sparkles}><div className="analysis-event-title"><div><span className="eyebrow">EVENT {selected.event_id || selected.id}</span><h2>{readable(selected.event_type || selected.type || selected.scenario)}</h2></div><Badge value={selected.severity || selected.outcome || "normal"} /></div><p className="explanation-text">{selected.explanation || selected.detection_explanation || selected.message || "No alert was produced for this event. This event was evaluated by the configured detection rules and compatible models."}</p>            <div className="detail-grid"><div><small>Endpoint</small><strong>{selected.endpoint_id || "—"}</strong></div><div><small>Detection method</small><strong>{readable(selected.detection_method || "Rules-based")}</strong></div><div><small>Risk score</small><strong>{selected.risk_score ?? "—"}</strong></div><div><small>Classifier output</small><strong>{readable(selected.classifier_prediction || "Not run")}</strong></div><div><small>Classifier score · not final verdict</small><strong>{selected.model_score == null ? "Not run" : Number(selected.model_score).toFixed(4)}</strong></div><div><small>Anomaly decision</small><strong>{readable(selected.anomaly_decision || "Not run")}</strong></div><div><small>Isolation Forest score · not probability</small><strong>{selected.anomaly_score == null ? "Not run" : Number(selected.anomaly_score).toFixed(4)}</strong></div><div><small>Model version</small><strong>{selected.model_version || "Unavailable"}</strong></div><div><small>Timestamp</small><strong>{dateOf(selected.timestamp || selected.created_at)}</strong></div></div>
      <div className="recommendation"><strong>Suggested analyst action</strong><span>Review the event context and independent signals, then record feedback if the finding is benign. No automatic response actions are taken.</span></div></Card>
        <Card title="Detection signals" icon={Gauge}><div className="signal-list">{findings.length ? findings.map((finding, index) => <div className="signal-item" key={finding.finding_id || index}><div className="signal-check"><Check size={14} /></div><div><strong>{finding.rule_name || finding.agent_type || finding.name || "Detection signal"}</strong><p>{finding.explanation || finding.reason || finding.message || JSON.stringify(finding)}</p></div><Badge value={finding.severity || finding.confidence || "signal"} kind="neutral" /></div>) : <Empty title="No additional findings">The backend did not include agent-level signals for this event.</Empty>}</div></Card></div>}</div> : events.loading ? <Loading /> : <Empty title="No events to analyze">Run a simulation to create events for this analysis view.</Empty>}
  </div>;
}

function Analytics() {
  const summary = useResource(() => get("/analytics/summary"), []);
  const matrix = useResource(() => get("/analytics/confusion-matrix"), []);
  const categories = useResource(() => get("/analytics/attack-categories"), []);
  const s = summary.data || {};
  const matrixData = matrix.data?.matrix || matrix.data?.confusion_matrix || matrix.data;
  const categoryRows = listOf(categories.data, "categories", "results", "items");
  return <div className="page"><PageHeader eyebrow="MEASUREMENT & VALIDATION" title="Detection analytics" description="Metrics are populated from available labeled evaluations and event history, never estimated in the UI." actions={<IconButton title="Refresh analytics" onClick={() => { summary.refresh(); matrix.refresh(); categories.refresh(); }}><RefreshCw size={17} /></IconButton>} /><ErrorBanner error={summary.error || matrix.error || categories.error} retry={() => { summary.refresh(); matrix.refresh(); categories.refresh(); }} />
    <div className="metrics-grid analytics-metrics"><Metric label="Precision" value={s.precision == null ? "—" : `${(Number(s.precision) * (Number(s.precision) <= 1 ? 100 : 1)).toFixed(1)}%`} note="From evaluation split" icon={TargetIcon} accent="blue" /><Metric label="Recall" value={s.recall == null ? "—" : `${(Number(s.recall) * (Number(s.recall) <= 1 ? 100 : 1)).toFixed(1)}%`} note="From evaluation split" icon={ArrowUpRight} accent="green" /><Metric label="F1-score" value={s.f1_score == null ? "—" : Number(s.f1_score).toFixed(3)} note="Harmonic mean" icon={Gauge} accent="cyan" /><Metric label="False-positive rate" value={s.false_positive_rate == null ? "—" : `${(Number(s.false_positive_rate) * (Number(s.false_positive_rate) <= 1 ? 100 : 1)).toFixed(2)}%`} note="Measured on labeled data" icon={ArrowDownRight} accent="orange" /></div>
    <div className="content-grid two"><Card title="Confusion matrix" icon={SlidersHorizontal}><ConfusionMatrix value={matrixData} /></Card><Card title="Evaluation context" icon={CircleHelp}><div className="context-list"><div><span>Evaluation dataset</span><strong>{s.dataset || s.dataset_name || "Unavailable"}</strong></div><div><span>Evaluation samples</span><strong>{numberOf(s, "evaluation_samples", "test_samples") || "—"}</strong></div><div><span>Evaluation status</span><Badge value={s.evaluation_status || (s.metrics_available ? "available" : "unavailable")} kind="neutral" /></div><div><span>Data provenance</span><strong>Synthetic only</strong></div></div><div className="notice blue-notice compact"><CircleHelp size={16} /><span>Metrics on synthetic data do not establish real-world detection effectiveness.</span></div></Card></div>
    <Card title="Category-wise performance" icon={Activity} className="history-card"><Table rows={categoryRows} emptyText="Train/evaluate models to populate category metrics." columns={[{ key: "category", label: "Category", render: (row) => readable(row.category || row.attack_cat || row.name) }, { key: "precision", label: "Precision", render: percentValue }, { key: "recall", label: "Recall", render: percentValue }, { key: "f1_score", label: "F1-score", render: percentValue }, { key: "support", label: "Samples", render: (row) => row.support ?? row.samples ?? "—" }]} /></Card>
  </div>;
}
function TargetIcon(props) { return <ShieldCheck {...props} />; }
function percentValue(row) { const value = row.precision ?? row.recall ?? row.f1_score; return value == null ? "—" : `${(Number(value) * (Number(value) <= 1 ? 100 : 1)).toFixed(1)}%`; }
function ConfusionMatrix({ value }) {
  const raw = Array.isArray(value) ? value : value?.values;
  if (!Array.isArray(raw) || !raw.length) return <Empty title="No evaluation matrix">Run model evaluation to calculate confusion-matrix values.</Empty>;
  const values = Array.isArray(raw[0]) ? raw : [];
  return <div className="matrix-wrap"><div className="matrix-label">PREDICTED</div><div className="matrix"><div /><div className="matrix-head">Normal</div><div className="matrix-head">Threat</div><div className="matrix-side">Normal</div>{values.slice(0, 2).map((row, i) => <Fragment key={`row-${i}`}><div className="matrix-side">{i === 0 ? "Normal" : "Threat"}</div>{row.slice(0, 2).map((cell, j) => <div className={`matrix-cell cell-${i}-${j}`} key={`${i}-${j}`}><strong>{cell}</strong><small>{i === j ? "Correct" : "Incorrect"}</small></div>)}</Fragment>)}</div></div>;
}

function Settings() {
  const [thresholds, setThresholds] = useState({});
  const [saved, setSaved] = useState(false);
  const [saveError, setSaveError] = useState("");
  const [saving, setSaving] = useState(false);
  const resource = useResource(() => get("/settings"), []);
  useEffect(() => {
    if (resource.data?.settings) setThresholds(resource.data.settings);
  }, [resource.data]);
  const save = async () => {
    setSaving(true); setSaveError(""); setSaved(false);
    try {
      await patch("/settings", thresholds);
      setSaved(true);
      await resource.refresh();
    } catch (error) {
      setSaveError(error.message);
    } finally { setSaving(false); }
  };
  const settingLabels = {
    failed_login_threshold: "Failed login threshold",
    login_frequency_threshold: "Login frequency threshold / minute",
    unauthorized_request_threshold: "Unauthorized API request threshold",
    correlation_window_minutes: "Correlation window (minutes)",
    api_requests_per_minute: "API requests per minute",
    file_modifications: "File modifications in burst",
    network_unique_ports: "Unique ports for network scan",
    dos_rate_threshold: "Network traffic-rate threshold",
    system_resource_threshold: "System resource threshold (%)",
    default_simulation_event_count: "Default simulation event count",
  };
  return <div className="page"><PageHeader eyebrow="LOCAL CONFIGURATION" title="Settings" description="Tune persisted detection and simulation defaults for this local synthetic environment." actions={<IconButton title="Refresh settings" onClick={resource.refresh}><RefreshCw size={17} /></IconButton>} /><ErrorBanner error={resource.error || saveError} retry={resource.refresh} />
    <div className="notice blue-notice"><LockKeyhole size={17} /><span>Settings are stored in local SQLite and apply to supported rules and subsequent simulations. They do not connect to real endpoints or change model artifacts.</span></div>
    <Card title="Detection thresholds" icon={SlidersHorizontal}><div className="settings-list">{Object.entries(settingLabels).map(([key, label]) => <label className="setting-row" key={key}><span><strong>{label}</strong><small>Persisted backend setting</small></span><input type="number" min="1" max={key === "system_resource_threshold" ? "100" : "10000"} value={thresholds[key] ?? ""} onChange={(event) => { setThresholds({ ...thresholds, [key]: Number(event.target.value) }); setSaved(false); }} disabled={resource.loading} /></label>)}</div><button className="secondary-button save-button" onClick={save} disabled={resource.loading || saving || !Object.keys(thresholds).length}><Check size={15} />{saving ? "Saving…" : saved ? "Settings saved" : "Save settings"}</button></Card>
    <Card title="Safe operation" icon={ShieldCheck} className="settings-safe"><div className="safe-points"><div><Check size={16} /><span>Synthetic records only</span></div><div><Check size={16} /><span>No shell commands executed</span></div><div><Check size={16} /><span>No real files or processes inspected</span></div><div><Check size={16} /><span>Alerts never trigger automated destructive actions</span></div></div></Card>
  </div>;
}

export default function App() {
  const health = useResource(() => get("/health"), [], 30000);
  const online = Boolean(health.data && !health.error);
  return <Shell health={online}><Routes><Route path="/" element={<Dashboard />} /><Route path="/endpoints" element={<Endpoints />} /><Route path="/alerts" element={<Alerts />} /><Route path="/simulation" element={<Simulation />} /><Route path="/analysis" element={<Analysis />} /><Route path="/analytics" element={<Analytics />} /><Route path="/settings" element={<Settings />} /><Route path="*" element={<Dashboard />} /></Routes></Shell>;
}
