/**
 * Zone configuration from the REST API (current state, not date-based):
 * plan, SSL/TLS and security settings, DNS records, certificates, rulesets,
 * load balancers and health checks, custom hostnames, Workers routes and
 * Email Routing. Missing permissions show as notes instead of failing.
 */

import { restCount, restList, restOne, type Api, type Obj, type Zone } from "./cloudflare";
import type { Metric, Section, Table, Unit } from "./usage";

const DAY = 86_400_000;

// ---------------------------------------------------------------------------
// One zone (zone drill-down page)

export async function zoneConfig(api: Api, zone: Zone): Promise<Section> {
	const z = `/zones/${zone.id}`;
	const errors: string[] = [];
	const denied: string[] = [];
	const get = async <T>(what: string, fn: () => Promise<T | null>): Promise<T | null> => {
		try {
			const v = await fn();
			if (v === null) denied.push(what);
			return v;
		} catch (err) {
			errors.push(`${what}: ${err instanceof Error ? err.message : String(err)}`);
			return null;
		}
	};

	const [details, settings, dnssec, records, packs, originCerts, rulesets, lbs, checks, hostnames, routes, email, emailRules] = await Promise.all([
		get("Zone details", () => restOne(api, z)),
		get("Zone settings", () => restList(api, `${z}/settings`, 100)),
		get("DNSSEC", () => restOne(api, `${z}/dnssec`)),
		get("DNS records", () => restList(api, `${z}/dns_records`, 500)),
		get("Certificates", () => restList(api, `${z}/ssl/certificate_packs`, 50)),
		get("Origin CA certificates", () => restCount(api, `/certificates?zone_id=${zone.id}`)),
		get("Rulesets", () => restList(api, `${z}/rulesets`, 50)),
		get("Load balancers", () => restList(api, `${z}/load_balancers`, 100)),
		get("Health checks", () => restList(api, `${z}/healthchecks`, 50)),
		get("Custom hostnames", () => restList(api, `${z}/custom_hostnames`, 50)),
		get("Workers routes", () => restList(api, `${z}/workers/routes`, 100)),
		get("Email Routing", () => restOne(api, `${z}/email/routing`)),
		get("Email Routing rules", () => restList(api, `${z}/email/routing/rules`, 50)),
	]);

	// Rule counts per configured phase (zone entrypoints only; managed rulesets are Cloudflare's).
	const phases = (rulesets ?? []).filter((r) => r.kind === "zone").map((r) => String(r.phase));
	const entrypoints = await Promise.all(
		phases.map((phase) =>
			get(`Ruleset ${phase}`, () => restOne(api, `${z}/rulesets/phases/${phase}/entrypoint`)).then((r) => ({ phase, rules: (r?.rules as Obj[] | undefined) ?? [] })),
		),
	);
	const rulesIn = (phase: string) => entrypoints.find((e) => e.phase === phase)?.rules ?? [];
	const enabled = (rules: Obj[]) => rules.filter((r) => r.enabled !== false).length;

	// ---- settings ----------------------------------------------------------------
	const setting = (id: string) => settings?.find((s) => s.id === id)?.value;
	const onOff = (v: unknown) => (v === "on" ? "On" : v === "off" ? "Off" : v === undefined ? "—" : String(v));
	const plan = details ? String((details.plan as Obj | undefined)?.name ?? "—") : zone.plan;

	// ---- certificates ------------------------------------------------------------
	const expiries = (packs ?? [])
		.filter((p) => p.status === "active")
		.flatMap((p) => ((p.certificates as Obj[] | undefined) ?? []).map((c) => ({ hosts: (p.hosts as string[] | undefined) ?? [], type: String(p.type), expires: String(c.expires_on ?? "") })))
		.filter((c) => c.expires)
		// A pack usually holds an ECDSA and an RSA copy expiring the same day: keep one.
		.filter((c, i, all) => all.findIndex((x) => x.expires.slice(0, 10) === c.expires.slice(0, 10) && x.hosts.join() === c.hosts.join()) === i)
		.sort((a, b) => a.expires.localeCompare(b.expires));
	const nextExpiryDays = expiries.length ? Math.floor((Date.parse(expiries[0].expires) - Date.now()) / DAY) : null;

	// ---- health ------------------------------------------------------------------
	const unhealthy = (checks ?? []).filter((c) => c.status === "unhealthy");
	const suspended = (checks ?? []).filter((c) => c.suspended || c.status === "suspended");
	const activeHostnames = (hostnames ?? []).filter((h) => h.status === "active");

	const metrics: Metric[] = [
		m("DNS records", records ? records.length : null),
		m("Proxied records", records ? records.filter((r) => r.proxied).length : null),
		m("Certificate packs", packs ? packs.length : null, "count", packs ? `${packs.filter((p) => p.status === "active").length} active` : undefined),
		m("Days to next cert expiry", nextExpiryDays, "count", expiries[0] ? `${expiries[0].hosts[0] ?? ""} · ${expiries[0].expires.slice(0, 10)}` : undefined),
		m("Origin CA certificates", originCerts),
		m("Rule phases configured", rulesets ? phases.length : null),
		m("WAF custom rules", rulesets ? rulesIn("http_request_firewall_custom").length : null),
		m("Rate limiting rules", rulesets ? rulesIn("http_ratelimit").length : null),
		m("Load balancers", lbs ? lbs.length : null, "count", lbs ? `${lbs.filter((l) => l.enabled).length} enabled` : undefined),
		m("Health checks", checks ? checks.length : null, "count", checks ? `${unhealthy.length} unhealthy · ${suspended.length} suspended` : undefined),
		m("Custom hostnames", hostnames ? hostnames.length : null, "count", hostnames ? `${activeHostnames.length} active` : undefined),
		m("Workers routes", routes ? routes.length : null),
		m("Email Routing rules", emailRules ? emailRules.length : null, "count", emailRules ? `${enabled(emailRules)} enabled` : undefined),
	];

	const tables: Table[] = [
		kv("Settings", [
			["Plan", plan],
			["Status", details ? `${String(details.status)}${details.paused ? " (paused)" : ""}` : "—"],
			["Setup", details ? (details.type === "partial" ? "Partial (CNAME)" : details.type === "full" ? "Full (Cloudflare DNS)" : String(details.type)) : "—"],
			["Nameservers", details ? ((details.name_servers as string[] | undefined) ?? []).join(", ") || "—" : "—"],
			["SSL/TLS mode", sslMode(setting("ssl"))],
			["Minimum TLS version", String(setting("min_tls_version") ?? "—")],
			["Always Use HTTPS", onOff(setting("always_use_https"))],
			["TLS 1.3", onOff(setting("tls_1_3"))],
			["HTTP/3 (QUIC)", onOff(setting("http3"))],
			["Security level", securityLevel(setting("security_level"))],
			["Browser Integrity Check", onOff(setting("browser_check"))],
			["Development mode", onOff(setting("development_mode"))],
			["DNSSEC", dnssec ? String(dnssec.status ?? "—") : "—"],
			["Email Routing", email ? `${email.enabled ? "Enabled" : "Disabled"} (${String(email.status ?? "—")})` : "—"],
		]),
	];
	if (records?.length) tables.push(countTable("DNS records by type", records.map((r) => String(r.type)), "Type", records.map((r) => !!r.proxied), "Proxied"));
	if (packs?.length) tables.push(countTable("Certificate packs by type · status", packs.map((p) => `${String(p.type)} · ${String(p.status)}`), "Type · status"));
	if (expiries.length) {
		tables.push({
			title: "Next certificates to expire",
			columns: [{ key: "host", label: "Hosts" }, { key: "type", label: "Type" }, { key: "exp", label: "Expires" }, { key: "days", label: "Days left", unit: "count" }],
			rows: expiries.slice(0, 8).map((c) => ({
				host: c.hosts.slice(0, 2).join(", ") + (c.hosts.length > 2 ? ` +${c.hosts.length - 2}` : ""),
				type: c.type,
				exp: c.expires.slice(0, 10),
				days: Math.floor((Date.parse(c.expires) - Date.now()) / DAY),
			})),
		});
	}
	if (entrypoints.length) {
		tables.push({
			title: "Rules by phase",
			columns: [{ key: "phase", label: "Phase" }, { key: "rules", label: "Rules", unit: "count" }, { key: "on", label: "Enabled", unit: "count" }],
			rows: entrypoints
				.map((e) => ({ phase: phaseName(e.phase), rules: e.rules.length, on: enabled(e.rules) }))
				.sort((a, b) => b.rules - a.rules),
		});
	}
	if (lbs?.length) {
		tables.push({
			title: "Load balancers",
			columns: [{ key: "name", label: "Hostname" }, { key: "state", label: "State" }, { key: "steering", label: "Steering" }, { key: "pools", label: "Pools", unit: "count" }],
			rows: lbs.map((l) => ({
				name: String(l.name),
				state: `${l.enabled ? "Enabled" : "Disabled"}${l.proxied ? " · proxied" : ""}`,
				steering: String(l.steering_policy || "off"),
				pools: ((l.default_pools as unknown[] | undefined) ?? []).length,
			})),
		});
	}
	if (checks?.length) {
		tables.push({
			title: "Health checks",
			columns: [{ key: "name", label: "Name" }, { key: "status", label: "Status" }, { key: "type", label: "Type" }, { key: "address", label: "Address" }],
			rows: checks.map((c) => ({ name: String(c.name), status: healthStatus(String(c.status)), type: String(c.type ?? "—"), address: String(c.address ?? "—") })),
		});
	}
	if (hostnames?.length) {
		tables.push({
			title: `Custom hostnames (${hostnames.length})`,
			columns: [{ key: "host", label: "Hostname" }, { key: "status", label: "Status" }, { key: "ssl", label: "SSL" }],
			rows: hostnames.slice(0, 25).map((h) => ({ host: String(h.hostname), status: String(h.status ?? "—"), ssl: String((h.ssl as Obj | undefined)?.status ?? "—") })),
		});
	}
	if (routes?.length) {
		tables.push({
			title: "Workers routes",
			columns: [{ key: "pattern", label: "Route" }, { key: "script", label: "Worker" }],
			rows: routes.map((r) => ({ pattern: String(r.pattern), script: String(r.script || "(none – route disabled)") })),
		});
	}

	const notes: string[] = [];
	if (denied.length) notes.push(`Not readable with this token: ${[...new Set(denied.map((d) => d.replace(/^Ruleset .*/, "Rulesets")))].join(", ")}.`);
	for (const c of unhealthy) notes.push(`⚠ Health check "${String(c.name)}" is unhealthy${c.failure_reason ? `: ${String(c.failure_reason)}` : ""}.`);
	if (nextExpiryDays !== null && nextExpiryDays < 14) notes.push(`⚠ A certificate for ${expiries[0].hosts[0] ?? "this zone"} expires in ${nextExpiryDays} days.`);
	notes.push("Current configuration, not limited to the selected dates.");

	return {
		id: "zone-config",
		group: "Configuration",
		title: "Zone configuration",
		source: "REST /zones, /settings, /dns_records, /ssl/certificate_packs, /rulesets, /load_balancers, /healthchecks, /custom_hostnames, /workers/routes, /email/routing",
		metrics,
		tables,
		notes,
		errors,
	};
}

// ---------------------------------------------------------------------------
// All zones (overview)

export async function zoneConfigTotals(api: Api, zones: Zone[]): Promise<Section> {
	const errors: string[] = [];
	const count = async (zone: Zone, what: string, fn: () => Promise<number | null>) => {
		try {
			return await fn();
		} catch (err) {
			errors.push(`${zone.name} ${what}: ${err instanceof Error ? err.message : String(err)}`);
			return null;
		}
	};
	const perZone = await Promise.all(
		zones.map(async (zone) => {
			const z = `/zones/${zone.id}`;
			const [dns, hostnames, lbs, checks] = await Promise.all([
				count(zone, "DNS records", () => restCount(api, `${z}/dns_records`)),
				count(zone, "custom hostnames", () => restCount(api, `${z}/custom_hostnames`)),
				count(zone, "load balancers", async () => (await restList(api, `${z}/load_balancers`, 100))?.length ?? null),
				count(zone, "health checks", () => restCount(api, `${z}/healthchecks`)),
			]);
			return { zone, dns, hostnames, lbs, checks };
		}),
	);
	const sum = (k: "dns" | "hostnames" | "lbs" | "checks") =>
		perZone.some((r) => r[k] !== null) ? perZone.reduce((a, r) => a + (r[k] ?? 0), 0) : null;

	return {
		id: "zone-config",
		group: "Zones",
		title: "Zone configuration",
		source: "REST /custom_hostnames, /load_balancers, /healthchecks, /dns_records",
		metrics: [
			m("Custom hostnames", sum("hostnames"), "count", "All states, incl. pending/deleted; open a zone for active ones"),
			m("Load balancers", sum("lbs")),
			m("Health checks", sum("checks")),
			m("DNS records", sum("dns")),
		],
		tables: [
			{
				title: "Per zone",
				columns: [
					{ key: "zone", label: "Zone" },
					{ key: "hostnames", label: "Custom hostnames", unit: "count" },
					{ key: "lbs", label: "Load balancers", unit: "count" },
					{ key: "checks", label: "Health checks", unit: "count" },
					{ key: "dns", label: "DNS records", unit: "count" },
				],
				rows: [
					...perZone.map((r) => ({ zone: r.zone.name, zoneId: r.zone.id, hostnames: r.hostnames, lbs: r.lbs, checks: r.checks, dns: r.dns })),
					{ zone: "Total", hostnames: sum("hostnames"), lbs: sum("lbs"), checks: sum("checks"), dns: sum("dns") },
				],
			},
		],
		notes: [
			"Current counts, not limited to the selected dates. Open a zone for its full configuration.",
			...(perZone.some((r) => r.hostnames === null || r.lbs === null) ? ["Some counts need more token permissions (SSL and Certificates / Load Balancers / Health Checks → Read)."] : []),
		],
		errors,
	};
}

// ---------------------------------------------------------------------------
// Helpers

function m(label: string, value: number | null, unit: Unit = "count", hint?: string): Metric {
	return hint ? { label, value, unit, hint } : { label, value, unit };
}

function kv(title: string, pairs: [string, string][]): Table {
	return { title, columns: [{ key: "k", label: "Setting" }, { key: "v", label: "Value" }], rows: pairs.map(([k, v]) => ({ k, v })) };
}

function countTable(title: string, keys: string[], label: string, flags?: boolean[], flagLabel = "Enabled"): Table {
	const agg = new Map<string, { n: number; f: number }>();
	keys.forEach((k, i) => {
		const a = agg.get(k) ?? { n: 0, f: 0 };
		a.n++;
		if (flags?.[i]) a.f++;
		agg.set(k, a);
	});
	const columns = [{ key: "k", label }, { key: "n", label: "Count", unit: "count" as Unit }];
	if (flags) columns.push({ key: "f", label: flagLabel, unit: "count" as Unit });
	return { title, columns, rows: [...agg.entries()].sort((a, b) => b[1].n - a[1].n).map(([k, v]) => ({ k, n: v.n, ...(flags ? { f: v.f } : {}) })) };
}

function sslMode(v: unknown): string {
	const names: Record<string, string> = { off: "Off", flexible: "Flexible", full: "Full", strict: "Full (strict)", origin_pull: "Strict (SSL-only origin pull)" };
	return v === undefined ? "—" : names[String(v)] ?? String(v);
}

function securityLevel(v: unknown): string {
	const names: Record<string, string> = {
		off: "Off", essentially_off: "Essentially off", low: "Low", medium: "Medium", high: "High", under_attack: "I'm Under Attack",
	};
	return v === undefined ? "—" : names[String(v)] ?? String(v);
}

function healthStatus(s: string): string {
	return s === "healthy" ? "● Healthy" : s === "unhealthy" ? "⛔ Unhealthy" : s === "suspended" ? "○ Suspended" : s;
}

function phaseName(phase: string): string {
	const names: Record<string, string> = {
		http_request_firewall_custom: "WAF custom rules",
		http_request_firewall_managed: "WAF managed rules",
		http_response_firewall_managed: "WAF managed rules (response)",
		http_ratelimit: "Rate limiting rules",
		http_request_transform: "URL rewrite rules",
		http_request_late_transform: "Request header rules",
		http_response_headers_transform: "Response header rules",
		http_request_dynamic_redirect: "Single redirects",
		http_request_redirect: "Bulk redirects",
		http_request_cache_settings: "Cache rules",
		http_config_settings: "Configuration rules",
		http_request_origin: "Origin rules",
		http_response_compression: "Compression rules",
		http_custom_errors: "Custom error rules",
		http_log_custom_fields: "Logpush custom fields",
		http_request_sanitize: "URL normalization",
		ddos_l7: "HTTP DDoS overrides",
	};
	return names[phase] ? `${names[phase]} (${phase})` : phase;
}
