/**
 * Zero Trust inventory from the REST API: seats vs subscription, devices, tunnels,
 * private networks and configuration. These describe the account *now*; only
 * "logged in during the range" and "seen during the range" use the selected dates.
 *
 * Needs read permissions beyond analytics (Access: Users / Apps and Policies,
 * Zero Trust, Cloudflare Tunnel, Billing). Missing ones show as a note, not a failure.
 */

import { restList as list, restOne as one, type Api, type DateRange, type Obj } from "./cloudflare";
import type { Metric, Section, Table, Unit } from "./usage";

/** Runs a fetch, turning unexpected errors into a message so one failure doesn't hide the rest. */
async function safe<T>(fn: () => Promise<T>, errors: string[], what: string): Promise<T | null> {
	try {
		return await fn();
	} catch (err) {
		errors.push(`${what}: ${err instanceof Error ? err.message : String(err)}`);
		return null;
	}
}

export async function buildZtInventory(api: Api, range: DateRange): Promise<Section[]> {
	const a = `/accounts/${api.accountId}`;
	const errors: Record<string, string[]> = { seats: [], devices: [], tunnels: [], networks: [], config: [] };

	const [users, subs, devices, fleet, tunnels, routes, vnets, apps, idps, groups, tokens, posture, rules, locations, lists, dlp, dex, org] =
		await Promise.all([
			safe(() => list(api, `${a}/access/users`), errors.seats, "Access users"),
			safe(() => list(api, `${a}/subscriptions`), errors.seats, "Subscriptions"),
			safe(() => list(api, `${a}/devices`), errors.devices, "Devices"),
			safe(() => one(api, `${a}/dex/fleet-status/live?since_minutes=60`), errors.devices, "DEX fleet status"),
			safe(() => list(api, `${a}/cfd_tunnel?is_deleted=false`), errors.tunnels, "Tunnels"),
			safe(() => list(api, `${a}/teamnet/routes`), errors.networks, "Routes"),
			safe(() => list(api, `${a}/teamnet/virtual_networks`), errors.networks, "Virtual networks"),
			safe(() => list(api, `${a}/access/apps`), errors.config, "Access applications"),
			safe(() => list(api, `${a}/access/identity_providers`), errors.config, "Identity providers"),
			safe(() => list(api, `${a}/access/groups`), errors.config, "Access groups"),
			safe(() => list(api, `${a}/access/service_tokens`), errors.config, "Service tokens"),
			safe(() => list(api, `${a}/devices/posture`), errors.config, "Posture rules"),
			safe(() => list(api, `${a}/gateway/rules`), errors.config, "Gateway policies"),
			safe(() => list(api, `${a}/gateway/locations`), errors.config, "Gateway locations"),
			safe(() => list(api, `${a}/gateway/lists`), errors.config, "Gateway lists"),
			safe(() => list(api, `${a}/dlp/profiles`), errors.config, "DLP profiles"),
			safe(() => list(api, `${a}/dex/devices/dex_tests`), errors.config, "DEX tests"),
			safe(() => one(api, `${a}/access/organizations`), errors.config, "Organization"),
		]);

	const now = Date.now();
	const day = 86_400_000;
	const inRange = (iso: unknown) => {
		if (typeof iso !== "string" || !iso) return false;
		const t = Date.parse(iso);
		return t >= Date.parse(`${range.from}T00:00:00Z`) && t < Date.parse(`${range.to}T00:00:00Z`) + day;
	};
	const within = (iso: unknown, days: number) => typeof iso === "string" && !!iso && now - Date.parse(iso) <= days * day;

	// ---- Seats & subscription ------------------------------------------------------
	const teams = subs?.find((s) => /^teams/.test(String(get(s, "rate_plan.id")))) ?? null;
	const components = (teams?.component_values as Obj[] | undefined) ?? [];
	const purchased = num(components.find((c) => c.name === "users")?.value) || null;
	const seated = users?.filter((u) => u.access_seat || u.gateway_seat) ?? null;
	const used = seated ? seated.length : null;
	const seats = section("zt-inv-seats", "Seats & subscription", "REST /access/users, /subscriptions", [
		m("Seats in use", used, "count", purchased && used !== null ? `of ${purchased.toLocaleString("en")} purchased (${((used / purchased) * 100).toFixed(1)}%)` : undefined),
		m("Seats purchased", purchased),
		m("Seats available", purchased !== null && used !== null ? purchased - used : null),
		m("Access seats", users ? users.filter((u) => u.access_seat).length : null),
		m("Gateway seats", users ? users.filter((u) => u.gateway_seat).length : null),
		m("Users on record", users ? users.length : null),
		m("Users logged in (selected dates)", users ? users.filter((u) => inRange(u.last_successful_login)).length : null),
		m("Users logged in (last 30 days)", users ? users.filter((u) => within(u.last_successful_login, 30)).length : null),
	], [
		...(teams ? [kv("Subscription", [
			["Plan", String(get(teams, "rate_plan.public_name") ?? get(teams, "rate_plan.id") ?? "—")],
			["State", String(teams.state ?? "—")],
			...components.map((c): [string, string] => [componentName(String(c.name)), formatComponent(c)]),
		])] : []),
		...(seated?.length ? [{
			title: `Users holding a seat (${seated.length})`,
			columns: [{ key: "user", label: "User" }, { key: "seat", label: "Seat" }, { key: "last", label: "Last login" }],
			rows: seated
				.sort((x, y) => String(y.last_successful_login ?? "").localeCompare(String(x.last_successful_login ?? "")))
				.slice(0, 25)
				.map((u) => ({
					user: maskEmail(String(u.email ?? u.name ?? "—")),
					seat: [u.access_seat ? "Access" : "", u.gateway_seat ? "Gateway" : ""].filter(Boolean).join(" + "),
					last: shortDate(u.last_successful_login),
				})),
		} satisfies Table] : []),
	], errors.seats, [
		...(users === null ? ["Seats need the token permission Access: Users → Read."] : []),
		...(subs === null ? ["Purchased seats need the token permission Billing → Read."] : []),
		"Current state, not limited to the selected dates.",
	]);

	// ---- Devices ---------------------------------------------------------------------
	const ds = get(fleet, "deviceStats") as Obj | undefined;
	const devicesSection = section("zt-inv-devices", "Devices (WARP)", "REST /devices, /dex/fleet-status/live", [
		m("Registered devices", devices ? devices.length : null),
		m("Seen in selected dates", devices ? devices.filter((d) => inRange(d.last_seen)).length : null),
		m("Seen in last 7 days", devices ? devices.filter((d) => within(d.last_seen, 7)).length : null),
		m("Not seen for 30+ days", devices ? devices.filter((d) => !within(d.last_seen, 30)).length : null),
		m("Online now (DEX, last hour)", ds ? num(ds.uniqueDevicesTotal) : null),
	], [
		...(devices ? [
			countTable("By operating system", devices.map((d) => String(d.device_type ?? "unknown")), "OS"),
			countTable("By WARP client version", devices.map((d) => String(d.version || "unknown")), "Version"),
			{
				title: "Devices by last seen",
				columns: [{ key: "name", label: "Device" }, { key: "os", label: "OS" }, { key: "version", label: "Client" }, { key: "seen", label: "Last seen" }],
				rows: [...devices]
					.sort((x, y) => String(y.last_seen ?? "").localeCompare(String(x.last_seen ?? "")))
					.slice(0, 25)
					.map((d) => ({ name: String(d.name ?? "—"), os: String(d.device_type ?? "—"), version: String(d.version || "—"), seen: shortDate(d.last_seen) })),
			} satisfies Table,
		] : []),
		...(ds ? [fleetTable("Live fleet by status (last hour)", ds.byStatus), fleetTable("Live fleet by mode (last hour)", ds.byMode)] : []),
	], errors.devices, [
		...(devices === null ? ["Devices need the token permission Zero Trust → Read."] : []),
		"Current state, not limited to the selected dates.",
	]);

	// ---- Tunnels ---------------------------------------------------------------------
	const down = tunnels?.filter((t) => t.status !== "healthy") ?? [];
	const tunnelsSection = section("zt-inv-tunnels", "Cloudflare Tunnels", "REST /cfd_tunnel", [
		m("Tunnels", tunnels ? tunnels.length : null),
		m("Healthy", tunnels ? tunnels.filter((t) => t.status === "healthy").length : null),
		m("Degraded", tunnels ? tunnels.filter((t) => t.status === "degraded").length : null),
		m("Down / inactive", tunnels ? tunnels.filter((t) => t.status === "down" || t.status === "inactive").length : null),
		m("Active connections", tunnels ? tunnels.reduce((s, t) => s + (Array.isArray(t.connections) ? t.connections.length : 0), 0) : null),
	], tunnels?.length ? [{
		title: "Tunnels",
		columns: [{ key: "name", label: "Tunnel" }, { key: "status", label: "Status" }, { key: "conns", label: "Connections", unit: "count" }, { key: "type", label: "Type" }, { key: "since", label: "Last change" }],
		rows: tunnels.map((t) => ({
			name: String(t.name ?? "—"),
			status: statusLabel(String(t.status ?? "unknown")),
			conns: Array.isArray(t.connections) ? t.connections.length : 0,
			type: String(t.tun_type ?? "—"),
			since: shortDate(t.status === "healthy" ? t.conns_active_at : t.conns_inactive_at ?? t.conns_active_at),
		})),
	}] : [], errors.tunnels, [
		...(tunnels === null ? ["Tunnels need the token permission Cloudflare Tunnel → Read."] : []),
		...down.map((t) => `⚠ Tunnel "${String(t.name)}" is ${String(t.status)}.`),
	]);

	// ---- Private networks ----------------------------------------------------------------
	const networks = section("zt-inv-networks", "Private networks", "REST /teamnet/routes, /teamnet/virtual_networks", [
		m("Private network routes", routes ? routes.length : null),
		m("Virtual networks", vnets ? vnets.length : null),
	], routes?.length ? [{
		title: "Routes",
		columns: [{ key: "network", label: "Network" }, { key: "comment", label: "Comment" }],
		rows: routes.slice(0, 25).map((r) => ({ network: String(r.network ?? "—"), comment: String(r.comment || "—") })),
	}] : [], errors.networks, routes === null ? ["Routes need the token permission Cloudflare Tunnel → Read."] : []);

	// ---- Configuration ---------------------------------------------------------------------
	const enabledRules = rules?.filter((r) => r.enabled) ?? null;
	const config = section("zt-inv-config", "Configuration", "REST /access/*, /gateway/*, /dlp/profiles, /dex", [
		m("Access applications", apps ? apps.length : null),
		m("Identity providers", idps ? idps.length : null),
		m("Access groups", groups ? groups.length : null),
		m("Service tokens", tokens ? tokens.length : null),
		m("Device posture rules", posture ? posture.length : null),
		m("Gateway policies", rules ? rules.length : null, "count", enabledRules ? `${enabledRules.length} enabled` : undefined),
		m("Gateway locations", locations ? locations.length : null),
		m("Gateway lists", lists ? lists.length : null),
		m("DLP profiles", dlp ? dlp.length : null),
		m("DEX tests", dex ? dex.length : null),
	], [
		...(org ? [kv("Organization", [
			["Team name", String(org.name ?? "—")],
			["Team domain", String(org.auth_domain ?? "—")],
		])] : []),
		...(rules?.length ? [
			countTable("Gateway policies by action", rules.map((r) => String(r.action ?? "unknown")), "Action", rules.map((r) => !!r.enabled)),
			countTable("Gateway policies by traffic type", rules.map((r) => (Array.isArray(r.filters) ? r.filters.join(" + ") : "unknown") || "unknown"), "Traffic", rules.map((r) => !!r.enabled)),
		] : []),
		...(apps?.length ? [countTable("Access applications by type", apps.map((x) => String(x.type ?? "unknown")), "Type")] : []),
	], errors.config, [
		...(apps === null || rules === null ? ["Some counts need the token permissions Access: Apps and Policies → Read and Zero Trust → Read."] : []),
	]);

	return [seats, devicesSection, tunnelsSection, networks, config];
}

// ---------------------------------------------------------------------------
// Helpers

function section(id: string, title: string, source: string, metrics: Metric[], tables: Table[], errors: string[], notes: string[]): Section {
	return { id, group: "Zero Trust · Seats & inventory", title, source, metrics, tables, notes, errors };
}

function m(label: string, value: number | null, unit: Unit = "count", hint?: string): Metric {
	return hint ? { label, value, unit, hint } : { label, value, unit };
}

function kv(title: string, pairs: [string, string][]): Table {
	return { title, columns: [{ key: "k", label: "Item" }, { key: "v", label: "Value" }], rows: pairs.map(([k, v]) => ({ k, v })) };
}

/** Count rows per key; optionally also how many are enabled. */
function countTable(title: string, keys: string[], label: string, enabled?: boolean[]): Table {
	const agg = new Map<string, { n: number; on: number }>();
	keys.forEach((k, i) => {
		const a = agg.get(k) ?? { n: 0, on: 0 };
		a.n++;
		if (enabled?.[i]) a.on++;
		agg.set(k, a);
	});
	const columns = [{ key: "k", label }, { key: "n", label: "Count", unit: "count" as Unit }];
	if (enabled) columns.push({ key: "on", label: "Enabled", unit: "count" as Unit });
	return {
		title,
		columns,
		rows: [...agg.entries()].sort((x, y) => y[1].n - x[1].n).map(([k, v]) => ({ k, n: v.n, ...(enabled ? { on: v.on } : {}) })),
	};
}

function fleetTable(title: string, entries: unknown): Table {
	const rows = Array.isArray(entries) ? (entries as Obj[]) : [];
	return {
		title,
		columns: [{ key: "k", label: "Value" }, { key: "n", label: "Devices", unit: "count" }],
		rows: rows.map((e) => ({ k: String(e.value ?? "—"), n: num(e.uniqueDevicesTotal) })),
	};
}

function componentName(name: string): string {
	const names: Record<string, string> = {
		users: "Seats (users)", browser_isolation_adv: "Browser Isolation (advanced)", dlp: "DLP", casb: "CASB",
		internal_dns_record_quota: "Internal DNS record quota", dex: "DEX", email_security: "Email security",
	};
	return names[name] ?? name.replace(/_/g, " ");
}

function formatComponent(c: Obj): string {
	const v = num(c.value);
	if (c.name === "users" || /quota/.test(String(c.name))) return v.toLocaleString("en");
	return v >= 1 ? "Included" : "Not included";
}

function statusLabel(s: string): string {
	return s === "healthy" ? "● Healthy" : s === "degraded" ? "▲ Degraded" : s === "down" ? "⛔ Down" : s === "inactive" ? "○ Inactive" : s;
}

/** Shows enough to recognise a user without printing full addresses on screen. */
function maskEmail(e: string): string {
	const at = e.indexOf("@");
	if (at < 1) return e;
	const name = e.slice(0, at);
	return `${name.slice(0, 2)}${"•".repeat(Math.max(1, Math.min(6, name.length - 2)))}${e.slice(at)}`;
}

function shortDate(v: unknown): string {
	if (typeof v !== "string" || !v) return "never";
	const d = new Date(v);
	return Number.isNaN(d.getTime()) ? "—" : d.toISOString().slice(0, 16).replace("T", " ") + " UTC";
}

function get(row: unknown, path: string): unknown {
	let cur: unknown = row;
	for (const part of path.split(".")) {
		if (cur === null || typeof cur !== "object") return undefined;
		cur = (cur as Obj)[part];
	}
	return cur;
}

function num(v: unknown): number {
	const n = typeof v === "number" ? v : Number(v);
	return Number.isFinite(n) ? n : 0;
}
