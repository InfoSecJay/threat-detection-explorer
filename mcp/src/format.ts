// Shape API responses for a model's context window.
//
// Several endpoints return far more than an agent needs (an observable
// diff of two rules is ~165 KB, an actor page ~40 KB). These functions
// keep the fields a detection engineer reasons with, cap long lists and
// say how much was left out, and always carry a detectionexplorer.io link
// so the human can click through to the full page.

import { SITE_URL } from "./client.js";

/* eslint-disable @typescript-eslint/no-explicit-any */
type Json = any;

export const ruleUrl = (id: string) => `${SITE_URL}/detections/${id}`;
export const actorUrl = (id: string) => `${SITE_URL}/actors/${id}`;
export const techniqueUrl = (id: string) => `${SITE_URL}/mitre/${id}`;

/** Drop undefined / null / empty-string / empty-array / empty-object values. */
export function prune<T extends Record<string, unknown>>(obj: T): Partial<T> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(obj)) {
    if (value === undefined || value === null || value === "") continue;
    if (Array.isArray(value) && value.length === 0) continue;
    if (typeof value === "object" && !Array.isArray(value) && Object.keys(value as object).length === 0) continue;
    out[key] = value;
  }
  return out as Partial<T>;
}

/**
 * Date-only view of an API timestamp. Sliced, never parsed: rule dates are
 * stored as midnight UTC and a local-time conversion renders them a day
 * early west of UTC (the DX-09 bug on the site).
 */
export function day(value: unknown): string | undefined {
  return typeof value === "string" && value.length >= 10 ? value.slice(0, 10) : undefined;
}

export function truncate(text: unknown, max: number): string | undefined {
  if (typeof text !== "string" || text === "") return undefined;
  if (text.length <= max) return text;
  return `${text.slice(0, max)}\n... [truncated ${text.length - max} more characters; see the rule page]`;
}

/** Cap a list and report the remainder. */
export function capped<T>(items: T[] | undefined, max: number): { items: T[]; omitted: number } {
  const list = items ?? [];
  return { items: list.slice(0, max), omitted: Math.max(0, list.length - max) };
}

/** Where a content: term hit (#167): one line of context, and whether the
 *  term sits only inside an exclusion, in which case the rule does not
 *  detect it. */
function contentMatch(s: Json | undefined) {
  if (!s || typeof s !== "object") return undefined;
  return prune({
    context: `${s.before ?? ""}${s.match ?? ""}${s.after ?? ""}`,
    match: s.match,
    field: s.field,
    exclusion_only: s.negated ? true : undefined,
  });
}

export function slimRule(r: Json) {
  const others = Array.isArray(r.equivalent_sources)
    ? r.equivalent_sources.filter((s: string) => s !== r.source)
    : undefined;
  return prune({
    id: r.id,
    title: r.title,
    source: r.source,
    severity: r.severity,
    status: r.status,
    modality: r.rule_modality && r.rule_modality !== "rule" ? r.rule_modality : undefined,
    language: r.language,
    techniques: r.mitre_techniques ?? r.techniques,
    platforms: r.platforms,
    data_sources: r.data_sources,
    event_types: r.event_types,
    created: day(r.rule_created_date ?? r.created ?? r.date),
    modified: day(r.rule_modified_date),
    quality: r.quality_score,
    same_behaviour_in: others,
    // #166: a PyPanther port of a panther-analysis rule; coverage figures
    // count the pair once, so do not count both when summarising.
    port_of: r.duplicate_of ? { id: r.duplicate_of, url: ruleUrl(r.duplicate_of) } : undefined,
    content_match: contentMatch(r.content_snippet),
    url: r.id ? ruleUrl(r.id) : undefined,
    upstream: r.source_rule_url,
  });
}

/** One line's worth of rule, for long secondary lists (digest, actor, observable). */
export function tinyRule(r: Json) {
  return prune({
    id: r.id,
    title: r.title,
    source: r.source,
    severity: r.severity,
    techniques: r.mitre_techniques ?? r.techniques,
    date: day(r.rule_modified_date ?? r.rule_created_date ?? r.created ?? r.date),
    url: r.id ? ruleUrl(r.id) : undefined,
  });
}

export function searchResult(page: Json, offset: number) {
  const items: Json[] = page.items ?? [];
  const next = offset + items.length;
  return prune({
    total: page.total,
    offset,
    returned: items.length,
    next_offset: next < (page.total ?? 0) ? next : undefined,
    results: items.map(slimRule),
  });
}

const OBSERVABLE_FIELDS: Array<[string, string]> = [
  ["process_names", "extracted_process_names"],
  ["event_ids", "extracted_event_ids"],
  ["file_paths", "extracted_file_paths"],
  ["registry_keys", "extracted_registry_keys"],
  ["network_indicators", "extracted_network_indicators"],
  ["api_actions", "extracted_api_actions"],
  ["source_tables", "extracted_source_tables"],
  ["target_resources", "extracted_target_resources"],
  ["fields_used", "extracted_fields_used"],
];

export function detectionDetail(d: Json, includeRaw: boolean) {
  const observables: Record<string, unknown> = {};
  for (const [label, key] of OBSERVABLE_FIELDS) {
    if (Array.isArray(d[key]) && d[key].length) observables[label] = d[key];
  }
  return prune({
    id: d.id,
    title: d.title,
    source: d.source,
    upstream_rule_id: d.rule_id,
    description: d.description,
    author: d.author,
    status: d.status,
    severity: d.severity,
    modality: d.rule_modality,
    building_block: d.is_building_block || undefined,
    language: d.language,
    platforms: d.platforms,
    domains: d.domains,
    products: d.products,
    data_sources: d.data_sources,
    event_types: d.event_types,
    mitre_tactics: d.mitre_tactics,
    mitre_techniques: d.mitre_techniques,
    mitre_groups: d.mitre_groups,
    mitre_software: d.mitre_software,
    use_cases: d.use_cases,
    tags: d.tags,
    false_positives: d.false_positives,
    references: d.references,
    deploy_notes: d.deploy_notes,
    detection_logic: truncate(d.detection_logic, 20_000),
    observables,
    query_complexity: d.query_complexity,
    quality_score: d.quality_score,
    created: day(d.rule_created_date),
    modified: day(d.rule_modified_date),
    last_synced: day(d.updated_at),
    // #166: the other half of a Panther/PyPanther pair, both directions.
    same_rule: Array.isArray(d.duplicate_links) && d.duplicate_links.length
      ? d.duplicate_links.map((l: Json) => ({
          relation: l.relation, id: l.id, source: l.source, title: l.title, url: ruleUrl(l.id),
        }))
      : undefined,
    url: ruleUrl(d.id),
    upstream_pinned: d.source_rule_url,
    upstream_latest: d.source_rule_url_latest,
    raw_content: includeRaw ? truncate(d.raw_content, 50_000) : undefined,
    note: "Rule content is licensed by its upstream repository; check the upstream link before redistributing.",
  });
}

function slimRelated(r: Json) {
  return prune({
    id: r.id,
    title: r.title,
    source: r.source,
    severity: r.severity,
    language: r.language,
    score: r.score,
    why: r.reasons,
    url: r.id ? ruleUrl(r.id) : undefined,
  });
}

export function relatedSummary(d: Json) {
  return prune({
    id: d.id,
    same_behaviour_other_vendors: (d.related ?? []).map(slimRelated),
    same_source: (d.same_source ?? []).map(slimRelated),
    technique_overlap_only: (d.technique_only ?? []).map(slimRelated),
    note: "same_behaviour_* share observables (process, event ID, path, API action...) with the rule; technique_overlap_only shares only ATT&CK tags.",
  });
}

const obsLabel = (o: Json) => `${o.type}${o.subtype ? `.${o.subtype}` : ""}: ${o.value}`;

export function diffSummary(d: Json, perRuleCap = 30) {
  const rules: Json[] = d.rules ?? [];
  const observables: Json[] = d.observables ?? [];
  const shared = observables.filter((o) => o.shared);
  const negated = observables.filter((o) => Array.isArray(o.negated_in) && o.negated_in.length);
  const unique: Record<string, { observables: string[]; omitted: number }> = {};
  for (const rule of rules) {
    const mine = observables.filter((o) => !o.shared && Array.isArray(o.present_in) && o.present_in.length === 1 && o.present_in[0] === rule.id);
    const { items, omitted } = capped(mine.map(obsLabel), perRuleCap);
    unique[rule.id] = { observables: items, omitted };
  }
  const axes: Record<string, unknown> = {};
  for (const [axis, entries] of Object.entries<Json[]>(d.axes ?? {})) {
    const inAll = entries.filter((e) => (e.present_in ?? []).length === rules.length).map((e) => e.value);
    const partial = entries.filter((e) => (e.present_in ?? []).length < rules.length).map((e) => `${e.value} [${(e.present_in ?? []).join(", ")}]`);
    axes[axis] = prune({ in_all: inAll, only_some: partial });
  }
  const sharedCapped = capped(shared.map(obsLabel), 60);
  const negatedCapped = capped(negated.map((o) => `${obsLabel(o)} (excluded by ${o.negated_in.join(", ")})`), 30);
  return prune({
    summary: d.summary,
    rules: rules.map(slimRule),
    shared_observables: sharedCapped.items,
    shared_omitted: sharedCapped.omitted || undefined,
    unique_observables_by_rule: unique,
    exclusions: negatedCapped.items,
    exclusions_omitted: negatedCapped.omitted || undefined,
    axes,
    missing_ids: d.missing_ids,
    url: `${SITE_URL}/compare?ids=${rules.map((r) => r.id).join(",")}`,
  });
}

export function techniqueSummary(p: Json) {
  const sources: Record<string, unknown> = {};
  for (const [source, info] of Object.entries<Json>(p.sources ?? {})) {
    const top: Record<string, string[]> = {};
    for (const [kind, values] of Object.entries<Json[]>(info.observables ?? {})) {
      top[kind] = values.slice(0, 5).map((v) => `${v.value} (${v.rules})`);
    }
    sources[source] = prune({ rules: info.rules, hygiene_avg: info.hygiene_avg, top_observables: top });
  }
  const groups = capped(p.groups ?? [], 15);
  const software = capped(p.software ?? [], 15);
  return prune({
    technique_id: p.technique_id,
    name: p.name,
    total_rules: p.total_rules,
    by_severity: p.by_severity,
    momentum: p.momentum,
    rules_by_source: sources,
    groups_using_it: groups.items.map((g: Json) => `${g.id} ${g.name}`),
    groups_omitted: groups.omitted || undefined,
    software_using_it: software.items.map((s: Json) => `${s.id} ${s.name} (${s.type})`),
    software_omitted: software.omitted || undefined,
    url: techniqueUrl(p.technique_id),
  });
}

export function actorSummary(a: Json, rulesCap = 25) {
  const techniques: Json[] = a.techniques ?? [];
  const gaps = techniques.filter((t) => !t.has_rules).map((t) => `${t.technique_id} ${t.technique_name}`);
  const covered = [...techniques]
    .filter((t) => t.has_rules)
    .sort((x, y) => (y.rule_count ?? 0) - (x.rule_count ?? 0));
  const coveredCapped = capped(covered, 30);
  const rules = capped(a.rules ?? [], rulesCap);
  const software = capped(a.associated_software ?? [], 15);
  return prune({
    id: a.id,
    name: a.name,
    kind: a.kind,
    aliases: (a.aliases ?? []).slice(0, 12),
    origin_country: a.origin_country,
    motivations: a.motivations,
    target_sectors: a.target_sectors,
    coverage_scope: a.coverage_scope,
    match_mode: a.match_mode,
    technique_count: a.technique_count,
    techniques_with_rules: a.covered_technique_count,
    techniques_without_rules: a.gap_count,
    weighted_coverage: a.weighted_coverage,
    gaps,
    covered_techniques: coveredCapped.items.map((t) =>
      prune({ id: t.technique_id, name: t.technique_name, rules: t.rule_count, by_source: t.rule_count_by_source }),
    ),
    covered_omitted: coveredCapped.omitted || undefined,
    coverage_by_source: a.coverage_by_source,
    match_counts: a.match_counts,
    named_rules: rules.items.map(tinyRule),
    named_rules_omitted: rules.omitted || undefined,
    associated_software: software.items.map((s: Json) => `${s.id} ${s.name} (${s.type}, ${s.rule_count ?? 0} rules)`),
    url: actorUrl(a.id),
    note: "A technique counts as covered when at least one public rule in the scoped sources maps to it. That says rules exist, not that an environment detects it.",
  });
}

export function observableSummary(o: Json, rulesCap = 25) {
  const coOccurring: Record<string, string[]> = {};
  for (const [kind, values] of Object.entries<Json[]>(o.co_occurring ?? {})) {
    coOccurring[kind] = values.slice(0, 5).map((v) => `${v.value} (${v.rules})`);
  }
  const rules = capped(o.rules ?? [], rulesCap);
  return prune({
    type: o.type,
    value: o.value,
    total_rules: o.total_rules,
    excluded_in_rules: o.negated_in,
    by_source: o.by_source,
    by_severity: o.by_severity,
    by_platform: o.by_platform,
    top_techniques: (o.by_technique ?? []).slice(0, 10).map((t: Json) => `${t.technique_id} (${t.rules})`),
    fields: (o.fields ?? []).slice(0, 8).map((f: Json) => `${f.field} (${f.rules})`),
    co_occurring: coOccurring,
    rules: rules.items.map(tinyRule),
    rules_omitted: rules.omitted || undefined,
    url: `${SITE_URL}/observables/${encodeURIComponent(o.type)}/${encodeURIComponent(o.value)}`,
  });
}

export function digestSummary(d: Json, cap = 20) {
  const created = capped(d.new_rules ?? [], cap);
  const modified = capped(d.modified_rules ?? [], cap);
  return prune({
    period: d.period,
    summary: d.summary,
    themes: (d.themes ?? []).map((t: Json) =>
      prune({ technique: `${t.technique_id} ${t.technique_name}`, tactic: t.tactic, rules: t.rules, sources: t.sources }),
    ),
    new_rules: created.items.map(tinyRule),
    new_rules_omitted: created.omitted || undefined,
    modified_rules: modified.items.map(tinyRule),
    modified_rules_omitted: modified.omitted || undefined,
    removed_rules: (d.removed_rules ?? []).map((r: Json) =>
      prune({ id: r.id, title: r.title, source: r.source, techniques: r.mitre_techniques, removed: day(r.removed) }),
    ),
    momentum: d.momentum ? prune({ gainers: d.momentum.gainers, losers: d.momentum.losers }) : undefined,
    url: `${SITE_URL}/digest`,
  });
}

export function corpusOverview(stats: Json, repos: Json[]) {
  return prune({
    total_rules: stats.total,
    rules_by_source: stats.by_source,
    by_severity: stats.by_severity,
    by_modality: stats.by_modality,
    repositories: repos.map((r) =>
      prune({ name: r.name, url: r.url, rules: r.rule_count, last_sync: r.last_sync_at, commit: r.last_commit_hash, status: r.status }),
    ),
    methodology: `${SITE_URL}/methodology`,
    note: "Rules are synced nightly from each upstream repository and keep their upstream licenses.",
  });
}

export function queryLanguage(f: Json) {
  return {
    usage:
      "Lucene-style: field:value, quotes for phrases, AND / OR / NOT, parentheses, trailing * for prefixes. Bare words match whole words in titles, descriptions, tags and rule IDs (and extracted process names), never the rule body; use content: to search the rule body.",
    fields: (f.fields ?? []).map((x: Json) =>
      prune({ names: x.aliases, kind: x.kind, meaning: x.description, examples: x.examples }),
    ),
    reference: `${SITE_URL}/query`,
  };
}
