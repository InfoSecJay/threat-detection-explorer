import { describe, expect, it } from "vitest";

import {
  actorSummary,
  capped,
  day,
  detectionDetail,
  diffSummary,
  prune,
  searchResult,
  slimRule,
  truncate,
} from "../src/format.js";

describe("helpers", () => {
  it("prune drops empty values but keeps false and zero", () => {
    expect(prune({ a: undefined, b: null, c: "", d: [], e: {}, f: 0, g: false, h: ["x"] })).toEqual({ f: 0, g: false, h: ["x"] });
  });

  it("day slices instead of parsing, so midnight-UTC dates never shift a day", () => {
    expect(day("2026-07-23T00:00:00Z")).toBe("2026-07-23");
    expect(day("2026-07-23")).toBe("2026-07-23");
    expect(day(null)).toBeUndefined();
    expect(day("short")).toBeUndefined();
  });

  it("truncate reports how much was cut", () => {
    expect(truncate("abcdef", 10)).toBe("abcdef");
    expect(truncate("abcdef", 3)).toBe("abc\n... [truncated 3 more characters; see the rule page]");
    expect(truncate("", 3)).toBeUndefined();
  });

  it("capped counts the remainder", () => {
    expect(capped([1, 2, 3], 2)).toEqual({ items: [1, 2], omitted: 1 });
    expect(capped(undefined, 2)).toEqual({ items: [], omitted: 0 });
  });
});

const ROW = {
  id: "2ac49dea-18b7-5784-9f09-334901e3c0b7",
  title: "Suspicious Cross-User Process Spawn",
  source: "sigma",
  severity: "medium",
  status: "experimental",
  rule_modality: "rule",
  language: "sigma",
  mitre_techniques: ["T1055", "T1134"],
  platforms: ["windows"],
  data_sources: ["sysmon"],
  event_types: ["process_creation"],
  equivalent_sources: ["elastic", "sigma", "splunk"],
  rule_created_date: "2026-07-23T00:00:00Z",
  rule_modified_date: "2026-08-03T08:35:04Z",
  quality_score: 72,
  source_rule_url: "https://github.com/SigmaHQ/sigma/blob/07ec293/rules/x.yml",
  mitre_groups: [],
};

describe("slimRule", () => {
  it("keeps triage fields, links both pages, and lists other vendors only", () => {
    const slim = slimRule(ROW);
    expect(slim).toMatchObject({
      id: ROW.id,
      techniques: ["T1055", "T1134"],
      created: "2026-07-23",
      modified: "2026-08-03",
      same_behaviour_in: ["elastic", "splunk"],
      url: `https://detectionexplorer.io/detections/${ROW.id}`,
      upstream: ROW.source_rule_url,
    });
    expect(slim).not.toHaveProperty("modality");
    expect(slim).not.toHaveProperty("mitre_groups");
  });

  it("shows a non-default modality", () => {
    expect(slimRule({ ...ROW, rule_modality: "hunting" }).modality).toBe("hunting");
  });
});

describe("searchResult", () => {
  it("gives the next offset only while more rows remain", () => {
    expect(searchResult({ total: 30, items: Array(20).fill(ROW) }, 0).next_offset).toBe(20);
    expect(searchResult({ total: 30, items: Array(10).fill(ROW) }, 20).next_offset).toBeUndefined();
  });
});

describe("detectionDetail", () => {
  const detail = {
    ...ROW,
    rule_id: "d2b7a134",
    detection_logic: "x".repeat(25_000),
    raw_content: "title: x",
    extracted_process_names: ["notepad.exe"],
    extracted_event_ids: [],
    source_rule_url_latest: "https://github.com/SigmaHQ/sigma/blob/master/rules/x.yml",
  };

  it("groups observables, caps the logic, and omits the raw file unless asked", () => {
    const out = detectionDetail(detail, false);
    expect(out.observables).toEqual({ process_names: ["notepad.exe"] });
    expect(out.detection_logic).toContain("[truncated 5000 more characters");
    expect(out).not.toHaveProperty("raw_content");
    expect(out.upstream_latest).toContain("/blob/master/");
    expect(detectionDetail(detail, true).raw_content).toBe("title: x");
  });
});

describe("diffSummary", () => {
  const A = "aaaa";
  const B = "bbbb";
  const diff = {
    rules: [
      { ...ROW, id: A },
      { ...ROW, id: B },
    ],
    observables: [
      { type: "process", value: "notepad.exe", present_in: [A, B], negated_in: [], shared: true },
      { type: "process", value: "calc.exe", present_in: [A], negated_in: [], shared: false },
      ...Array.from({ length: 40 }, (_, i) => ({ type: "field", value: `f${i}`, present_in: [B], negated_in: [], shared: false })),
      { type: "path", subtype: "dir", value: "C:\\Temp", present_in: [B], negated_in: [A], shared: false },
    ],
    axes: {
      mitre_techniques: [
        { value: "T1055", present_in: [A, B] },
        { value: "T1036", present_in: [B] },
      ],
    },
    summary: { rules: 2, observables: 43 },
    missing_ids: [],
  };

  it("splits shared, per-rule and excluded observables and caps each list", () => {
    const out = diffSummary(diff, 30);
    expect(out.shared_observables).toEqual(["process: notepad.exe"]);
    expect(out.unique_observables_by_rule?.[A]).toEqual({ observables: ["process: calc.exe"], omitted: 0 });
    expect(out.unique_observables_by_rule?.[B].observables).toHaveLength(30);
    expect(out.unique_observables_by_rule?.[B].omitted).toBe(11);
    expect(out.exclusions).toEqual(["path.dir: C:\\Temp (excluded by aaaa)"]);
    expect(out.axes).toEqual({ mitre_techniques: { in_all: ["T1055"], only_some: ["T1036 [bbbb]"] } });
    expect(out.url).toBe("https://detectionexplorer.io/compare?ids=aaaa,bbbb");
  });
});

describe("actorSummary", () => {
  it("lists gaps, ranks covered techniques and says what coverage means", () => {
    const out = actorSummary({
      id: "G0016",
      name: "APT29",
      technique_count: 3,
      covered_technique_count: 2,
      gap_count: 1,
      techniques: [
        { technique_id: "T1001", technique_name: "Data Obfuscation", has_rules: false, rule_count: 0 },
        { technique_id: "T1059", technique_name: "Command and Scripting Interpreter", has_rules: true, rule_count: 5 },
        { technique_id: "T1566.002", technique_name: "Spearphishing Link", has_rules: true, rule_count: 814 },
      ],
      rules: [ROW],
      aliases: Array.from({ length: 30 }, (_, i) => `alias${i}`),
    });
    expect(out.gaps).toEqual(["T1001 Data Obfuscation"]);
    expect(out.covered_techniques?.map((t) => t.id)).toEqual(["T1566.002", "T1059"]);
    expect(out.aliases).toHaveLength(12);
    expect(out.url).toBe("https://detectionexplorer.io/actors/G0016");
    expect(out.note).toContain("not that an environment detects it");
  });
});
