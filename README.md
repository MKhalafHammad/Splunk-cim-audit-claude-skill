# CIM Compliance Auditor

A [Claude Skill](https://docs.claude.com/en/docs/agents-and-tools/agent-skills/overview) for auditing how well a Splunk environment normalises its data into the Common Information Model.

Point Claude at a Splunk estate and this skill gives it the method a senior detection engineer would use: diagnose in the right order, measure the right things, and refuse to call something a gap until the data says it is one.

---

## The problem this solves

Most CIM audits produce a number that is wrong in a specific, predictable way.

A tool reports a model as "34% compliant." That figure divides the fields that are populated by every field the data model defines. But no single source ever fills every field a model has — a firewall does not carry file hashes, a DNS feed does not carry HTTP methods. The score counts fields the source was never meant to produce as failures, so healthy data looks broken and the report sends engineers to fix things that were never wrong.

The second failure is order. Audits jump straight to field coverage, but a data model only sees an event if three things are true first: the index is named in the model's index macro, the event is tagged into the model, and only then are the fields read. A perfectly parsed source behind a closed macro reports zero. Measuring fields before checking the gates produces confident, useless numbers.

This skill fixes both. It sorts every field into three buckets so the score only counts fields that genuinely apply, and it diagnoses in the order macro → tag → parser so remediation goes to the actual cause.

---

## What it does

- **Starts with data collection,** not assumptions. A discovery phase reads the platform and CIM version, add-ons, indexes, the index-to-sourcetype map, macros, data models, tags, and licence usage into an Environment Profile before any finding is written.
- **Audits field-level CIM compliance** per data model, with three numbers per model instead of one misleading percentage.
- **Diagnoses every gap** to one of macro, tag, parser, or value-normalisation — using queries, never inference.
- **Runs at two resolutions:** per index and model (fast, finds the weak models), or per sourcetype (precise, produces the actionable per-source fix list).
- **Checks findings before booking them,** including the false-negative trap where a raw-text availability check silently lies on JSON and XML sources.
- **Sets expectations from the vendor add-on, for any vendor,** so a field is only ever a gap if the source's own add-on says it should map. The expectation is read from the installed add-on's own configuration (the eventtypes that classify the sourcetype, the CIM tags on them, the tags each model requires, the fields its `props.conf` produces) and cross-checked against the add-on's published "Source types and CIM" page. No vendor list to maintain: Windows, Linux, FortiGate, Palo Alto, or anything else goes through the same steps.
- **Produces the deliverable:** a field-level compliance workbook, macro findings, and a dependency-ordered remediation plan.
- **Needs no extra app.** The whole audit runs on raw SPL and a few REST calls. A validator app such as SA-cim_vladiator is optional, used only as a cross-check if it is already installed.

---

## Installation

Clone or download this repository, then place the `cim-compliance-auditor` folder in your skills directory:

```
~/.claude/skills/cim-compliance-auditor/
```

Or for a project-scoped install:

```
.claude/skills/cim-compliance-auditor/
```

The skill loads automatically when a conversation involves CIM compliance, index macros, data model coverage, `fieldsummary`, or sourcetype-to-CIM mapping. You can also invoke it directly.

---

## Usage

Just describe the work. The skill triggers on the subject matter:

> "Audit CIM compliance for our Splunk environment — 11 indexes, CIM 8.5."

> "The Authentication data model is nearly empty but the logs are clearly there. Find out why."

> "This field shows 0% coverage. Is it a real gap or does the source just not produce it?"

> "Run the audit per sourcetype so I can give the client a per-source fix list."

> "Our Windows events aren't reaching Malware. Macro, tag, or parser?"

**One thing to know up front:** unless Claude has direct access to your search head, it cannot run SPL against your environment. You run the queries; Claude supplies them, then does the classification, arithmetic, and document production from your results. The skill is built around that split — every phase produces copy-ready queries and expects results back. The intake only asks what the environment cannot tell (access, scope, deliverable format, whether remediation is in scope); everything else is collected in the first phase.

---

## What's inside

| File | What it covers |
|---|---|
| `SKILL.md` | The method. Three buckets, three numbers, four fix types, the availability habit, the audit engine (raw SPL, validator apps optional), the eleven-phase runbook, reporting style. |
| `references/discovery_kit.md` | Phase 1 data collection. The queries that build the Environment Profile: platform and CIM version, add-ons, indexes and retention, naming pattern, index-to-sourcetype map, sprawl, structured versus delimited, CIM macros verbatim, data models and acceleration, the model routing matrix, tag coverage, licence usage, and the CIM expectation per sourcetype resolved from its vendor add-on, with UI fallbacks. |
| `references/query_kit.md` | Copy-ready SPL for the analysis phases, with every placeholder taken from the Environment Profile: macro reading, per-field coverage from the model's own field list, the raw-versus-mapped availability check, tag gates, value formats, and volume-based speed tiers. |
| `references/investigation_kit.md` | Verifying a finding before it is booked. The structured-source false negative and the `fieldsummary` method, the value-versus-name rule, a per-finding checklist, the batch reversal pass for correcting an existing workbook, and detection tuning traced back to normalisation. |
| `references/sourcetype_mapping_kit.md` | The optional per-sourcetype audit. Real index-to-sourcetype mapping, how the vendor add-on CIM expectation is used (with known pitfalls), the macro-vs-tag-vs-parser diagnosis, per-sourcetype coverage, and findings like incidental mapping and double-ingest. |
| `references/worked_example.md` | One environment audited end to end, showing how each phase played out and how ambiguous results were resolved. |

---

## The method in brief

**Three buckets.** Every field is *Mapped* (the source carries it), *Not mapped yet* (the data is in the raw event but nothing extracts it — the real work list), or *Not produced by source* (the source does not emit it, excluded from scoring so it cannot unfairly drag the number down).

**Three numbers per model.** The raw percentage, the corrected mapped percentage counting only applicable fields, and the fully-compliant percentage counting only fields at 90% coverage or better. The gap between the last two is how much partial work remains.

**Four fix types, diagnosed in order.** *Macro* (the index is not in the model's index list — first gate, cheapest fix), *Tag* (events reach the index but are not claimed by the model), *Parser* (the value is in the raw event but not extracted), *Alias/Value* (the field extracts but the value is in vendor form). Each is confirmed by a query, never guessed, because a parser fix on events that never reach the model does nothing.

**A gap is a gap regardless of method.** Auditing per index, per model, or per sourcetype changes which gaps are easy to see, not which gaps exist. The audit is complete when the gaps are resolved, not when a particular view has been produced.

---

## Design principles

**Nothing about the environment is assumed.** Index names, sourcetype-to-index mapping, macro definitions, add-on presence — all read from the environment into the Environment Profile, never inferred from a spreadsheet or a naming convention. No finding is written until the profile is complete.

**The skill carries the method, never a client's data.** Real index names, sourcetypes, hosts, and findings stay in the engagement's profile and deliverables, not in the skill or its examples.

**Vendor add-ons decide what should map.** Whether a source is expected to feed a CIM model comes from its add-on, not from the device category. The skill resolves it the same way for every vendor: the installed add-on's eventtypes, tags, and props first (exact for the installed version), the add-on's published CIM table as the cross-check, the Splunkbase package when the add-on is not installed, and a judgement from the events only when no add-on exists. Each expectation carries its evidence label, and a disagreement between the config and the documentation is a finding in itself. Active Directory maps to no CIM model per Splunk's own Windows add-on, so its empty CIM fields are correct rather than a failure. Raw `auditd` is n/a until translated into `linux_audit`. Getting this from the vendor is what stops an audit raising gaps that can never be closed.

**Availability before accusation.** A low number is measured against how often the value actually appears in the raw log. Mapped far below raw availability is a real gap; mapped roughly equal to raw availability is not a gap at all.

**`match(_raw, ...)` lies on structured sources.** On JSON and XML feeds the value lives in a parsed field, not a matchable substring, so a raw-text check returns zero on fields that are fully populated. Use `fieldsummary` there. This single trap accounts for a large share of false findings.

**Exclusions stay visible.** Fields set aside as not-produced are listed with their evidence, never silently dropped, so every exclusion is auditable.

---

## Requirements

- Claude with Agent Skills support.
- A Splunk environment with the CIM app installed, and access to run searches and read macro definitions. REST access and read access to `_internal` let the discovery phase collect everything; where they are missing, the profile records the gap and the UI fallbacks cover it.
- No additional Splunk app is required.
- Read access over REST to add-on configuration (eventtypes, tags, props, transforms) so each sourcetype's CIM expectation can be read from the installed add-on.
- For the documentation cross-check, either web access for Claude or the add-on's "Source types and CIM" page pasted in. The skill finds the right page from the add-on's name; no per-vendor list is needed.

---

## Contributing

Corrections from real engagements are welcome, particularly vendor add-on CIM mappings confirmed against official documentation. If you add a mapping, please note its source: the published add-on CIM table, the add-on's `tags.conf`, or observed behaviour.

---

## License

MIT
