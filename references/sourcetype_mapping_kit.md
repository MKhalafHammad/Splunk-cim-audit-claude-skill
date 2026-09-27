# CIM Sourcetype Mapping Kit

The base audit works per index and data model. This kit is the second way to run it: **per sourcetype**.
Use it when the index-level numbers are too blended to act on, when a client wants to know which specific
sources to fix, or when joining CIM compliance to a log utilisation or licensing review. It produces one
row per sourcetype and field, and it brings into focus classes of problem that are hard to isolate at the
index level.

A word on scope before the method. Nothing here is a sourcetype-only problem. Every gap this kit helps you
find — a macro exclusion, an untagged source, an unextracted field, a source mapping data it should not,
the same data ingested twice — is a fact about the environment that exists regardless of how the audit is
run. The sourcetype pass is a sharper lens, not a different set of gaps. So when this kit says the pass
"surfaces" or "reveals" a finding, read that as makes it easy to see, not is the only way it exists. An
audit is complete when the gaps are resolved, not when a particular view has been produced. If an
engagement stays at the index level, these same findings must still be chased down and fixed.

Run this as an option, not a replacement. The index-level audit answers "is this model healthy." The
sourcetype pass answers "which source, specifically, is or is not mapping, and what is the exact fix." A
mature engagement often does the index pass first to find the weak models, then the sourcetype pass on
those models to produce the actionable per-source fix list.

---

## Part 1. Why per-sourcetype, and what it brings into focus

An index holds many sourcetypes. An index-level coverage number blends them, so a field mapped on one
sourcetype and absent on another averages into a single blurred figure that is true of neither. Three real error classes are hard to isolate at the index level and come into focus per
sourcetype (they exist in both views and must be fixed either way):

- **Blended numbers hiding both good and bad.** Linux Change at "50%" can be auditd at 0% and linux_secure
  at 100%. The index number tells you nothing about which to fix. The sourcetype pass separates them.
- **Fields booked against the wrong model.** A firewall sourcetype gets Web fields scored against it, or a
   zero-trust access source gets HTTP fields, because the index carries several models at once. Per
  sourcetype, you can see the field does not belong to that source at all and mark it not-produced instead
  of a false gap.
- **Sources the index audit never itemised.** Fragmented sourcetypes, operational logs, and inventory
  collectors sit inside audited indexes but were never checked individually. The sourcetype pass forces
  every one to be accounted for.

---

## Part 2. The environment is defined by the real index-to-sourcetype map, not a document

The actual list of sourcetypes and which index each lives in is collected in Phase 1 (`discovery_kit.md`,
D3) and held in the Environment Profile. It comes from the environment, not from a utilisation
spreadsheet or an assumption. The query that settles it, if you need to rerun it for a narrower scope:

```
| tstats count where index=[all_in_scope_indexes] by index, sourcetype
| stats dc(index) as index_count, values(index) as indexes by sourcetype
```

Two things this settles:

- **Does any sourcetype span more than one index?** `where index_count > 1` lists them. If empty, every
  sourcetype has one index and the per-index query structure is safe. If not, those sourcetypes need care,
  because a per-index coverage query would only see part of their events.
- **The true sourcetype count.** A utilisation review often lists more sourcetypes than the index actually
  contains in the window (fragments that produced nothing, consolidated types). Audit against the real
  list from `tstats`, not the inflated document, or you will chase sourcetypes that are not there.

Never trust a utilisation or inventory spreadsheet for the index of a sourcetype. Those documents are
keyed on sourcetype and frequently carry no index column at all; the index-to-sourcetype relationship
comes only from the environment.

---

## Part 3. Vendor add-on CIM expectation: the field that decides whether a zero is a gap

**This is the most important discipline in the sourcetype pass.** A field reading zero on a sourcetype is
only a gap if that sourcetype is *supposed* to map to that model. Whether it is supposed to is not a
judgement call and not a guess from the device category: it is declared by the sourcetype's **vendor
add-on CIM table**. Every audited sourcetype gets an "expected CIM" value sourced from its add-on, and the
compliance verdict is read against that expectation.

Add a column to the sourcetype audit: **CIM Expected? (per vendor)** — Yes if the vendor add-on declares
one or more CIM data models for the sourcetype, No if the add-on lists it as n/a. Label the source of
each mapping so it is defensible:

- **vendor-doc** — confirmed in the add-on's published "Source types and CIM" table.
- **add-on-tags** — read from the add-on's `tags.conf` / eventtypes where no table is published.
- **known** — established add-on behaviour, not re-verified against the doc this pass.

Where to find the vendor CIM table, by add-on:

- Splunk Add-on for Microsoft Windows: its Source types and CIM page (github.io). Confirms, for example,
  that ActiveDirectory and the Perfmon/Script inventory types are n/a, and XmlWinEventLog carries
  Authentication/Change/Endpoint/Malware/Updates.
- Splunk Add-on for Unix and Linux: its Sourcetypes page. Confirms **raw auditd is n/a** — it maps to CIM
  only after ausearch translation into linux_audit. linux_audit is Authentication/Change; linux_secure is
  Authentication/Network_Sessions/Change. This single table corrects the most common Linux mis-audit.
- Zscaler add-on: read `tags.conf` — ZPA maps to Authentication/Network, web gateway to Web/Proxy/Network.
- Splunk Stream: the "Protocols that map to CIM" page — IP/TCP/UDP to Network_Traffic, HTTP to Web, DNS to
  Network_Resolution.
- Microsoft Cloud Services / O365 / legacy Azure add-ons: the sourcetype names in the environment
  determine which add-on governs. `azure:aad:*` names are the legacy Microsoft Azure add-on;
  `azure:monitor:*` are Microsoft Cloud Services. Identity feeds like `azure:aad:user` and
  `azure:aad:device` are asset/identity enrichment, not a security data model.
- Aruba wireless (ArubaOS) add-on: the operational sourcetypes are tagged with generic keywords
  (security, network, system, user, wireless), not CIM data models — treat them as n/a except ClearPass,
  which is a separate NAC add-on mapping to Authentication.

The rule this produces: **a non-CIM source (vendor says n/a) never carries a gap.** If a field extracts on
it anyway, that is not compliance and not a gap — it is incidental extraction, flagged separately (Part
6). ActiveDirectory is the canonical example: vendor n/a, so its empty CIM fields are correct, not
failures.

---

## Part 4. The fix-type diagnosis: macro vs tag vs parser (never guess this)

The base skill names four fix types. At the sourcetype level, a zero-coverage field must be diagnosed to
the right one with queries, because the fixes are different and ordered, and mislabeling them is the error
an expert will catch fastest. The order is always **macro, then tag, then parser** — each earlier fix
makes the later ones visible, and a parser fix on events that never reach the model does nothing.

Run the diagnosis in this sequence and stop at the first that explains the zero:

### 4.1 Macro — is the index even in the model's index list?

```
| rest /servicesNS/-/-/admin/macros count=0
| search title IN ("cim_Authentication_indexes","cim_Change_indexes","cim_Endpoint_indexes",
    "cim_Network_Traffic_indexes","cim_Web_indexes","cim_Intrusion_Detection_indexes",
    "cim_Network_Resolution_indexes","cim_Network_Sessions_indexes","cim_Alerts_indexes",
    "cim_Malware_indexes","cim_Updates_indexes")
| table title, definition
```

Read whether the sourcetype's index appears in the relevant model's definition (mind wildcards: a macro entry
like `*linux` also matches any index ending in `linux`, and a wildcard can catch indexes you did not mean
to include). If the index is **absent**, the model filters those events out before anything
else — a macro gate. Fix = macro, first priority, and it goes on the macro findings, not the field detail.
A macro pointing at `index=empty` is dead outright. **Do not label anything a macro gate without reading
this; and do not label a tag or parser problem as a macro problem when the index is present — the
definition is the evidence either way.**

### 4.2 Tag — do the events reach the model but lack the model's tag?

If the index is in the macro, the events reach the model's search but only join the model if they carry
its tag. Check what they are actually tagged:

```
index=[idx] sourcetype=[st] earliest=[window]
| eval t=if(isnull(tag),"NO TAG",mvjoin(tag,","))
| stats count by t
```

`NO TAG`, or tags that are not the model's tag (Linux auditd events tagged only `error`/`check`/`report`
instead of `authentication`/`change`), means the events never enter the model even though the macro is
fine. Fix = tag. This is the most common real cause of a sourcetype-level zero, and it is routinely
mislabeled as a parser gap.

### 4.3 Parser — events reach the model and are tagged, but the field is not extracted

Only if macro and tag are both fine is a zero a genuine extraction gap. Confirm the raw data exists under a
vendor name with `fieldsummary`:

```
index=[idx] sourcetype=[st] earliest=[window]
| fieldsummary | search count>0 | table field count | sort -count
```

Raw fields present (auditd `uid`/`exe`/`comm`/`acct`; Zscaler `ClientIP`/`requestmethod`; O365
`UserPrincipalName`) while the CIM field is empty confirms a parser gap, and names the exact raw field to
map. Raw field absent under any vendor name means the source genuinely does not produce it —
not-produced, not a gap.

### 4.4 The tie-breaker

If macro and tag both look fine but you are unsure, search the model directly rather than the raw index:

```
| datamodel [Model] [Model] search | search sourcetype=[st] | stats count
```

Zero here while the raw index has millions confirms a routing problem (macro or tag). A non-zero count
confirms the events reach the model, so any low field coverage is genuinely extraction.

### 4.5 What tagging actually is (so the fix is actionable)

A data model searches for a **tag**, not a sourcetype. Tags reach events through eventtypes: an eventtype
is a saved search that classifies events (`eventtypes.conf`), and a CIM tag is attached to that eventtype
(`tags.conf`). Matching events then carry the tag and flow into the model. Vendor add-ons normally ship
these eventtypes and tags, so a "NO TAG" source usually means the vendor add-on is not installed on the
search head, or the events are not in the format the add-on's eventtypes expect (the raw-auditd case), or
a local config disabled them. State the routing fix as "install or repair the vendor add-on so its
eventtypes and tags fire," not "hand-write tags," because that is the real root cause.

### 4.6 Plain-language labels for the deliverable

Users do not understand "tag" or "macro" as fix words. Keep the technical accuracy in the evidence, but
label the fix in the report as a routing-then-mapping sequence:

- macro gate → "Step 1: add the index to the model's index list, Step 2: map fields"
- tag gap → "Step 1: route events into the model (tagging), Step 2: map fields"
- parser only → "Extract and map the fields"

Never soften a tag problem into the word "macro" for readability — the macro definition proves which it
is. Solve the comprehension problem with plain language, not by mislabeling the cause.

---

## Part 5. Coverage measurement per sourcetype (query shape and window sizing)

One query per index, split by sourcetype, over the audited field set for that index's models:

```
index=[idx] earliest=[short_window]
| stats count as total, count([f1]) as [f1], count([f2]) as [f2], ... by sourcetype
| foreach [f1] [f2] ...
    [ eval <<FIELD>>=round('<<FIELD>>'/total*100,1) ]
| sort - total
```

Notes that keep the numbers honest:

- **Field set = the audited fields for that index, never a generic CIM dump.** Pull the field list from the
  index audit's detail, so excluded/not-produced fields are not re-queried and the tables stay readable.
- **Size the window to volume, not to a fixed span.** High-volume indexes need only minutes; low-volume
  ones need hours. Coverage of a field on a sourcetype is stable over time, so a short window measures it
  fine — unless the `total` comes back tiny, in which case widen just that index before trusting a zero.
- **Multivalue inflation:** `count(field)` counts every value instance, so a multivalue field can exceed
  100%. Display it capped at 100% with a multivalue flag, and confirm with `mvcount(field)` that it is
  genuinely multivalue and not a parsing artefact before calling it fully mapped.
- **Coverage on a gap row is zero by definition.** When a field is booked "not mapped yet," its CIM
  coverage is zero because the CIM field is empty; put the raw field's coverage in the note, not in the
  coverage column, so a reader never sees a high number next to a gap.

---

## Part 6. Findings the sourcetype view brings into focus (present in any audit)

These findings are not created by the sourcetype pass; they exist in the environment and the sourcetype
view simply makes them easy to see and pin to a specific source. In an index-level audit they are still
present and still must be addressed — they are just harder to isolate. Chase them down whichever way the
audit is run.

### 6.1 Incidental mapping on a non-CIM source (mapping that should not happen)

A source the vendor lists as n/a should carry no CIM fields. When it does — generic `syslog` tagged
`authentication`, an operational log populating `src`/`user` — that is Splunk spending normalisation effort
on data with no CIM purpose, polluting the model with unnormalised events. Flag every non-CIM source with
whether CIM fields are firing on it and which fields, confirmed by the tag query (Part 4.2). This is a real
finding: it means detections built on that model are seeing junk. ActiveDirectory clean (n/a, nothing
firing) is the target state; syslog tagged `authentication` is the defect.

### 6.2 Double-ingest of the same data under multiple sourcetypes (a licence finding)

The sourcetype pass often reveals the same events ingested under several sourcetype names. The clearest
case: raw `auditd` (vendor n/a) alongside the translated `linux_audit`/`linux:audit` (the CIM sources) —
the raw copy contributes nothing to CIM and roughly doubles the audit-log licence spend. Confirm with:

```
index=[idx] (sourcetype=[raw] OR sourcetype=[translated1] OR sourcetype=[translated2]) earliest=[window]
| stats count as events, dc(_raw) as distinct_raw by sourcetype
```

Similar counts across the names over the same window indicate the same data ingested more than once.
Report it as a licence finding with the recommendation to drop the redundant raw ingestion or route only
the translated sourcetype.

### 6.3 Fragmented sourcetypes (broken input typing)

A single logical source shattered across many junk sourcetypes (dozens of `vmware:vclog:*` fragments,
`*-too_small` types) points at a broken input or props typing. The sourcetype pass makes this visible as a
long tail of near-identical near-zero rows. It is a data-onboarding defect, not a CIM gap; note it and
recommend fixing the input's sourcetype assignment.

---

## Part 7. Account for every sourcetype, including the non-CIM ones

Every sourcetype consumes licence, so every one must appear somewhere in the deliverable, consistently:

- **CIM-expected sources** go in the field detail, audited field by field.
- **Non-CIM sources** (vendor n/a) go on a dedicated Non-CIM sheet, with the incidental-mapping flag from
  6.1. Do not leave them out silently and do not scatter some into the detail marked "not applicable" — one
  consistent home, the same treatment for all, so the reader sees the whole environment and the reviewer
  cannot ask "did you check these."
- **Genuinely unaudited CIM sources** — CIM-expected per vendor but not measured in the window — get a
  short scoped coverage query each and are folded in; until then they are listed as open, not omitted.

The test: someone reading the deliverable can find every sourcetype in the environment in exactly one
place, and for each one knows whether it is a CIM source, whether it maps, and if not, the ordered fix.

---

## The one line summary

Run the audit per sourcetype when the index numbers are too blended to act on: get the real
index-to-sourcetype map from tstats, set each sourcetype's expected CIM mapping from its vendor add-on so a
zero is only a gap where the vendor says the source should map, diagnose every gap to macro then tag then
parser with queries rather than guessing, surface the findings the sourcetype view brings into focus but
which exist in any audit (incidental mapping,
double-ingest, fragmentation), and account for every licensed sourcetype in one consistent place.
