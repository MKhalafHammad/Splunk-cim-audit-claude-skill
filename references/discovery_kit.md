# CIM Audit Discovery Kit (Phase 1: collect the environment profile)

Every later phase of the audit works on names it did not invent: indexes, sourcetypes, add-ons, macros,
models. This kit collects them from the environment before any finding is written, and records them in one
**Environment Profile**. Every query in the other kits takes its placeholders (`[idx]`, `[st]`,
`[all_in_scope_indexes]`, `[Model]`) from this profile, never from the skill text, a previous engagement,
or a spreadsheet the client sent.

Why it is a separate phase: the most expensive audit mistakes are made on wrong names. An index that
was assumed to exist, a sourcetype copied from another client, a macro read from memory instead of from
the search head, a CIM version guessed. Collecting first makes every later number traceable to something
that was actually looked at.

**The rule: no finding is written until the profile is complete.** If a collection step cannot be run
(no REST permission, no access to `_internal`), record it in the profile as *not collected* with the
reason, and use the UI fallback listed under that step. Never fill a gap in the profile with an assumption.

Run everything below on a search head that has the CIM add-on and the vendor add-ons installed, because
that is where macros, eventtypes, tags, and data models are evaluated.

---

## The Environment Profile (what gets recorded)

Keep the profile as the first sheet of the workbook (or a section of the findings document). One row per
item, with the collection date and the query that produced it. It holds:

| Section | What it records | Collected by |
|---|---|---|
| P1 Platform | Splunk version, CIM add-on version, ES present or not | D1 |
| P2 Add-ons | Every installed vendor add-on and its version | D1 |
| P3 Indexes | Every non-internal index: events in window, total events, retention, empty or populated | D2 |
| P4 Naming | The index naming pattern actually observed, and the wildcard(s) that capture each domain | D2 (derived) |
| P5 Sourcetypes | Index-to-sourcetype map with volume, host count, last seen | D3 |
| P6 Sprawl | Auto generated or fragmented sourcetypes, count and trapped events | D4 |
| P7 Format | Per sourcetype: structured (JSON/XML) or delimited text | D5 |
| P8 Macros | Every `cim_*_indexes` macro definition, verbatim | D6 |
| P9 Models | Every data model, its app, acceleration state | D7 |
| P10 Routing | Which models actually receive events, per index and sourcetype | D8 |
| P11 Tags | Tag coverage per sourcetype (including NO TAG) | D9 |
| P12 Licence | Daily ingest per index and sourcetype | D10 |
| P13 CIM expectation | Per sourcetype: governing add-on, the CIM models and datasets it should feed, the fields its add-on produces, and the evidence behind each | D11 |
| P14 Gaps in collection | Any step that could not be run, and why | manual |

Placeholders used below: `[st]` is a sourcetype from P5, `[idx]` its index. `[window]` is the discovery window (default `-30d` for counts, `-1h` or `-4h`
for anything that reads raw events). Widen only where a result comes back suspiciously small.

---

## D1. Platform, CIM version, and installed add-ons

```
| rest /services/apps/local splunk_server=local count=0
| table title, label, version, disabled
| sort title
```

From the result record: the `Splunk_SA_CIM` version (this is the field reference standard for the whole
audit), whether Enterprise Security is present, and every vendor technology add-on (usually `Splunk_TA_*`
or `TA-*`) with its version. The add-on list is what D11 later uses to decide which sourcetypes are
CIM-expected, so a missing add-on found here is often the root cause of a later zero.

Splunk version:

```
| rest /services/server/info splunk_server=local
| table serverName, version, server_roles
```

UI fallback: Apps, Manage Apps.

---

## D2. Indexes: populated, empty, retention

```
| rest /services/data/indexes count=0
| search NOT title=_*
| stats max(totalEventCount) as total_events, max(frozenTimePeriodInSecs) as frozen_secs by title
| rename title as index
| eval retention_days=round(frozen_secs/86400,0)
| join type=left index
    [| tstats count as events_in_window where index=* earliest=-30d by index]
| fillnull value=0 events_in_window
| eval state=if(events_in_window>0,"populated","empty in window")
| table index, state, events_in_window, total_events, retention_days
| sort - events_in_window
```

Record every index. Empty indexes are an operational note, not a CIM finding, but they must be listed so
a later reader knows they were seen.

**Derive the naming pattern (P4) from this list, do not ask for it or assume it.** Look at the real names
and write down the structure you observe (flat, `prefix_domain`, `site_domain`, `prefix_site_domain`, or
no pattern at all), the set of domains, whether there is a site dimension, and for each domain the
wildcard that captures it. Then test each wildcard so it catches exactly what you intend and nothing else:

```
| tstats count where index=[candidate_wildcard] by index
```

If the names follow no pattern, the profile says so and later queries list indexes explicitly.

UI fallback: Settings, Indexes.

---

## D3. The index-to-sourcetype map

```
| tstats count, dc(host) as hosts, latest(_time) as last_seen where index=* earliest=-30d by index, sourcetype
| eval last_seen=strftime(last_seen,"%F %T")
| sort index, - count
```

This is the ground truth for which sourcetypes exist and where. Never take it from a utilisation or
inventory document. Then check whether any sourcetype spans more than one index, because those need care
in every per-index query later:

```
| tstats count where index=* earliest=-30d by index, sourcetype
| stats dc(index) as index_count, values(index) as indexes, sum(count) as events by sourcetype
| where index_count > 1
```

The high volume sourcetypes per index are the anchors for that domain. Sourcetypes with a `last_seen` far
in the past are stale inputs, note them.

---

## D4. Sourcetype sprawl

Auto generated names (per file, per date, `-too_small`) and long tails of fragments point at an input with
no explicit sourcetype. Data trapped this way gets no extraction, no tags, and no model membership.

```
| tstats count where index=* earliest=-30d by index, sourcetype
| where match(sourcetype,"-too_small$") OR match(sourcetype,"^\d{4}-\d{2}-\d{2}") OR match(sourcetype,"\d{6,}")
| stats dc(sourcetype) as junk_sourcetypes, sum(count) as trapped_events, values(sourcetype) as examples by index
| eval examples=mvindex(examples,0,4)
```

Also look in the D3 output for one logical source split across many near-identical names (a vendor prefix
followed by dozens of suffixes). Adjust the patterns to what you see; the ones above are only the common
shapes.

---

## D5. Structured or delimited, per sourcetype

This decides, for every sourcetype, whether the raw text availability check (`match(_raw,...)`) is
allowed or whether `fieldsummary` must be used (see `investigation_kit.md`). Judge it from the events,
not from the name:

```
index=* earliest=-1h
| eval fmt=case(match(_raw,"^\s*\{"),"json", match(_raw,"^\s*<"),"xml", true(),"text")
| stats count by index, sourcetype, fmt
| eventstats sum(count) as st_total by index, sourcetype
| eval pct=round(count/st_total*100,1)
| sort index, sourcetype, - count
```

Cross check against the search time parsing configuration:

```
| rest /servicesNS/-/-/configs/conf-props count=0
| search KV_MODE IN ("json","xml") OR INDEXED_EXTRACTIONS=*
| table title, eai:acl.app, KV_MODE, INDEXED_EXTRACTIONS
```

A sourcetype that is mostly `json` or `xml` is **structured** in the profile. A text sourcetype with a
JSON or XML payload after a syslog header is also structured for the purpose of the availability check.
For low volume sourcetypes that produced nothing in one hour, rerun scoped to that sourcetype with a wider
window.

---

## D6. CIM index macros, verbatim

```
| rest /servicesNS/-/-/admin/macros count=0
| search title=cim_*_indexes
| table title, definition, eai:acl.app
| sort title
```

Copy each definition into the profile exactly as returned. If a macro appears more than once (the CIM
default and a local override in another app), record both and note which one wins. A definition of `()`,
an empty value, or one that points at a non existent index means the model sees nothing.

These are only collected here. They are compared against the populated indexes in Phase 3.

UI fallback: Settings, Advanced search, Search macros, filter on `cim_`. Or Apps, CIM Setup, where the
index constraints per model are shown.

---

## D7. Data models and acceleration

```
| rest /servicesNS/-/-/datamodel/model count=0 splunk_server=local
| spath input=acceleration path=enabled output=accelerated
| table title, eai:acl.app, accelerated
| sort title
```

Record which models exist (the CIM models plus any custom or ES models) and which are accelerated.
Acceleration does not change the audit (the audit always reads raw), but it tells you which models
detections read from summaries, so it frames the impact of a finding.

UI fallback: Settings, Data models.

---

## D8. Routing reality: which models actually receive what

For each CIM model in scope, count what reaches it, by index and sourcetype. This reads through the macro
and the tag, so it shows the combined effect of both before any field work:

```
| tstats summariesonly=false count from datamodel=[Model] where earliest=-4h by index, sourcetype
| eval model="[Model]"
```

Run it once per model (or chain them with `append`). `summariesonly=false` makes it read raw events for
any part not accelerated, so keep the window short on high volume environments. Put the results in one
matrix: rows are index and sourcetype from D3, columns are models, cells are event counts. Blank cells are
the first candidates for macro or tag findings, to be diagnosed in later phases, not declared here.

---

## D9. Tag coverage per sourcetype

```
index=[all_in_scope_indexes] earliest=-1h
| eval t=if(isnull(tag),"NO TAG",mvjoin(mvsort(tag),","))
| stats count by index, sourcetype, t
| sort index, sourcetype, - count
```

Record per sourcetype the tag sets its events carry, and the share with no tag. A sourcetype with only
NO TAG is not claimed by any model. The eventtype and tag definitions behind them, for later diagnosis:

```
| rest /servicesNS/-/-/saved/eventtypes count=0
| table title, search, eai:acl.app, disabled
```

---

## D10. Licence usage per index and sourcetype

Needed for the sourcetype pass, double ingest findings, and for weighing a finding by how much data it
affects.

```
index=_internal source=*license_usage.log* type=Usage earliest=-30d
| stats sum(b) as bytes by idx, st
| eval GB_30d=round(bytes/1024/1024/1024,2), GB_per_day=round(GB_30d/30,2)
| rename idx as index, st as sourcetype
| sort - GB_30d
```

On busy environments the licence log squashes sourcetype detail and `st` can come back empty for part of
the volume. Record that in the profile rather than dropping those rows. If `_internal` is not readable,
mark P12 as not collected.

---

## D11. CIM expectation per sourcetype (what the vendor add-on says should map)

A zero is only a gap if the sourcetype is supposed to feed that model. This step decides that for every
sourcetype in P5, for any vendor, without a vendor list in the skill. It works because every CIM
compliant add-on declares model membership the same way: `eventtypes.conf` classifies the sourcetype's
events, `tags.conf` puts CIM tags on those eventtypes, and each data model selects events by tag. The
fields come from the same add-on's `props.conf` and `transforms.conf`. All of it is readable over REST
on the search head, and it matches the installed version exactly. The published documentation is then
used as the cross check, not as the only source.

Work through the steps below. Parsing configuration over REST is best effort: eventtype searches that use
macros, reference other eventtypes, or select by `source::` rather than sourcetype will not parse. Read
those by hand, or settle them with the observed check in D11.5.

### D11.1 Which add-on governs each sourcetype

The app that defines the sourcetype's `props.conf` stanza is normally its add-on:

```
| rest /servicesNS/-/-/configs/conf-props count=0 splunk_server=local
| search NOT title="source::*" NOT title="host::*" NOT title="default"
| rename title as sourcetype, eai:acl.app as app
| stats values(app) as defining_apps by sourcetype
```

Join this to P5 by sourcetype and to P2 for the add-on's label and version. A sourcetype defined only in
`search`, `system`, or a local app, or not defined at all, has no add-on behind it. Some add-ons attach
their parsing to `source::` stanzas instead (per channel or per file); if a sourcetype comes back with no
defining app, check the `source::` stanzas against the sources that sourcetype actually carries
(`| tstats count where index=[idx] sourcetype=[st] by source`).

### D11.2 What the add-on declares: eventtypes and their tags

Eventtypes and the sourcetypes their searches name:

```
| rest /servicesNS/-/-/saved/eventtypes count=0 splunk_server=local
| search disabled=0
| rename title as eventtype, eai:acl.app as et_app, eai:acl.sharing as sharing
| rex field=search max_match=20 "sourcetype\s*=\s*\"?(?<st_ref>[^\s\"\)]+)"
| join type=left eventtype
    [| rest /servicesNS/-/-/configs/conf-tags count=0 splunk_server=local
     | search title="eventtype=*"
     | fields - eai:* author id published updated splunk_server
     | untable title tag state
     | search state=enabled
     | eval eventtype=replace(title,"^eventtype=","")
     | stats values(tag) as tags by eventtype]
| table eventtype, et_app, sharing, st_ref, tags, search
```

Map each `st_ref` (which may hold a wildcard) onto the real sourcetypes in P5. Rows with no `st_ref`
select by macro, source, or another eventtype; read their `search` column. Tags can also be attached to
stanzas other than eventtypes (`sourcetype=...` or a field value); list those separately with
`search NOT title="eventtype=*"` in the subsearch.

Record `sharing` as well. An eventtype or tag shared only at app level is invisible to searches run from
other apps, so the model never sees it even though the add-on is installed. That is a routing finding in
its own right.

### D11.3 Which tags each model and dataset requires

Take the tag requirements from the installed models, not from memory, so they match the CIM version in P1:

```
| datamodel
| spath output=model path=modelName
| spath output=obj path=objects{}
| mvexpand obj
| spath input=obj output=dataset path=objectName
| spath input=obj output=parent path=parentName
| spath input=obj output=constraint path=constraints{}.search
| rex field=constraint max_match=10 "tag\s*=\s*\"?(?<req_tag>[\w\-]+)"
| eval req_tags=mvjoin(mvsort(req_tag),",")
| table model, dataset, parent, req_tags, constraint
```

A dataset requires every tag in its own constraint plus every tag its parents require (a child inherits
its parent's constraint). A tag inside a `NOT (...)` clause is an exclusion, not a requirement; read the
`constraint` column when it has one. A sourcetype is expected in a dataset when the tags its add-on
declares (D11.2) cover all the tags the dataset requires.

### D11.4 Which fields the add-on produces for the sourcetype

This gives the field level expectation, the evidence for the Not Applicable bucket. Aliases and
calculated fields, with the field each one outputs:

```
| rest /servicesNS/-/-/configs/conf-props count=0 splunk_server=local
| search title="[st]"
| eval stanza=title."|".'eai:acl.app'
| fields stanza EVAL-* FIELDALIAS-* LOOKUP-* REPORT-*
| untable stanza key value
| rex field=value max_match=100 "(?i)\bAS(?:NEW)?\s+\"?(?<alias_out>[\w\.:\-]+)"
| eval produced=case(like(key,"EVAL-%"), replace(key,"^EVAL-",""),
                     like(key,"FIELDALIAS-%"), alias_out)
| table stanza, key, produced, value
```

`LOOKUP-*` rows name their outputs after `OUTPUT` or `OUTPUTNEW` in `value`. `REPORT-*` rows name
transforms; resolve them in `| rest /servicesNS/-/-/configs/conf-transforms count=0` (the `FORMAT` value
or the named groups in `REGEX`). Intersect the produced fields with the model's field list
(`query_kit.md`, 5.1).

A CIM field the add-on produces is expected for that sourcetype, so a zero on it is a candidate gap. A
CIM field the add-on does not produce is a candidate for Not Applicable, not a verdict. Automatic key
value, JSON, and indexed extractions create fields that no `props.conf` key names, so confirm with the
availability check (`fieldsummary` on structured sources) before excluding it.

### D11.5 Observed check: which eventtypes actually fire

Static configuration says what should happen. This says what does, and it settles any eventtype D11.2
could not parse:

```
index=[idx] sourcetype=[st] earliest=-1h
| eval eventtype=coalesce(eventtype,"NO EVENTTYPE")
| stats count by eventtype
```

Declared eventtypes that do not fire mean the events are not in the form the add-on expects (a raw
format the add-on only supports after a translation step, a changed log format, a wrong sourcetype name
on the input), or the eventtype is disabled or not shared. Record it; Phase 6 diagnoses it.

### D11.6 Cross check against the published documentation

Every add-on documents which sourcetypes it maps to which CIM models, usually as a "Source types" or
"Source types and CIM" page. Find it by pattern, not from a list:

- Take the add-on's label and version from P2.
- Splunk built add-ons (`Splunk_TA_*`) publish it in the add-on's documentation, on docs.splunk.com
  ("Source types for the Splunk Add-on for ...") or, for newer add-ons, on a splunk.github.io page per
  add-on.
- Vendor or community add-ons link their documentation from the Splunkbase listing, or publish it on the
  vendor's own documentation site. Search for the add-on label with "source types CIM".
- If you can fetch web pages, read the table directly. If not, ask the user for the page or a paste of
  the table, for all the add-ons at once in one request.

Record the page URL, the add-on version it documents, and the date read. Documentation often gives the
mapping per sourcetype and source (for example per event log channel), so record the expectation at the
granularity the page gives.

If the add-on is not installed on the search head, download its package from Splunkbase (or ask the user
for it) and read `default/eventtypes.conf`, `default/tags.conf`, and `default/props.conf` directly. The
same analysis applies offline.

### D11.7 Setting the expectation

Each sourcetype gets one of three values in P13: **Yes** (with the models and datasets), **No** (the add-on
lists it as not CIM), or **Unknown** (no add-on covers it). Resolve disagreements like this:

| Installed add-on config | Published doc | Expectation | Record |
|---|---|---|---|
| Declares the model | Declares the model | Yes | Strongest evidence |
| Declares the model | Silent or n/a | Yes | Doc lags the installed version; note both versions |
| Only a local or unrelated app declares it | n/a | No | Incidental mapping, unless the client confirms a deliberate custom mapping |
| Does not declare it, or not installed | Declares the model | Yes | Add-on missing, outdated, disabled, or not shared: an add-on fix |
| Does not declare it | n/a or silent | No | Non-CIM source |
| No add-on and no documentation | | Unknown | Judge from sample events, and record that the source has no add-on |

Label every row's evidence so it can be defended: `installed-conf` (D11.1 to D11.5), `vendor-doc`
(D11.6), `splunkbase-package` (package read offline), `content-judgement` (no add-on; decided from the
events). Where the installed config and the doc agree, record both labels.

Known pitfalls that are easy to get wrong are listed in `sourcetype_mapping_kit.md`, Part 3. They are
examples to check against, not a substitute for this step.

---

## Closing the phase

The profile is complete when every section is either filled or explicitly marked *not collected* with a
reason. At that point, and not before:

- The scope is set from real names: which indexes, which sourcetypes, which models.
- Every placeholder in the other kits has a real value to take.
- Every sourcetype has a CIM expectation (Yes, No, or Unknown) with its evidence, so a later zero can be
  judged against what the add-on says should map.
- The intake questions that the environment answers (CIM version, naming pattern, which models are
  populated) are answered from evidence, and only the questions the environment cannot answer (scope,
  deliverable format, whether remediation is in scope) remain for the client.

Keep the profile with the engagement's deliverables. Never copy a client's index names, sourcetypes,
hosts, or users back into this skill; the skill holds the method, the profile holds the environment.
