# CIM Audit Query Kit

Reusable SPL shapes for every phase of a CIM compliance audit. Fill in the bracketed parts and run.
These are the same handful of shapes used again and again. Learn them once and the audit is fast.

Conventions used below:
- Every bracketed value is taken from the Environment Profile built in Phase 1
  (`discovery_kit.md`). Never fill a placeholder from memory, from another engagement, or from a client
  document.
- `[idx]` is your index scope: the wildcard or explicit index list the profile recorded for the domain
  you are auditing. If the profile says the names follow no pattern, list the indexes explicitly.
- `[st]` is a sourcetype from the profile's index-to-sourcetype map.
- `[Model]` is a CIM data model name as listed in the profile (for example `Authentication`).
- Whether a sourcetype is structured or delimited is also in the profile; it decides whether the raw text
  availability check below is allowed.
- Size the `earliest` window to volume: very high volume anchors get a short window like `-4h`,
  medium sources `-24h`, small sources all time.
- Always use raw search or `summariesonly=false`. Never audit on accelerated data. Accelerated summaries
  only contain events that already reached the model, which hides the unmapped events you are hunting.

---

## Phase 1. Data collection

The full collection set (platform and add-ons, indexes and retention, naming pattern, index-to-sourcetype
map, sprawl, structured versus delimited, macros, models, routing matrix, tags, licence) is in
`discovery_kit.md`. The two shapes below are the ones you will rerun most often during analysis.

Volume per index for one domain:

```
| tstats count where index=[idx] by index
```

Sourcetypes by volume in one index. The top rows are your real anchors.

```
| tstats count where index=[idx] by sourcetype
| sort - count
```

---

## Phase 2. Quantify sprawl in one index

Count the junk sourcetypes and the events trapped in them:

```
| tstats count where index=[idx] sourcetype=[junk_pattern]* by sourcetype
| stats sum(count) as trapped_events, dc(sourcetype) as junk_sourcetype_count
```

---

## Phase 3. Read the macros

The macro definitions were collected verbatim in Phase 1 (`discovery_kit.md`, D6). If you need to see how
a model uses its macro, inspect the model's root search constraint, which begins with the index macro:

```
(`cim_Authentication_indexes`) tag=authentication NOT (action=success user=*$)
```

For each of the CIM index macros, note which index categories it names, then compare against the indexes
that hold data from Phase 1. Any index that holds data but is not named in a relevant macro is a macro
gate finding. This is read and compare, not a query, and it is the highest leverage step in the audit.

---

## Phase 5. Field coverage with raw SPL (no validator app needed)

### 5.1 The model's field list, from the model itself

The list of fields a model defines is the denominator of the raw percentage. Take it from the installed
model so it matches the CIM version in the profile:

```
| datamodel [Model]
| spath output=obj_fields path=objects{}.fields{}.fieldName
| spath output=calc_fields path=objects{}.calculations{}.outputFields{}.fieldName
| eval field=mvdedup(mvappend(obj_fields, calc_fields))
| mvexpand field
| search NOT field IN ("_time","host","source","sourcetype")
| table field
```

This returns the union across the model's datasets. Some fields belong only to a child dataset (for
example registry fields on an Endpoint child); note which dataset each field sits in when applicability
depends on it. Cross check the list against the CIM field reference for the installed CIM version.

### 5.2 Per field coverage per sourcetype, through the model

`tstats` against the model with `summariesonly=false` reads raw events through the macro and the tag, and
counts each field as the model sees it:

```
| tstats summariesonly=false count as total,
    count([Model].[field_a]) as field_a,
    count([Model].[field_b]) as field_b,
    count([Model].[field_c]) as field_c
  from datamodel=[Model] where index=[idx] earliest=[window] by sourcetype
| foreach field_* [ eval <<FIELD>>=round('<<FIELD>>'/total*100,1) ]
| sort - total
```

Only events that reach the model are counted here, so a sourcetype missing from the result is a routing
problem (macro or tag, diagnose it), not a field problem. Some CIM fields are calculated with a default
such as `unknown` when the source is empty, which makes `count()` read full. Check the top values of any
field that looks suspiciously complete and treat the default as unpopulated:

```
| tstats summariesonly=false count from datamodel=[Model] where index=[idx] sourcetype=[st] earliest=[window]
  by [Model].[field]
| sort - count
```

---

## Phase 6. The raw versus mapped availability check (the key query)

This is the single most important shape. For a low field, it compares how often the field is mapped
against how often the value actually appears in the raw log. The gap between them is the finding.

Generic form for one field:

```
index=[idx] sourcetype=[st] earliest=[window]
| eval raw_has_field=if(match(_raw,"[raw_pattern_for_the_value]"),1,0)
| stats count as total, sum(raw_has_field) as raw_available, count([cim_field]) as mapped
| eval raw_pct=round(raw_available/total*100,1), mapped_pct=round(mapped/total*100,1)
```

Read the result:
- `mapped_pct` well below `raw_pct`: real Parser gap. Data present, not mapped.
- `mapped_pct` roughly equal to `raw_pct`: not a gap. The source only carries the value that often.
- `raw_pct` near zero: the source does not produce this field. Not Applicable.

Multiple core fields at once for a domain (adjust field and pattern per model):

```
index=[idx] sourcetype=[st] earliest=[window]
| stats count as total,
        count([field_a]) as a_mapped,
        count([field_b]) as b_mapped,
        count([field_c]) as c_mapped
| eval a_pct=round(a_mapped/total*100,1),
       b_pct=round(b_mapped/total*100,1),
       c_pct=round(c_mapped/total*100,1)
```

**Structured sources: use fieldsummary, not `match(_raw, ...)`.** The `match(_raw, ...)` availability
check above is reliable only on delimited text sources. On JSON or XML sources (Windows `XmlWinEventLog`,
M365 and Entra JSON, Defender JSON, Splunk Stream) the value lives in a parsed field, not the raw string,
so a raw text test returns a false zero on fields that are fully populated. Get the true field inventory
instead:

```
index=[idx] sourcetype=[st] earliest=[window]
| fieldsummary
| table field, count, distinct_count, mean
| sort - count
```

Cross reference each CIM field the model expects against this inventory. Name present with a high count
is Present. Name present with count zero is a real Applicable Missing. Name absent but a raw vendor field
present (for example `status.errorCode` behind CIM `status`) is a real parser gap, and the inventory
tells you the raw field to map. Name absent with no raw source at all is a true Not Applicable. Ignore
empty CIM placeholder fields (`*_asset`, `*_bunit` and similar): the name appears but no value is
present, so they are lookup scaffolding, not coverage. Full procedure in `investigation_kit.md`.

---

## Applicability by event subset

Many low numbers are really a field that only applies to a subset of events. Split by the subset before
judging. Example pattern: a field that should only appear on one event class.

```
index=[idx] sourcetype=[st] earliest=[window]
| eval subtype=case(match(_raw,"[pattern_1]"),"class_1",
                    match(_raw,"[pattern_2]"),"class_2",
                    true(),"other")
| stats count as events, count([cim_field]) as mapped by subtype
| eval cov=round(mapped/events*100,1)
| sort - events
```

If the field is 100 percent on the class that should carry it and 0 on the others, it is working and
Not Applicable elsewhere, not a gap. This is how a scary looking domain wide percentage resolves.

---

## Tag gate check

Confirms whether events are being claimed by a model. Low tag coverage means a Tag fix (or a Macro gate
upstream if the index is also excluded).

```
index=[idx] sourcetype=[st] earliest=[window]
| stats count as total, count(eval(searchmatch("tag=[model_tag]"))) as tagged
| eval tag_pct=round(tagged/total*100,1)
```

If tag coverage is zero and the index is also missing from the model macro, the macro is the root cause.
An index cannot be tagged into a model whose macro does not name it.

---

## Value format check (for Alias Value findings)

Confirms whether a field holds the CIM prescribed value or a raw vendor value. Classic case: numeric
severity where CIM wants words, split by vendor so you fix only the ones that need it.

```
index=[idx] ([st_list]) earliest=[window]
| eval sev_type=case(match(severity,"^\d+$"),"numeric",
                     severity IN ("critical","high","medium","low","informational"),"prescribed_word",
                     isnotnull(severity),"other",
                     true(),"empty")
| stats count by vendor_product, sev_type
```

Vendors showing `prescribed_word` are already compliant and clear. Vendors showing `numeric` need a value
map. Vendors showing `empty` on events that should not carry the field at all are Not Applicable, not a
fix. Do not blanket fix every vendor.

---

## Add on gate check (for cloud and identity JSON feeds)

Confirms the classic pattern where raw JSON is fully present but no CIM field is extracted because the
vendor add on is missing.

```
index=[idx] sourcetype=[st] earliest=[window]
| stats count as total,
        count(eval(match(_raw,"[raw_json_key_pattern]"))) as raw_present,
        count([cim_field]) as mapped
| eval raw_pct=round(raw_present/total*100,1), mapped_pct=round(mapped/total*100,1)
```

`raw_pct` near 100 with `mapped_pct` at 0 is the add on gate. The data is all there, nothing is
extracting it. One add on install resolves the whole source at once.

---

## Confirming a source is genuinely absent (before marking Not Applicable)

Never mark a field Not Applicable on the strength of one sourcetype returning zero. Search the whole
index over full retention for any evidence of the data first.

```
index=[idx] (match(_raw,"[broad_pattern_for_the_data]")) earliest=-30d
| stats count by sourcetype
| sort - count
```

Zero results across all sourcetypes over full retention is a confident absence. Results appearing under
some sourcetype means the data is present and the field is Applicable Missing after all, not
Not Applicable.

---

## Speed tiers

- **tstats** for counts, scope, and anything on indexed fields. Fast, use for Phase 1 and 2 and every
  denominator.
- **Raw bounded** with a time window sized to volume for common field coverage checks. Most of Phase 6.
- **Raw unbounded** over full retention only for rare sub one percent fields, or to confirm absence.

Keep the denominator exact with tstats wherever possible, and only sample the numerator ratio, and only
for common fields.
