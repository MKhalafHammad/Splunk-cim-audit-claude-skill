# CIM Audit Query Kit

Reusable SPL shapes for every phase of a CIM compliance audit. Fill in the bracketed parts and run.
These are the same handful of shapes used again and again. Learn them once and the audit is fast.

Conventions used below:
- `[idx]` is your index scope. Use whatever wildcard captures the indexes you are auditing in this
  environment. If the deployment is multi site with a repeated pattern, a wildcard can capture all sites
  for one domain at once. If index names are flat or unpatterned, list them explicitly instead. Discover
  the real names first, never assume a shape.
- `[st]` is a sourcetype.
- Size the `earliest` window to volume: very high volume anchors get a short window like `-4h`,
  medium sources `-24h`, small sources all time.
- Always use raw search or `summariesonly=false`. Never audit on accelerated data. Accelerated summaries
  only contain events that already reached the model, which hides the unmapped events you are hunting.

---

## Phase 1. Inventory: indexes and volume

Every index and its event count. Shows which hold data and which are empty.

```
| tstats count where index=* by index
| sort - count
```

Volume per index for one domain across all sites:

```
| tstats count where index=[idx] by index
```

---

## Phase 2. Sourcetype discovery

Sourcetypes by volume in one index. The top rows are your real anchors. A long tail of tiny
auto generated names is sourcetype sprawl.

```
| tstats count where index=[idx] by sourcetype
| sort - count
```

Quantify sprawl (count the junk and the events trapped in it):

```
| tstats count where index=[idx] sourcetype=[junk_pattern]* by sourcetype
| stats sum(count) as trapped_events, dc(sourcetype) as junk_sourcetype_count
```

---

## Phase 3. Read the macros

The macros are configuration, not data, so read them in Settings, Advanced search, Search macros, or
inspect a data model's root search constraint which begins with the index macro:

```
(`cim_Authentication_indexes`) tag=authentication NOT (action=success user=*$)
```

For each of the CIM index macros, note which index categories it names, then compare against the indexes
that hold data from Phase 1. Any index that holds data but is not named in a relevant macro is a macro
gate finding. This is read and compare, not a query, and it is the highest leverage step in the audit.

---

## Phase 5 and 6. The raw versus mapped availability check (the key query)

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
