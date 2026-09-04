# CIM Audit Investigation Kit

The coverage phase produces suspect numbers. This kit is how you confirm what each one really is before
it goes in the workbook. A compliance percentage is a claim, and an unconfirmed claim is a guess. Every
gap that reaches a deliverable should have survived the checks below.

There are two kinds of investigation, and they are different work:

- **Finding verification.** A field reads as a gap but may not be one, or reads as fine but hides a gap.
  This is the audit's own false positives and false negatives. Do this before booking any finding. It is
  the main content of this file and the rest of the skill.
- **Detection tuning.** A correlation search fires on events that are not the thing it is meant to catch.
  This is downstream of the audit and often caused by the same normalization gaps the audit found. The
  last section covers it.

---

## Part 1. The two errors an audit makes

Treat the audit like any classifier. It can be wrong in two directions, and they need different checks.

- **False positive finding.** The workbook says *real gap* but the truth is *Not Applicable* or *already
  fine*. You raise a work item that can never be closed, or you send an engineer to fix a field the
  source was never meant to carry. This wastes remediation effort and erodes trust in the whole audit.
- **False negative finding.** The workbook says *fine* or *Not Applicable* but the truth is *real gap*.
  A genuine blind spot ships as green. This is worse, because nobody goes looking for it again.

The two habits already in the skill each defend one direction. Confirming absence over full retention
before marking Not Applicable defends against the false positive NA. Measuring mapped against raw
availability defends against calling a source broken when it only carries the value sometimes. This kit
adds the checks the base skill was missing, above all the structured source false negative.

---

## Part 2. The structured source false negative (the big one)

**This is the single most important addition to the method.** The availability check in the query kit
tests whether a value is in the log with `match(_raw, "pattern")`. That works on **delimited text**
sources, where the value sits in the raw string: syslog, CSV, key value firewall logs, IIS, Zscaler NSS.
It **silently lies on structured sources**, where the event is JSON or XML and the value lives in a
parsed field, not as a matchable substring of a flat line. On those sources a raw text test returns zero
even when the field is fully populated. You then mark a real, present field as absent. That is a false
negative, and it is invisible unless you know to look for it.

Structured sources in a typical environment: Windows `XmlWinEventLog`, Microsoft 365 and Entra JSON
(`o365:management:activity`, `azure:aad:signin`), Defender JSON, Splunk Stream, any HTTP Event Collector
or add on that writes JSON, most cloud audit feeds.

**The rule: on structured sources, never judge availability with `match(_raw, ...)`. Use `fieldsummary`
or a direct `count(field)`.** `fieldsummary` reads the parsed field inventory, which is what the source
actually presents to CIM, so it cannot be fooled by JSON structure.

### 2.1 Get the true field inventory of a structured source

```
index=[idx] sourcetype=[st] earliest=[window]
| fieldsummary
| table field, count, distinct_count, mean
| sort - count
```

Every field the source presents, with how many events carry it. This is the ground truth for what the
source can feed CIM. Export it and keep it as evidence.

### 2.2 Cross reference the inventory against the model's CIM fields

For each CIM field the model expects, check whether a field of that name (or an obvious raw source of it)
appears in the inventory. Three outcomes:

- **Name present, count high.** The source carries it. If the workbook marked it a gap or NA, that was a
  false negative. Reverse it to Present.
- **Name present, count zero or near zero.** The field exists in schema but is not populated. This is a
  real Applicable Missing, and now you have evidence it is real, not a raw text artifact.
- **Name absent, but a raw source field is present.** The CIM field is not mapped, but the data is there
  under a vendor name (for example `status.errorCode` behind CIM `status`, `UserPrincipalName` behind
  `src_user`, `ParentProcessName` behind `parent_process`). Real parser gap, confirmed. Note the raw
  field name so remediation knows exactly what to map.
- **Name absent, no raw source anywhere in the inventory.** The source genuinely does not emit it. True
  Not Applicable, now backed by the inventory rather than an assumption.

### 2.3 The value coverage rule (a name is not a value)

`fieldsummary` listing a field means the name exists. It does **not** mean the field carries a value on
your events. A field counts as Present only if the source **populates it with a value**, not merely if
the name appears. Two traps:

- **Empty CIM placeholders.** The CIM lookups seed empty fields like `*_asset`, `*_bunit`, `*_priority`,
  `*_category` on every event. They will appear in `fieldsummary` with the name present and the value
  empty. Never count these as coverage. They are lookup scaffolding, not source data.
- **Multivalue inflation.** `count(field)` counts every value instance, so a multivalue field can report
  more than one per event and a naive coverage ratio can exceed 100 percent. When a coverage number comes
  out above 100, the field is multivalue and effectively present on all events. Read it as full coverage,
  and if you need the true event count use `count(eval(isnotnull(field)))` or `dc` on an id.

Confirm value coverage with a scoped count on the event subset that should carry the field:

```
index=[idx] sourcetype=[st] [subset filter] earliest=[window]
| stats count as total, count([cim_field]) as populated
| eval pct=round(populated/total*100,1)
```

### 2.4 Scope the count to the events that should carry the field

A whole stream percentage buries the truth when a field only belongs to a subset. Windows is the clearest
case: `object_path` reads zero on account management event codes because those events have no path, yet
the same field is fully carried on file, registry, and share change codes. Measuring across all of
Windows hides both facts. Always scope the value count to the event codes or subset that should carry the
field, exactly as the subset split in the query kit does, then judge coverage on that subset alone.

The corollary matters for classification: a field can be **Not Applicable on one event subset and a real
gap at the model level**. If any subset of the source should carry the field and does not map it, it is
an Applicable Missing gap for the model, even though it is legitimately absent on the subset your first
query happened to hit. Do not mark the model level field Not Applicable on the strength of one subset
that never carries it. Widen to the subset that should, and classify from there.

---

## Part 3. The verification checklist for a single finding

Run this before any suspect field is booked. First matching answer decides it.

1. **Is the source structured (JSON or XML)?** If yes, and the suspect number came from a `match(_raw,...)`
   check, discard that number. Re run with `fieldsummary` (Part 2). A raw text zero on a structured
   source is worthless.
2. **Does the field only apply to a subset of events?** Split by subset (query kit). Judge coverage on the
   subset that should carry it, not the whole stream.
3. **Is the field a value or just a name?** Confirm it carries a value, not an empty CIM placeholder, and
   is not multivalue inflating the ratio (Part 2.3).
4. **Mapped far below raw availability?** Real parser gap. Data present, unmapped. Note the raw field name.
5. **Mapped roughly equal to raw availability?** Not a gap. The source only carries it that often. The
   remainder is Not Applicable.
6. **Raw availability near zero across the whole index over full retention?** True Not Applicable. Confirm
   with the absence query in the query kit before dropping the field.

If a finding survives to step 4 or 5 with evidence, it is real and defensible. If it resolves at step 1,
2, 3, or 6, it was an audit false positive and the base number would have misled the deliverable.

---

## Part 4. Batch reversal pass (re auditing an existing workbook)

When correcting a workbook that was built before this method, or auditing several reports at once, do the
false negative sweep as one deliberate pass rather than field by field.

1. **List the structured sources** in the environment (Part 2 opening). Only these can carry the raw text
   false negative. Delimited sources were measured correctly and do not need re checking for this error.
2. **Pull `fieldsummary` once per structured source.** One export each. This is the whole evidence base
   for the sweep.
3. **For every current NA and every current zero on those sources**, cross reference against the inventory
   (Part 2.2). Most will confirm; some will reverse.
4. **Reverse only with value coverage confirmed** (Part 2.3), never on the name alone. A reversal changes
   a score, so it must be as well evidenced as the original finding.
5. **Recompute the three numbers** for every model a reversal touched. A field moving out of Not
   Applicable into Applicable Missing changes the applicable denominator, so both the corrected mapped and
   fully compliant numbers move. Recompute from the detail rows, never by editing a percentage by hand.
6. **Know when the sweep is done.** When new `fieldsummary` pulls keep confirming existing findings and
   stop producing reversals, the sweep has reached diminishing returns. Confirmations that match the
   workbook are the signal to stop, not a reason to keep pulling more.

Delimited sources are out of scope for this specific sweep. Their zeros came from a reliable raw text
check and re pulling `fieldsummary` on them only re confirms what you already know.

---

## Part 5. Scope gaps versus field gaps (a different blind spot)

Finding verification catches false calls on fields that **were** audited. It cannot catch a model that
was **never** audited at all. That is a scope gap, and it needs a scope query, not a coverage check.

Before calling an audit complete, confirm every CIM model that could be fed is accounted for. Common
models that quietly go unaudited: Updates, Vulnerabilities, Email, Compute Inventory, Certificates,
Data Access. For each, one scope query answers whether any index carries the data:

```
| tstats count where index=[all_in_scope] by index sourcetype
| search [broad pattern or sourcetype for the model's data]
```

Or, for a model whose macro you already know is dead (points at a non existent index), the field coverage
is still unmeasured until the macro is opened. Note it as an open item: the macro fix is known, but
whether the data then maps or needs extraction is not, and that only resolves once events flow.

A scope gap is not a false positive or a false negative in a booked finding. It is an unasked question.
List these as open items in the deliverable so the reader knows the boundary of what was checked, rather
than letting silence imply coverage.

---

## Part 6. Detection tuning (downstream, after the audit)

This section is about a different false positive: a correlation search or alert firing on events that are
not what it is meant to catch. It sits downstream of the CIM audit because a detection reads from a data
model, and a detection is only as clean as the normalization under it. Many detection false positives are
a CIM problem wearing a detection costume.

### 6.1 The common root causes, in audit terms

- **A model polluted by events that should not be in it.** If a model's tag claims event classes it
  should not, every detection on that model inherits the noise. The Windows Authentication model pulling
  in WFP and PowerShell event codes is the pattern: the detection for failed logons now also sees
  firewall platform events. The fix is a tag scope, the same Tag fix type the audit already uses. Confirm
  by splitting the model's events by the code or subtype driving the false hits.
- **A value in raw vendor form the detection did not expect.** A detection keyed on `action="blocked"`
  misses or misfires when the source emits `action="deny"` or a numeric code. This is the Alias Value fix
  type. The detection looks broken; the normalization is the cause.
- **A field the detection trusts that is only partly populated.** If a detection assumes `user` is always
  present but the source carries it on half the events, the logic silently applies to the wrong half. The
  audit's coverage number for that field is exactly the diagnostic.

### 6.2 The tuning loop

1. **Pull a sample of the false hits.** The events the detection fired on that should not have counted.
2. **Ask which of the three causes it is.** Split the false hits by event code or subtype (pollution), by
   the raw value of the keyed field (alias value), or check the coverage of the field the logic trusts
   (partial population). The same three splits the audit already uses.
3. **Locate the fix in CIM terms.** Tag scope, value normalization, or extraction. A detection false
   positive almost always resolves to a fix type the audit vocabulary already names.
4. **Fix once, upstream.** Correct the tag, alias, or extraction in the normalization layer, not in the
   detection's SPL. A fix in the model clears every detection built on it. A fix in one detection's
   search leaves the next one exposed.
5. **Re measure.** After the upstream fix, the model's events and the field coverage change, so confirm
   the false hits are gone at the model level rather than only in the one search.

### 6.3 Keep audit and tuning separate in the deliverable

Detection tuning is remediation, and the skill keeps findings separate from remediation. Record a
detection false positive as evidence of a normalization gap in the findings, and put the tuning action in
the remediation plan. Do not let a tuning request pull raw detection SPL into an audit workbook whose job
is to state what is true about the data.

---

## The one line summary

Verify every suspect finding before booking it: on structured sources use `fieldsummary`, never
`match(_raw,...)`; scope the count to the events that should carry the field; confirm a value, not just a
name; and separate a model that was audited and passed from a model that was never audited at all.
