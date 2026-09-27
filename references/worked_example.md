# Worked Example: One Environment, Audited End to End

This is one real multi site Splunk environment audited with the method in the skill. It is included to
show how each phase plays out and, more importantly, how ambiguous results get resolved without guessing.

**Read this as an illustration of the method, not as a set of rules.** Every environment has different
gaps. The macro exclusions, the trapped switch data, the missing audit source, and the vendor splits
below are this environment's findings. Yours will differ. The index names, the domains, the vendors, and
the site structure here are all specific to this one deployment and none of them should be carried into
another audit as an expectation. Another environment may have completely different index names, a
different set of domains, no sites at all, and an entirely different vendor mix. What carries over is only
the way each finding was reached: check the structural cause first, then confirm every field against real
events before believing the number.

---

## The environment

A multi site deployment whose index names combined a site and a domain, established from the index list
in the collection phase rather than taken from the client. Fewer than half the indexes held data; the rest
were empty and noted as operational. Six domains carried the security relevant data: windows, security,
linux, network, cloud, and a small cloud alert source. A separate index held an LDAP asset list.

The domain labels below are generic descriptions of what each group of indexes carried. The real index
names, site codes, and counts stay in that engagement's Environment Profile, not in this example.

---

## The systemic finding: macros first paid off

Reading the seven index macros before any field work showed the whole shape of the audit in five minutes.
Several indexes that held good data were simply not named in the macros they should feed:

- Authentication macro named windows, network, firewall only. Linux and cloud were shut out.
- Change macro named windows, firewall, network only. Linux and both cloud sources were shut out.
- Endpoint macro named endpoint, windows only. Linux and network were shut out.
- Web macro named firewall, security only. Cloud was shut out.

This one finding was the hidden root cause behind what first looked like separate add on and mapping
problems. The lesson: had the audit measured field coverage first, it would have chased linux and cloud
as field problems for days. Reading the macros first told us immediately those were gated, not broken.

---

## How each domain resolved, and the reasoning

### Windows: healthy, the raw number lied

Raw tool score was 3 to 11 percent, which looked alarming. But every model reached 100 percent once
Not Applicable fields were set aside. The low raw number was two things: fields like signature and status
that only apply to a subset of the many Windows event codes, and system account SIDs (the null SID and
local system) filling the user field on machine activity. Splitting the SID types showed 55 percent
built in or system accounts, which are real Windows behavior, not a gap. Nothing to fix.

**Reasoning that mattered:** the availability check and the subset split. Service fields read 100 percent
once measured on the service event codes rather than across all Windows events. Never measure a subset
field across the whole stream.

### Security: strong, one real value fix

The web feed carried method, url, and status at 100 percent once measured on the web sourcetype alone
rather than across all the vendor's streams. File hash was complete on the events that actually carried
files, and correctly absent elsewhere. The one real fix was a threat feed putting numbers in the severity
field where CIM expects words. Splitting severity by vendor showed one vendor already used words (clear),
one used numbers (the fix), and the firewall traffic events had empty severity because they are not
intrusion detection events at all (Not Applicable, not a fix).

**Reasoning that mattered:** do not blanket fix a field across a vendor. Split by sourcetype and by event
subset, and only the truly broken slice remains.

### Linux: blocked at the macro, then tagging, and the parser gaps were phantom

Linux looked like a parser problem at first. It was not. The macro excluded the linux index from every
model, so the data never arrived. On top of that, the authentication tag covered only about a fifth of
the auth events, so even after the macro opened, tagging work remained.

The important resolution was the field gaps. The workbook had inherited notes assuming an audit daemon
feed carrying process and file and change fields. A search of the whole index over full retention found
zero such events. That source did not exist. So the fields that depended on it were Not Applicable, not
parser gaps. The authentication fields that did exist extracted in line with what the raw logs actually
carried, which the availability check confirmed. So linux had one real fix, tagging, sitting behind the
macro gate, and no parser work at all.

**Reasoning that mattered:** confirming absence over full retention before marking Not Applicable, and
the availability check showing the fields were mapped as well as the raw allowed. Both prevented false
parser findings.

### Network: real extraction work, and a model correction

Two genuine fixes. First, the switch authentication decisions carried no action value. Splitting the auth
events by subtype showed the session lifecycle events were fully mapped but the actual authorization and
authentication decision events carried nothing, which is exactly backwards from what you want. A real
parser gap on the events that matter most.

Second, a large fleet of switches from one vendor sent real security data that landed in throwaway
sourcetypes because the input had no explicit sourcetype set. Over a million events of trapped switch
security data. Comparing against the correctly configured switch vendors in the same index proved the
cause was the input config.

A model correction also came out of it: the switch feed carried no signature data at all, so the
intrusion detection model was dropped for this domain. Network was Authentication and Endpoint, not
intrusion detection. The data decided the mapping, not the index name.

**Reasoning that mattered:** the subtype split reversing the naive reading of a partial percentage, and
letting the actual event content, not the index name, decide model membership.

### Cloud: present but not extracted, an add on gate

Around half a million events per model sat in the index as raw JSON with the right data inside, but no
CIM field was extracted. The raw versus mapped check was decisive: the identity keys were present in
close to 100 percent of events, and the mapped CIM fields were at 0 percent. That signature, all raw and
nothing mapped, is the add on gate. The vendor add on that ships the extractions was not installed. One
install resolves the whole source. A web app log source in the same index showed the same pattern, so
cloud had Authentication, Change, and Web all gated the same way.

**Reasoning that mattered:** the raw near 100, mapped near 0 pattern is unmistakable once you look for it.
Do not mistake it for a field problem.

### Cloud alert source: too small to score

A single alert source with about 20 events in total over a month. Any percentage on 20 events is
meaningless, so it was noted and set aside rather than scored. Not every source is worth a compliance
number.

**Reasoning that mattered:** knowing when a source is too small to measure, and saying so, rather than
reporting a noisy percentage.

---

## Where the non model feeds landed

Some sources did not belong in a data model. The asset inventory in the asset list index turned out to be a
daily snapshot of the asset list (flat, near identical event counts every day), which is reference data
for the Asset and Identity framework, not a data model source. Among the security sources, a load
balancer feed and a CDN feed belonged in Web, and a privileged access feed belonged in Change and
Authentication.

**Reasoning that mattered:** a flat daily event count is the signature of a snapshot, which is a lookup
feed, not events. Profiling the fields each source carried decided where it belonged.

---

## The fix order that came out of it

1. Open the index macros so linux and cloud reach their models and network reaches Endpoint. One change,
   the most data restored for the least effort, and the prerequisite for everything else.
2. Install the cloud add on so the sign in, audit, and web app data map into CIM.
3. Correct the threat feed severity values so severity based alerting sees the feeds.
4. Extract the switch authentication action value and give the trapped switch input a proper sourcetype.
5. Tag the linux authentication events and bring the privileged access feed into its models.

Field coverage was to be re measured after the macro fix, because numbers taken through a closed gate
change once the gate opens.

---

## The three habits this example proves

1. **Read the macros first.** It reframed the entire audit in five minutes and prevented days of chasing
   gated data as field problems.
2. **Confirm absence before marking Not Applicable.** It caught a whole set of phantom parser gaps built
   on a source that did not exist.
3. **Measure mapped against raw availability.** It separated every real gap from every source that simply
   does not carry the field, which is the difference between a defensible audit and a misleading one.
