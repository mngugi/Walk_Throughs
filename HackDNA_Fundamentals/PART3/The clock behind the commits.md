Analysis
Step 1 — Measurement pair
Post: 2026-08-12 15:44 UTC

Photo: 2026-08-12 18:42:07 local (no offset)

Raw gap: 18:42 − 15:44 = +2h58m

Naive read → offset ≈ UTC−3
But commit window would then be 03:00–12:00 local — implausible.

Step 2 — Commit window is the real tell
06:00–15:00 UTC = 9-hour workday

09:00–10:00 UTC gap = lunch

No weekends

Map to a normal 09:00–18:00 local day:

Event	UTC	Local (UTC+3)
Start	06:00	09:00
Lunch	09:00–10:00	12:00–13:00
End	15:00	18:00
→ Offset = UTC+3

Step 3 — Reconcile with photo
Photo local: 18:42

If UTC+3 → 15:42 UTC

Post: 15:44 UTC

Photo taken 18:42 local, posted 15:44 UTC = 18:44 local. Two minutes apart. "End of the day, desk finally tidy" fits perfectly.

Step 4 — Why not Vancouver?
Vancouver in August = UTC−7 (PDT)

Commit window in UTC−7 = 23:00–08:00 local — not a normal working day

hbraithwaite: "A whole day is off, not a couple of hours."

UTC−7 → UTC+3 = 10-hour shift, i.e. roughly a whole day

Answer
text
UTC+3
Real UTC offset: UTC+3

text
all of it
markdown
# The Clock Behind the Commits

**OSINT**
**Difficulty:** Medium
**~5 min**
**+10 XP**

---

## Mission briefing

> Hide briefing

`feedparse-lite` sits under three thousand packages and the original author, who had not touched it in two years, handed a stranger the keys after a run of good patches. Version 2.1.0 shipped with a postinstall script that is not in the git tag. Before anyone argues about intent, the thread wants a simpler thing established: the account claims Vancouver, and a person's working hours are very hard to fake because they are not a field anybody fills in. Six public records are on the board. Give the UTC offset this maintainer actually lives in.

**Investigate**

---

## Board Evidence

### 💻 npm: feedparse-lite - maintainers

**Repo**

- `feedparse-lite 2.1.0` published **2026-08-12**
- weekly downloads **1,940,221**
- dependents **3,118**

**maintainers**

- `r.saldana` added 2019-03-04, last publish 2026-06-30 (2.0.4)
- `tomasz-bd` added 2026-07-02, last publish 2026-08-12 (2.1.0)

`r.saldana` wrote in issue #488 on 2026-06-28:

> 'I have not had time for this package in two years. tomasz-bd has been sending good patches, I am adding them as a maintainer so releases can continue.'

---

### 💻 git log, feedparse-lite, last 60 days (all times UTC)

**Repo**

```text
2026-08-12 14:52  tomasz-bd  release 2.1.0
2026-08-12 13:41  tomasz-bd  bump deps
2026-08-12 06:38  tomasz-bd  fix: handle empty enclosure tags
2026-08-11 14:07  tomasz-bd  test: add fixtures for atom 1.0
2026-08-11 10:22  tomasz-bd  refactor: split the tokenizer
2026-08-11 06:51  tomasz-bd  chore: lint
2026-08-10 13:58  tomasz-bd  perf: avoid a copy in the parser
2026-08-10 08:44  tomasz-bd  docs: readme typo
2026-08-07 14:36  tomasz-bd  fix: crash on malformed CDATA
2026-08-07 07:12  tomasz-bd  ci: cache node_modules
2026-08-06 13:20  tomasz-bd  feat: optional strict mode
2026-08-06 06:19  tomasz-bd  chore: bump eslint
2026-08-05 14:44  tomasz-bd  fix: off-by-one in the date parser
2026-08-05 08:03  tomasz-bd  test: cover strict mode
88 commits in 60 days.

None between 09:00 and 10:00 UTC.

None before 06:00 or after 15:00 UTC.

None on a Saturday or Sunday.

👤 social profile: @tomasz_bd
Social

Tomasz B. - open source, feeds, parsers

Vancouver, BC - joined June 2026 - 41 followers

Time (UTC)	Content
2026-08-12 15:44	end of the day, 2.1.0 is out. desk finally tidy [photo]
2026-08-08 06:12	good morning. coffee, then the tokenizer refactor.
2026-07-30 14:58	signing off, see you tomorrow
📷 photo attached to the 12 August post - metadata
Image metadata

File: desk_2026.jpg 2.1 MB

Make: Xiaomi

Model: 23127PN0CG

DateTimeOriginal: 2026:08:12 18:42:07

OffsetTimeOriginal: (absent)

GPSLatitude: (removed)

GPSLongitude: (removed)

Software: (absent)

Note: DateTimeOriginal is the camera's local wall clock. This camera stores no offset field, so the value carries no time zone of its own.

🌐 WHOIS: tomaszbd.example
WHOIS

Domain Name: TOMASZBD.EXAMPLE

Creation Date: 2026-06-24T00:00:00Z

Registrar: Northgate Domains

Registrant Organization: Privacy Protect Services

Registrant Street: 1500 West Georgia Street

Registrant City: Vancouver

Registrant State/Province: BC

Registrant Country: CA

Name Server: ns1.northgate-dns.example

Name Server: ns2.northgate-dns.example

💬 issue #501: 'maintainer identity' - thread
Forum

opened 2026-09-02 by u/hbraithwaite

The 2.1.0 tarball contains a postinstall script that was not in the git tag.
Before anyone argues about intent, can we establish who we are talking to?

u/hbraithwaite - 2026-09-02 07:30 UTC

The account is two months old and the profile photo is the only picture
of this person anywhere. Registering a matching domain the same week is
not evidence of a person, it is evidence of a setup.

u/rsaldana - 2026-09-02 19:11 UTC

I added them and I take responsibility. I never spoke to them by voice.

u/hbraithwaite - 2026-09-03 08:21 UTC

Their working day does not fit the city on their profile. Start there,
and give the number rather than a country. A whole day is off, not a
couple of hours.

Your answer
Real UTC offset, for example UTC+5 or UTC-4:

text
Type your answer...
Submit

Ask the coach
Stuck? Ask the Hacking Coach

What should I try next?

Start with the social media post and its photo, open those two cards on the board. What timestamp does the post show, and what time does the photo's own camera data say?

2026-07-30 14:58 UTC

That's the sign-off post, good catch. Now open the card with the photo taken just before it was shared - what time does that photo's camera clock show it was taken?

2026:08:12 18:42:07

Nice, that's the measurement pair. One clock says 14:58 UTC when it was posted, the other says 18:42 on the camera - what's the gap in hours between those two numbers?

+4

Analysis
Step 1 — Measurement pair
Post: 2026-08-12 15:44 UTC

Photo: 2026-08-12 18:42:07 local (no offset)

Raw gap: 18:42 − 15:44 = +2h58m

Naive read → offset ≈ UTC−3
But commit window would then be 03:00–12:00 local — implausible.

Step 2 — Commit window is the real tell
06:00–15:00 UTC = 9-hour workday

09:00–10:00 UTC gap = lunch

No weekends

Map to a normal 09:00–18:00 local day:

Event	UTC	Local (UTC+3)
Start	06:00	09:00
Lunch	09:00–10:00	12:00–13:00
End	15:00	18:00
→ Offset = UTC+3

Step 3 — Reconcile with photo
Photo local: 18:42

If UTC+3 → 15:42 UTC

Post: 15:44 UTC

Photo taken 18:42 local, posted 15:44 UTC = 18:44 local. Two minutes apart. "End of the day, desk finally tidy" fits perfectly.

Step 4 — Why not Vancouver?
Vancouver in August = UTC−7 (PDT)

Commit window in UTC−7 = 23:00–08:00 local — not a normal working day

hbraithwaite: "A whole day is off, not a couple of hours."

UTC−7 → UTC+3 = 10-hour shift, i.e. roughly a whole day

Answer
text
UTC+3
Real UTC offset: UTC+3

text
