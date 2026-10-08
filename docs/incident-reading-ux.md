# Monitor 0.8.1: incident reading

An incident opens with its meaning, signal range, existing assessment and affected scope, and up to three primary facts. Known connection/error baseline facts use plain language in this short view. The full summary, every evidence/unknown item and exact copyable token remain under disclosures. A signal range is explicitly a first-to-last span, never a claim of continuous downtime.

The insufficient-evidence result means that anomalies were recorded but their cause and affected scope remain unknown. It does not certify a healthy server, name a culprit or recommend switching protocols. Unrecognized copy remains literal text. The device brief distinguishes missing historical records from unavailable data; current reporting status stays separately labeled inside the device panel.

Record-category buttons are above a fixed-height scroll region. Changing from a long sample table to a short journal table does not change the surrounding page height. Raw rows use a nested disclosure inside that region. Missing-data, read-failure, truncation and retention notices remain visible without opening raw values. A request generation fence discards responses from a previous section or closed/replaced subject. Journal display labels are translated; exact grouping and raw fields are preserved.

## Verification

- 144 DOM behavior checks pass, including default disclosure state, complete evidence preservation, literal future text, uncertainty, missing/read-failed records and delayed-response isolation.
- Local browser fixture: 80 samples followed by 16 journal rows. On the old UI, page height fell from 7,267 to 3,091 px and the section bar moved from 345 to -47 px in the viewport. With the fixed region, page height remained 1,446 px and the bar stayed at 345 px. An empty category also kept the same page height. These are synthetic records, not production telemetry.
- Desktop visual preview verified. The browser viewport override did not apply in this environment; mobile visual validation is not claimed.

## Scope and rollout

Only presentation and the public release identity change. VERSION and MONITOR_WEB_VERSION are 0.8.1; exact release checks move with them. Classifier, presenter, History v5, core/remote storage, ingest, evidence response contracts, enrollment and the Windows Agent remain unchanged. This server update requires no Windows reinstall, signing change or native resource test.

Release checklist:

- [x] Reproduce scroll displacement and verify bounded layout in a real browser.
- [x] Preserve full judgments, caveats, raw fields and source-failure semantics.
- [x] Run UI behavior checks and review changed paths.
- [ ] All existing CI gates pass on the exact candidate and merged main commits.
- [ ] Existing-server update completes with a healthy final receipt.
