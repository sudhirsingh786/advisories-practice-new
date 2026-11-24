---
id: "CVE-YYYY-NNNNN"
name: "<Common name or short description>"
severity: "<Critical / High / Medium / Low>"
status: "<Identify / Prioritize / Remediate / Monitor / Closed>"
published: ""
updated: ""
summary: "<One or two sentences - what is broken, what an attacker can do, and the condition that makes it exploitable>"
---

# What you need to do

1. **Identify** by **<deadline with time zone>**: create your product line page under the [Inventory page](https://company.atlassian.net/wiki/spaces/EO/pages/CVE-YYYY-NNNNN-inventory), answer *Uses component?* (Yes / No / Unknown) and list affected resources.
2. **Prioritize**: answer the Yes/No context questions on your page; ServiceNow sets priority and due date from them (see the priority table on the site front page).
3. **Remediate**: write the remediation plan and keep *Control status* current.
4. **Monitor**: attach evidence when done; InfoSec verifies and re-scans.

If you suspect exploitation, contact InfoSec immediately through the incident line.

# Threat status

| Indicator | Status (as of YYYY-MM-DD) |
|---|---|
| Public disclosure | YYYY-MM-DD |
| CVSS | <vendor score and version; add other scores if they differ> |
| Public proof of concept | Yes / No / details |
| Exploited in the wild | Confirmed / Not confirmed |
| CISA KEV listing | Yes (date added, federal due date) / No |

# Am I affected?

| Condition | How to check | Affected when |
|---|---|---|
| <condition 1> | `<command>` | <result that means affected> |
| <condition 2> | `<command>` | <result> |

# Affected and fixed versions

| Product / distribution | Affected | Fixed |
|---|---|---|
| <vendor product> | <versions> | <version> |
| <product or version line> | Not affected | n/a |

# How to fix

| Option | When to use | Done when |
|---|---|---|
| <permanent fix> | Default | <verifiable evidence> |
| <temporary mitigation> | Only if the permanent fix is not possible yet | <evidence> and InfoSec-approved risk acceptance |

# Frequently asked questions

| Question | Answer |
|---|---|
| <question> | <validated answer> |

# Links

- [Confluence response hub](https://company.atlassian.net/wiki/spaces/EO/pages/CVE-YYYY-NNNNN)
- [ServiceNow parent ticket](https://company.service-now.com/)
- [Vendor advisory](https://example.com/vendor-advisory)
- [NVD entry](https://nvd.nist.gov/vuln/detail/CVE-YYYY-NNNNN)

# Vulnerability details

<Free section: extra headings, tables, nested bullets, command output, notes. Published exactly in the order written.>
