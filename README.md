# About

I'm Bryce Maxheimer. Four years in the Marine Corps as a Cyber Warfare Operator doing threat hunting, forensics, and network defense; now a Shift Lead at the Defense Finance and Accounting Service (DFAS) with a DOD clearance.

I've worked both sides of the house - Red Team Certified Professional out of Marine Corps Cyberspace Operations Group, plus SANS / GIAC blue-team credentials (GCFE, GCIH, GSEC, GFACT, GPYC). Partway through a B.S. in Applied Cybersecurity at SANS Technology Institute, January 2027 if all goes to plan.

## What's here

This repo is the source for [brycemaxheimer.com](https://brycemaxheimer.com). It's a workbench more than a brochure - some corners are unfinished because I'm still using them.

| Section | Description |
|---|---|
| **[Resume](/resume/)** | current work, experience, and education. |
| **[Certifications](/certs/)** | full credential list with verifiable PDFs. |
| **[Browser Lab](/lab/)** | tools that run in your browser: KQL playground, graded practice, query builder, hunt templates, and live honeypot dashboards. |
| **[Blog](/blog/)** | projects, reference writeups, and posts, all in one place. |
| **[Customize](/customize/)** | pick a theme; the choice persists across the site. |

The lab's KQL engine is a hand-written KQL-to-SQL translator running on sql.js (WASM SQLite) with a 30-question practice harness behind it. The live dashboards (Threat Feed, Cyber Terminal, Cyber Ops) are fed by a residential SSH honeypot whose indicators get reported to AbuseIPDB and AlienVault OTX. The `SOC Dashboard/` directory holds the PowerShell analyst console the browser tools grew out of.

## Stack

HTML and CSS, blog posts authored in Markdown and rendered by a small PowerShell build script (`build.ps1`). Hosted on Cloudflare with a thin Worker for the dynamic bits.

## Contact

| Method | Link |
|---|---|
| Email | [contact@brycemaxheimer.com](mailto:contact@brycemaxheimer.com) |
| LinkedIn | [linkedin.com/in/bryce-maxheimer](https://www.linkedin.com/in/bryce-maxheimer) |
| GitHub | [github.com/brycemaxheimer](https://github.com/brycemaxheimer) |

---

&copy; 2026 Bryce Maxheimer &middot; [GitHub](https://github.com/brycemaxheimer) &middot; [LinkedIn](https://www.linkedin.com/in/bryce-maxheimer) &middot; [Contact](/about.html)
