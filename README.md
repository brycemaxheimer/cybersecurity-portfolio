# Bryce Maxheimer - Cybersecurity Portfolio

I'm Bryce Maxheimer. Four years in the Marine Corps as a Cyber Warfare Operator doing threat hunting, forensics, and network defense; now a Shift Lead at the Defense Finance and Accounting Service (DFAS) with a DOD clearance.

I've worked both sides of the house - Red Team Certified Professional out of Marine Corps Cyberspace Operations Group, plus SANS / GIAC blue-team credentials (GCFE, GCIH, GSEC, GFACT, GPYC). Partway through a B.S. in Applied Cybersecurity at SANS Technology Institute, January 2027 if all goes to plan.

## How I got into cybersecurity

<!-- TODO(Bryce): replace this paragraph with your own origin story. -->
The Marine Corps is where it started. I went in as a Cyber Warfare Operator and spent four years on threat hunting, forensics, and network defense, which turned out to be the work I actually wanted to keep doing. That is why I stayed in the field after active duty, and why I'm finishing the degree at SANS.

## National Cyber League (NCL)

NCL is a collegiate CTF run on Cyber Skyline's platform, with an Individual Game and a Team Game each season. Challenges cover the nine NCL skill categories: open source intelligence, cryptography, password cracking, log analysis, network traffic analysis, forensics, scanning & reconnaissance, enumeration & exploitation, and web application exploitation.

### Score reports

All links below are the public validation links from Cyber Skyline, so anyone can open the full report.

| Season | Game | Result | Report |
|---|---|---|---|
| Fall 2025 | Individual | 30th of 620 (Experienced Students bracket), 96th percentile, Diamond 1 Medal | [cyberskyline.com/report/QCBEMP8D263T](https://cyberskyline.com/report/QCBEMP8D263T) &middot; [PDF](Cyber%20Skyline/Bryce%20Maxheimer%20-%20Cyber%20Skyline%20Report.pdf) &middot; [Certificate](Cyber%20Skyline/Bryce%20Maxheimer%20-%20Cyber%20Skyline%20Certificate.pdf) |
| Fall 2026 | Team (SANS) | <!-- TODO --> Pending, score reports are released about 2 weeks after the Team Game | <!-- TODO: public share link --> |
| Fall 2026 | Individual | <!-- TODO --> Pending | <!-- TODO: public share link --> |

### Highlights (Fall 2025 Individual Game)

- **2680 / 3000 points**, against a bracket average of 1394.2.
- **94.0% completion**, against a bracket average of 53.8%.
- **Perfect category scores** in Open Source Intelligence (385/385), Log Analysis, Network Traffic Analysis, and Scanning & Reconnaissance (300/300 each).
- **Password Cracking at 90.0% accuracy**, the highest accuracy of any category for me.

### Reflection

<!-- TODO(Bryce): personalize this, and add your Team Game experience once the report is out. -->
The categories that went cleanly were the ones closest to my day job: logs, network traffic, and recon are the same muscles I use on shift. OSINT was the surprise, full marks but at 44.4% accuracy, which means I got there by brute persistence more than by method.

Accuracy is the number I'm least happy with. 57.4% overall against a bracket average of 70.8% says I was submitting answers before I'd confirmed them. While the completion rate made up for it this time, in a tighter game that habit costs placement. Going forward the goal is to verify before submitting, as well as to close the gaps in web application exploitation (75% completion) and password cracking (78.3% completion).

Per NCL rules, I don't publish write-ups of NCL challenges. Write-ups from other CTFs go on the [blog](https://brycemaxheimer.com/blog/).

## What's here

This repo is the source for [brycemaxheimer.com](https://brycemaxheimer.com). It's a workbench more than a brochure - some corners are unfinished because I'm still using them.

| Section | Description |
|---|---|
| **[Resume](https://brycemaxheimer.com/resume/)** | current work, experience, and education. |
| **[Certifications](https://brycemaxheimer.com/certs/)** | full credential list with verifiable PDFs. |
| **[Browser Lab](https://brycemaxheimer.com/lab/)** | tools that run in your browser: KQL playground, graded practice, query builder, hunt templates, and a live honeypot threat feed. |
| **[Blog](https://brycemaxheimer.com/blog/)** | projects, reference writeups, and posts, all in one place. |
| **[Customize](https://brycemaxheimer.com/customize/)** | pick a theme; the choice persists across the site. |

The lab's KQL engine is a hand-written KQL-to-SQL translator running on sql.js (WASM SQLite) with a 30-question practice harness behind it. The live threat feed is fed by a residential SSH honeypot whose indicators get reported to AbuseIPDB and AlienVault OTX. The `SOC Dashboard/` directory holds the PowerShell analyst console the browser tools grew out of.

## Stack

HTML and CSS, blog posts authored in Markdown and rendered by a small PowerShell build script (`build.ps1`). Hosted on Cloudflare with a thin Worker for the dynamic bits.

## Contact

| Method | Link |
|---|---|
| Email | [contact@brycemaxheimer.com](mailto:contact@brycemaxheimer.com) |
| LinkedIn | [linkedin.com/in/bryce-maxheimer](https://www.linkedin.com/in/bryce-maxheimer) |
| GitHub | [github.com/brycemaxheimer](https://github.com/brycemaxheimer) |

---

&copy; 2026 Bryce Maxheimer &middot; [GitHub](https://github.com/brycemaxheimer) &middot; [LinkedIn](https://www.linkedin.com/in/bryce-maxheimer) &middot; [Contact](https://brycemaxheimer.com/about.html)
