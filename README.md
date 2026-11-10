# Bryce Maxheimer - Cybersecurity Portfolio

I'm Bryce Maxheimer. Four years in the Marine Corps as a Cyber Warfare Operator doing threat hunting, forensics, and network defense; now an Integration Specialist on the Defense Finance and Accounting Service (DFAS) CSSP Analyst Team with a DOD clearance.

I've worked both sides of the house - Red Team Certified Professional out of Marine Corps Cyberspace Operations Group, plus SANS / GIAC blue-team credentials (GCFA, GCFE, GCIH, GSEC, GFACT, GPYC). Partway through a B.S. in Applied Cybersecurity at SANS Technology Institute, January 2027 if all goes to plan.

## How I got into cybersecurity

<!-- TODO(Bryce): replace this paragraph with your own origin story. -->
The Marine Corps is where it started. I went in as a Cyber Warfare Operator and spent four years on threat hunting, forensics, and network defense, which turned out to be the work I actually wanted to keep doing. That is why I stayed in the field after active duty, and why I'm finishing the degree at SANS.

## National Cyber League (NCL)

NCL is a collegiate CTF run on Cyber Skyline's platform, with an Individual Game and a Team Game each season. Challenges cover the nine NCL skill categories: open source intelligence, cryptography, password cracking, log analysis, network traffic analysis, forensics, scanning & reconnaissance, enumeration & exploitation, and web application exploitation.

### Fall 2026 season

| Game | Result | Report |
|---|---|---|
| Individual Game (Oct 23-25) | 281st of 6,366 in the All Student bracket. 2,555/3,000 points, 89.6% accuracy, 90.2% completion. | [Score breakdown, All Student (PDF)](Cyber%20Skyline/Bryce%20Maxheimer%20-%20NCL%20Fall%202026%20Individual%20Game%20Score%20Breakdown%20(All%20Student).pdf) &middot; <!-- TODO: public Scouting Report link once released --> public report pending |
| Team Game (SANS) | <!-- TODO --> Pending | <!-- TODO: public share link --> Pending, NCL releases score reports about 2 weeks after the Team Game |

#### Highlights

- **Full marks in four modules:** Open Source Intelligence (390/390), Log Analysis, Forensics, and Exploitation & Enumeration (300/300 each).
- **100% accuracy** in Log Analysis, Network Traffic Analysis, and Password Cracking, with 147 correct answers on 164 attempts across the whole game and one hint used.
- **Accuracy went from 57.4% in Fall 2025 to 89.6% in Fall 2026**, the number I most wanted to fix after last season.

#### Reflection

<!-- TODO(Bryce): personalize this, and add the Team Game once the report is out. -->
Last season my completion was high but my accuracy was 57.4%, well under the bracket average. That told me I was submitting before I had confirmed answers. This season I slowed down and verified first, and accuracy came up to 89.6% without giving up much completion.

The gaps this time were the hard challenges in Scanning & Reconnaissance, Network Traffic Analysis, and Password Cracking, which is where most of my missing points sit. That is where I'm putting my practice time before the next season.

Per NCL rules, I don't publish write-ups of NCL challenges. Write-ups from other CTFs go on the [blog](https://brycemaxheimer.com/blog/).

### Previous season: Fall 2025

| Game | Result | Report |
|---|---|---|
| Individual Game | Diamond 1 Medal, 97th percentile overall. 30th of 620 in the Experienced Students bracket. 2680/3000 points, 94.0% completion. | [cyberskyline.com/report/QCBEMP8D263T](https://cyberskyline.com/report/QCBEMP8D263T) &middot; [PDF](Cyber%20Skyline/Bryce%20Maxheimer%20-%20Cyber%20Skyline%20Report.pdf) &middot; [Certificate](Cyber%20Skyline/Bryce%20Maxheimer%20-%20Cyber%20Skyline%20Certificate.pdf) |

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
