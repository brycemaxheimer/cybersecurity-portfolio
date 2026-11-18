# Bryce Maxheimer - Cybersecurity Portfolio

I'm Bryce Maxheimer. Four years in the Marine Corps as a Cyber Warfare Operator doing threat hunting, forensics, and network defense; now an Integration Specialist on the Defense Finance and Accounting Service (DFAS) CSSP Analyst Team with a DOD clearance.

I've worked both sides of the house - Red Team Certified Professional out of Marine Corps Cyberspace Operations Group, plus SANS / GIAC blue-team credentials (GCFA, GCFE, GCIH, GSEC, GFACT, GPYC). Partway through a B.S. in Applied Cybersecurity at SANS Technology Institute, January 2027 if all goes to plan.

## How I got into cybersecurity

When I was in the 9th grade, I signed up for an elective at my high school called "Computer Maintenance." I had never really used a computer beyond my parents' desktop, so I had no idea what I was getting into. Once the class started, I realized how right a choice I had made.

The class covered what was essentially CompTIA A+, with hands-on labs and a chance to take the A+ certification exam as the final, which I took and passed. After that course I fell in love with technology, and I built my first desktop only a year later. Fast forward to 2022: I enlisted in the United States Marine Corps as a Cyber Warfare Operator. That occupational specialty put me through JCAC and COSC, where I learned everything about computers and cybersecurity, from reading assembly to offensive operations.

After 3.5 years of cybersecurity in the military, I entered the job market and began my civilian career as a SOC analyst.

## National Cyber League (NCL)

NCL is a collegiate CTF run on Cyber Skyline's platform, with an Individual Game and a Team Game each season. Challenges cover the nine NCL skill categories: open source intelligence, cryptography, password cracking, log analysis, network traffic analysis, forensics, scanning & reconnaissance, enumeration & exploitation, and web application exploitation.

### Fall 2026 season

| Game | Result | Report |
|---|---|---|
| Individual Game (Oct 23-25) | 281st of 6,366 in the All Student bracket. 2,555/3,000 points, 89.6% accuracy, 90.2% completion. | [Score breakdown, All Student (PDF)](Cyber%20Skyline/Bryce%20Maxheimer%20-%20NCL%20Fall%202026%20Individual%20Game%20Score%20Breakdown%20(All%20Student).pdf) &middot; public report pending |
| Team Game (Nov 6-8) | 9th of 290 teams in the Experienced Student bracket, 97th percentile, with team SANS.edu The Usual Subnets. 3,000/3,000 points, 97.1% accuracy, 100% completion. | [cyberskyline.com/report/LK5XY4EDVQ3L](https://cyberskyline.com/report/LK5XY4EDVQ3L) &middot; [Scouting Report (PDF)](Cyber%20Skyline/Bryce%20Maxheimer%20-%20NCL%20Fall%202026%20Team%20Game%20Scouting%20Report.pdf) |

#### Highlights

- **Team Game: 9th of 290 with a perfect 3,000/3,000** and 100% completion in every module. 99th percentile in Open Source Intelligence and 97th in Enumeration & Exploitation and Scanning & Reconnaissance.
- **Full marks in four modules:** Open Source Intelligence (390/390), Log Analysis, Forensics, and Exploitation & Enumeration (300/300 each).
- **100% accuracy** in Log Analysis, Network Traffic Analysis, and Password Cracking, with 147 correct answers on 164 attempts across the whole game and one hint used.
- **Accuracy went from 57.4% in Fall 2025 to 89.6% in Fall 2026**, the number I most wanted to fix after last season.

#### Reflection

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
