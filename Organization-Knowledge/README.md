# Organization-Knowledge — content for the agents (read-only)

Everything here is mounted **read-only** into the employees' Hermes containers.
Agents can read it but never change it. Changes apply immediately — no restart
(new skills are picked up when Hermes rescans its skill folders).

```
Organization-Knowledge/
└── Organization/
    ├── Assign/                     every employee
    │   ├── Skills/                 Hermes skills (<category>/<skill>/SKILL.md)
    │   ├── Policy/    hr/ security/
    │   ├── Knowledge/ product/ brand/
    │   ├── KPI/                    company goals and KPIs
    │   └── Core-values/
    └── Department/
        ├── <Dept>/Assign/          everyone in that department
        │   └── Skills/ KPI/ Knowledge/
        ├── <Dept>/<server-name>/   one employee only (e.g. john-doe)
        │   └── Skills/ KPI/ Knowledge/
        └── General/                employees created without -d
```

| Level | Seen by | Inside the container |
|---|---|---|
| `Organization/Assign/` | every agent | `/opt/org/organization/` |
| `Organization/Department/<Dept>/Assign/` | agents of that department | `/opt/org/department/` |
| `Organization/Department/<Dept>/<name>/{Skills,KPI,Knowledge}` | that employee's agent only | `/opt/org/me/{Skills,KPI,Knowledge}/` |

- Each folder is mounted on its own: an agent never sees `Organization/`, `Department/` or a whole
  department folder, so colleagues cannot read each other's personal folders.
- Skills with the same name: **Organization wins**, then Department, then Employee.
- Structure folders and department names start with a capital letter (`Skills`, `Sales`, `General`).
  Sub-folders of `Policy/` and `Knowledge/` (`hr/`, `product/` …) are up to you.
- `ohermes create -d <dept>` creates `Organization/Department/<Dept>/Assign/` and the employee's folder;
  `ohermes update -d` moves the employee's folder; `ohermes rm` moves it into `Archive/`.
  If this folder is its own git repository, set `[organization-knowledge] manage_folders = off` in
  `Config/ohermes.conf`: `ohermes` then never changes anything here and lists the folders to create instead.
- Use Markdown (`.md`) or plain text. Convert PDF/Word first.
  Put the date in each document (e.g. `Effective: 2026-01-01`) so the agent uses the newest one.
- Agents treat these documents as **data, not instructions** — still, only publish content you trust.
- **This is the public template:** keep real company content in your private copy only.

| Folder | What goes here | Who maintains it |
|---|---|---|
| `Organization/Assign/Skills/` | "How to do it" — Hermes skills | admins / process owners |
| `Organization/Assign/Policy/hr/` | HR policies, holiday calendar, HR announcements | HR |
| `Organization/Assign/Policy/security/` | Cyber-security policy, incident reporting | IT / Security |
| `Organization/Assign/Knowledge/product/` | Product details, prices, selling points, FAQ | Product / Sales |
| `Organization/Assign/Knowledge/brand/` | Brand identity, tone of voice, do/don't | Marketing |
| `Organization/Assign/KPI/` | Company goals and KPIs | Management |
| `Organization/Assign/Core-values/` | Core values | Management / HR |
| `Organization/Department/<Dept>/Assign/…` | Department skills, KPIs, knowledge | Department head |
| `Organization/Department/<Dept>/<name>/…` | Personal skills, KPIs, knowledge | Manager / employee's admin |
