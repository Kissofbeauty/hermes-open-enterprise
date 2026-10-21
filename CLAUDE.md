# CLAUDE.md — Hermes Open Enterprise

## Overview
Open-source (MIT) template สำหรับรัน **Hermes Agent (Nous Research)** ให้พนักงานทั้งองค์กรด้วย Docker Compose ล้วน
1 พนักงาน = 1 โฟลเดอร์ `Users/<name>/` = 1 container + 1 network + 1 subdomain (name = ชื่อใน server จาก email · subdomain ตั้งเอง) · ด่าน 1 = Hermes basic auth · ด่าน 2 = Cloudflare Access
repo นี้เป็น template สาธารณะ — **ห้ามใส่ข้อมูลองค์กรจริง** (องค์กรใช้สำเนา private) · PM docs (proposal, ohermes spec) อยู่ใน private docs repo ของผู้ดูแล (ไม่อยู่ใน repo สาธารณะนี้)

## Tech stack
- Docker Compose: `docker-compose.yml` (ohermes ไม่แก้) + `docker-compose.override.yml` (ohermes สร้างจาก `Users/*/`, gitignore: include พนักงาน + network ของ caddy/egress — Compose อ่านเองเมื่อมีไฟล์) · `nousresearch/hermes-agent:v0.22.2@sha256:…` (data `/opt/data`, dashboard 9119, UID 10000, Python 3.14 + ruamel.yaml ใน image) · image ทุกตัวปัก version+digest
- Caddy 2.10 (route เฉพาะ host ที่รู้จัก: `Infrastructure/caddy/generated/routes.caddy` ที่ ohermes สร้าง — `<EMP_SUBDOMAIN>.<HERMES_DOMAIN>` → alias `<name>.employee.internal:9119` · host อื่น 404) · cloudflared (profile `tunnel`)
- egress = Squid `ubuntu/squid:6.6-24.04_edge` (`EGRESS_IMAGE`) on `outbound` + every employee network · Hermes uses `HTTP(S)_PROXY=http://egress:3128`
- `ohermes` (bash) · ops container (alpine 3.22 + busybox crond + jq + age) · `setup.py` รันใน entrypoint ของ Hermes (root) · plugin `org-guard` (`Infrastructure/hermes/plugins/org-guard`)

## Docs map
| ไฟล์ | เนื้อหา |
|---|---|
| `README.md` | ภาพรวม + ติดตั้ง/ใช้งานแบบย่อ (อังกฤษ) |
| `guides/admin.md` · `guides/deploy.md` | คู่มือผู้ดูแล · GitOps + checklist ตั้งค่า GitHub (อังกฤษ, เผยแพร่) |
| `docs/` (gitignored, private — อาจไม่มีในเครื่องอื่น) | `admin-guide.md` `deploy.md` (ไทย) · `qa-report.md` · `security-review.md` (รอบ 5: R5-01..R5-13) — ห้ามอ้างอิง `docs/` จากไฟล์ที่เผยแพร่ |
| `SECURITY.md` | ข้อสมมติด้านความปลอดภัย |
| `CONTRIBUTING.md` · `CHANGELOG.md` · `CODE_OF_CONDUCT.md` | วิธีร่วมพัฒนา + test · release notes · CoC |
| maintainers' private docs repo: `project-proposal.md` · `ohermes-cli.md` (ไม่อยู่ใน repo นี้) | Proposal v0.6 (ภาคผนวก A Organization-Knowledge · B ohermes.conf + ทรัพย์สิน A1–A3 · C ผลตรวจ source Hermes) · สเปก ohermes |

## Project structure
```
.env(.example) docker-compose.yml docker-compose.override.yml(generated) ohermes
Users/_template/{compose.yml,config.yaml}
Users/<name>/{.env,compose.yml,config.yaml,data/,model/(ohermes model: model.yaml+model.env, 600),runtime/(setup.py: config.yaml hermes.env auth.json hooks/ skills/ org-skill-names.json)}
Organization-Knowledge/Organization/
  Assign/{Skills,Policy/{hr,security},Knowledge/{product,brand},KPI,Core-values}
  Department/<Dept>/Assign/{Skills,KPI,Knowledge}   Department/<Dept>/<name>/{Skills,KPI,Knowledge}   Department/General/
Config/{defaults,enforced}.yaml SOUL.md ohermes.conf (กฎเว็บ — ไม่ mount เข้า Hermes; Hermes ได้แค่ 3 ไฟล์แรกทีละไฟล์)
Infrastructure/caddy/{Caddyfile,access-dev.caddy,access-prod.caddy,generated/routes.caddy (gitignored, ohermes)}
Infrastructure/hermes/{start.sh,setup.py,model_capture.py,skills/org-navigator/,plugins/org-guard/{plugin.yaml,__init__.py,guard.py,tests/}}
Infrastructure/ops/{Dockerfile,crontab,scripts/}   Infrastructure/deploy/   Infrastructure/host/firewall.sh (ทางเลือก ไม่รันอัตโนมัติ)
Infrastructure/hermes/verify_guard_log.py (ตรวจลายเซ็นบรรทัด ORG-GUARD)
Infrastructure/egress/{squid.conf,start.sh,generated/rules.conf (gitignored, from ohermes reconf)}
Archive/ Logs/ Backups/   guides/ (เผยแพร่)   docs/ (private, gitignored)
```

## Conventions & workflow
- Git: `main` ← `uat` ← `feature/<name>` · Conventional Commits · PR (`skill-git-standard`) · `docs/` ไม่เผยแพร่ (อยู่ใน .gitignore)
- `ohermes` ไม่แก้ไฟล์ใน git (checkout บน server ไม่ dirty): `write_override` สร้าง `docker-compose.override.yml` ใหม่ทั้งไฟล์จาก `Users/*/` (มี `compose.yml` + `.env`) · `dc()` ส่ง `-f` ทั้งสองไฟล์ · networks ต้องเป็นรูป map (`<name>: {}`) เพราะ `edge`/`outbound` มี `gw_priority`
- ตัวแปรพนักงานใน `Users/<name>/.env` ต้องขึ้นต้น `EMP_` (กันชนกับตัวแปรของ host เช่น `USERNAME`) · ค่าใส่ single quote (hash มี `$`)
  - `EMP_USERNAME` = ชื่อใน server (โฟลเดอร์/service/network/login) · `EMP_EMAIL` · `EMP_SUBDOMAIN` (host เว็บ — Caddy route จาก routes.caddy · alias ของ container คือ `<EMP_USERNAME>.employee.internal`) · `EMP_DEPARTMENT` (ชื่อโฟลเดอร์แผนก ใช้ใน path mount) · `EMP_TITLE` · `EMP_NET_ID` · `EMP_NET_SUBNET` · ไม่มี `EMP_SLUG` แล้ว (archive เก่ายังอ่านเป็น fallback)
- compose project = `hermes-open-enterprise`
- Code/README อังกฤษ · admin-guide/qa ไทย · LF line endings

## Domain rules
- ชื่อใน server = ส่วนหน้า @ ของ email ตัวเล็ก + อักขระที่ไม่ใช่ a-z0-9 → `-` · ตั้งครั้งเดียวไม่เปลี่ยน · ห้ามชน (รวม Archive, ไม่สนตัวพิมพ์) · สงวน `assign` `caddy` `cloudflared` `ops` `egress` `edge` `outbound`
- subdomain a-z0-9- 1–63 · email/subdomain ห้ามซ้ำ (รวม Archive) · แผนก: จับคู่ไม่สนตัวพิมพ์ · ใหม่ → ตัวแรกใหญ่ · ไม่ระบุ → `General`
- `EMP_NET_ID` ถาวร ไม่ reuse (รวม Archive) → subnet `<NETWORK_PREFIX>.<id/16>.<(id%16)*16>/28`
- ลาออก = `ohermes rm` → stop + ย้าย `Users/<name>` และโฟลเดอร์ส่วนตัวใน Organization-Knowledge ไป `Archive/<name>_<date>/` (ส่วนตัวอยู่ใน `Organization-Knowledge/` ข้างใน) · **ไม่ลบข้อมูลเด็ดขาด**
- Config merge (ตัวหลังชนะ): defaults → `Users/<name>/config.yaml` → AI model (personal `Users/<name>/model/` > central `AI_*` ใน root `.env`) → enforced → generated · setup.py เขียน `runtime/` ทุกครั้งที่ start · `runtime/config.yaml` เป็น JSON (YAML 1.1 ของ Hermes อ่าน `off` เป็น false) · mount `:ro` ทับ `/opt/data/{config.yaml,.env,auth.json,hooks}` — ค่าใน dashboard ไม่ถูกเก็บ (ตั้งใจ)
- AI key ไปถึง Hermes ทาง `runtime/hermes.env` → `/opt/data/.env` (Hermes โหลดแบบ override) เท่านั้น · start.sh `unset HOE_AI_*` ก่อน exec /init
- Organization-Knowledge mount `:ro` ทีละโฟลเดอร์: `Organization/Assign` → `/opt/org/organization` · `Department/<Dept>/Assign` → `/opt/org/department` · `Department/<Dept>/<name>/{Skills,KPI,Knowledge}` → `/opt/org/me/...` · **ห้าม mount `Organization/` `Department/` หรือทั้งแผนก**
- Skill: Hermes ปฏิเสธชื่อซ้ำข้าม external_dirs + local บัง external → setup.py สร้าง `runtime/skills/<tier>/<path>` (symlink) ชื่อซ้ำ: Organization > Department > Employee > system · ตัวซ้ำถูกตัด + WARNING · local ชนชื่อ → WARNING (ไม่ลบ) + org-guard บล็อกการสร้าง
- `Config/ohermes.conf` = กฎเว็บ บังคับโดย egress · IP ตรงถูกปฏิเสธทั้ง default allow/deny เว้นแต่ allow IP นั้น · ACL ชื่อเว็บใช้ `dstdomain -n` (ไม่ผ่าน reverse DNS)

## Constraints & gotchas
- **prod ต้องมี `ORIGIN_SECRET` (≥32) + Cloudflare Transform Rule ใส่ `X-Hermes-Origin`** — ไม่งั้น 403 ทุกคำขอ (ตั้งใจ)
- Caddy ปฏิเสธคำขอจากวงเครือข่ายพนักงาน ยกเว้น gateway (.1, .17, …) — Docker ส่ง published port ผ่าน gateway ของวงพนักงาน
- อย่าใช้ one-shot `depends_on: service_completed_successfully` กับ Hermes — ทำให้ทุก `up -d` สร้าง container ใหม่ (QA D2)
- Windows dev: `ohermes` ใช้ `cygpath -m` ให้ docker CLI · ต้อง `MSYS_NO_PATHCONV=1` เวลาสั่ง `docker exec` path แบบ `/opt/...`
- Docker Desktop: Hermes เตือน SQLite บน bind mount (dev เท่านั้น)
- `setup.py` (root) ห้าม import โมดูล Hermes หรืออ่านไฟล์ที่ agent คุมใน process ของ root — ทำใน `unprivileged()` (fork เป็น uid 10000 + HERMES_HOME ชั่วคราว) ไม่งั้น Hermes สร้างไฟล์ของ root ใน `/opt/data` แล้ว log/skills เขียนไม่ได้ (QA D5)
- อ่านอย่างเดียวใน `/opt/data`: `config.yaml` `.env` `auth.json` `SOUL.md` `active_profile` `hooks/` `plugins/` `profiles/` (ว่าง) — ไฟล์ต้นทางใน `runtime/` ต้องมีก่อน `up` (`ohermes sync`) · stage2 ของ image เตือน `chown /opt/data/profiles failed` ทุก start = ปกติ
- Squid: กฎ allow ทุกบรรทัดต้องลงท้าย `!to_private` และห้ามมี `dst` ACL ก่อนกฎชื่อ (กัน DNS leak H-04) · log egress: `strip_query_terms off`, ไฟล์ 0640 proxy ในโฟลเดอร์ 0750 root:proxy (root ใน egress ไม่มี FOWNER/DAC_OVERRIDE — อ่าน log จาก host)
- ตรวจ hardening ของคนที่รันอยู่: `Infrastructure/hermes/tests/live-check.sh <name>` · unit test org-guard อยู่ใน CI
- `Config/ohermes.conf` `[organization-knowledge] manage_folders = off` (Organization-Knowledge in its own git repo): `create`/`update -d`/`rm`/`restore`/`sync` never touch `Organization-Knowledge/` (only warn with paths; `rm` writes `Archive/<name>_<date>/Organization-Knowledge.README`) · Docker auto-creates missing mount folders (empty, root-owned) — accepted · `name_taken` skips Department folders when off · `org_managed` dies on an invalid value, `org_off_quiet` never dies · gen_rules ignores non-`[web…]` sections
- ยังไม่ทดสอบ: Cloudflare จริง, AI provider จริง (ทดสอบด้วย key ปลอม), สิทธิ์ไฟล์บน Linux host (runtime ของ root / model 600), `ohermes model` แบบ interactive จริง (ทดสอบ capture ผ่าน `hermes config set`)
- ไฟล์ `runtime/{config.yaml,hermes.env,auth.json}` ต้องมีก่อน `up` (bind `create_host_path: false`) → `ohermes create/restore/sync` สร้าง · setup.py เขียน **in place** (inode เดิม) ห้าม rename
- setup.py ล้มขณะยังไม่มี config ขององค์กร → exit 1 (Hermes ไม่ start = fail closed) · ห้ามแตะ `/opt/data` ด้วย path ที่ตาม symlink (H1) — ใช้ dir fd + `O_NOFOLLOW` + `fchown`
- `hermes config set` / `hermes plugins …` บน config ro ทิ้ง `installs/*/publication.json` → Hermes start ไม่ได้ → setup.py ลบให้ทุกครั้งที่ start
- Hermes rootfs read-only (tmpfs `/run:exec` `/tmp` `/var/tmp`) → `docker cp` เข้าไม่ได้ ใช้ `docker exec -i … sh -c 'cat > /tmp/x'` · cap_add ขั้นต่ำ: CHOWN DAC_OVERRIDE FOWNER SETUID SETGID · ops: DAC_READ_SEARCH SETGID SETUID (busybox crond ต้อง setgroups)
- dashboard/gateway/เครื่องมือ รัน uid เดียวกัน → agent อ่าน secret ของ dashboard + AI key ได้ (ข้อจำกัด Hermes) · gateway stdout ไปไฟล์ s6-log ใน /opt/data/logs (agent อ่าน/ลบได้) → org-guard เขียน log ทาง fd 2 ของตัวเอง (= stderr ของ container, pipe ของ root: agent เปิดผ่าน /proc ไม่ได้ — ทดสอบแล้ว) + เซ็น HMAC ต่อ process (`verify_guard_log.py`)
- browser: Chromium มีใน image, `agent-browser` ไม่มี → start.sh ติดตั้งครั้งแรกด้วย `hermes pm install agent-browser` ลง `/opt/data/tools` ผ่าน egress (ต้องเข้า registry.npmjs.org)
- Windows: heredoc + `python -` ทำ `\n` `\0` em-dash เพี้ยน — แก้ไฟล์ด้วย Edit หรือ script ไฟล์ + `python -X utf8`
- วงพนักงาน `internal: true` → ออกเน็ตได้ทาง egress เท่านั้น · Docker DNS ไม่ตอบชื่อภายนอกบนวง internal (ทดสอบ Engine 29) · ต้องมี `HTTP_PROXY` ตัวใหญ่+เล็ก และ `NODE_USE_ENV_PROXY=1` (Node) · aiohttp ต้อง `trust_env=True` ไม่งั้นออกไม่ได้
- กฎเว็บ: แก้ `Config/ohermes.conf` → `ohermes reconf` (check → gen `rules.conf.new` → `squid -k parse` → swap → `squid -k reconfigure`; ผิด = คงกฎเดิม) · egress start โดยไม่มี `rules.conf` → deny ทั้งหมด + marker `/run/hermes-first-boot` → reconf จะ restart egress
- Squid รันเป็น user proxy · cap ที่ต้องใช้: CHOWN/SETUID/SETGID · `-k reconfigure/rotate` ผ่าน `docker compose exec` ใช้ได้
- Production deploy ทำโดยผู้ดูแลระบบ (คน) — agent ไม่ deploy เอง

- R5 (รอบ 5): ไฟล์ shell start ใน HOME (`.profile` `.bashrc` …) = bind ro จาก `runtime/shell-rc` (ว่าง) · `PATH` ใน template ตัด `/opt/data/.local/bin` ออก (image ใส่ไว้หน้า /usr/bin) · `PYTHONNOUSERSITE=1` · provider lock อ่านจาก image + สำเนา `runtime/provider-facts.json` (ไม่มีทั้งคู่ = setup หยุด) · models.dev catalog: setup.py ดึงตอน start (child uid 10000 ผ่าน egress) → `runtime/models_dev_cache.json` mount ro ที่ `/opt/data/models_dev_cache.json` + `.etag` ว่าง · `models_dev.url` ใน enforced ชี้ port ปิด (Hermes refresh ไม่ได้) · default deny ต้อง allow `models.dev` · `ohermes provider_host` มีตาราง host ของ provider แบบ API key ทั้งหมด (v0.22.2)

## Commands
```bash
docker compose up -d                       # deploy / apply
./ohermes create -e <email> -s <subdomain> [-d dept] [-t title]
./ohermes update -u <name|email> [-d] [-t] [-e] [-s] | rm | restore | repasswd -u <name|email> | ls | check
./ohermes reconf [--dry-run]               # apply Config/ohermes.conf web rules to egress (no agent restart)
./ohermes model -u <name> [--show|--reset] # personal AI model (interactive, on the server)
./ohermes sync                             # rebuild docker-compose.override.yml + runtime files from Users/
docker run --rm --network none -v "$PWD/Infrastructure/hermes/plugins/org-guard:/g:ro" --entrypoint /opt/hermes/.venv/bin/python "$HERMES_IMAGE" -m unittest discover -s /g/tests   # org-guard tests
docker compose exec ops /ops/backup.sh     # backup now
docker compose exec ops /ops/logs.sh       # logs job now (caddy + egress + docker)
docker compose logs -f <name>
```
