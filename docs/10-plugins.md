# 10 · Plugins: CiaB & CLE

CyberCore ships two plugins, both nested under the **crucible** module. Each owns
its own database and adds a substantial feature set on top of the core platform.
This doc is an orientation, not an API reference — follow the file links for
detail.

For how plugins are loaded in general, see
[04-modules-and-plugins.md](04-modules-and-plugins.md).

---

## CiaB — Clinic-in-a-Box

> [modules/crucible/plugins/ciab/](../front-end/modules/crucible/plugins/ciab/)
> · database `clinic_db` · mount `/ciab` · API under `/`

**What it is:** an AI-powered **cyber risk-assessment training** platform. It's
historically the origin of this codebase (the repo's `package.json` is still
named `clinic-in-a-box`), and it's the largest plugin by far.

**What it does:** students act as consultants running a security assessment for a
simulated (or real) client organization. The plugin generates realistic client
**profiles**, drives a structured **intake**, produces a **risk assessment**
(CIS-RAM, NICE framework), and can **deploy a matching vulnerable lab** for the
profile.

### Capabilities (by route area)

| Area | Routes | What it covers |
|------|--------|----------------|
| Profiles | `profiles.js`, `api.js` | AI-generated client organizations; browse/own/tag. |
| Intakes | `intakes.js`, `intake-form.js`, `real-client-intake.js` | Structured intake questionnaires; synthetic and real-client variants. |
| Risk assessment | `clinic-risk-assessment.js`, `cis-ram.js` | CIS-RAM quantitative risk, findings, snapshots, insurance readiness. |
| Interview sim | `interview.js` | AI-driven stakeholder interview practice. |
| Documents | `clinic-api.js` | Generated policy/report deliverables (see `generated_documents`, `security_documents`). |
| Instructor | `instructor.js`, `progress.js` | Assignments, working sets, student progress. |
| Lab deploy | `profile-deploy.js` | Turns a profile into a deployed lane of vulnerable apps (bridges into the core lane system). |

### How it connects to the core platform

- **AI generation** runs through [utils/llm-client.js](../front-end/src/utils/llm-client.js)
  (Anthropic) — profiles, policies, examples, interview, and vuln-app synthesis.
  Historically some flows also used the external **n8n** workflows in
  [config/n8n/workflows/](../config/n8n/workflows/); those are optional.
- **Vuln-app builder** ([utils/vuln-app-builder.js](../front-end/modules/crucible/plugins/ciab/utils/)):
  builds per-profile vulnerable web apps as container images (this is why the app
  container mounts the Docker socket — see [09](09-deployment-and-ops.md)).
- **Lane deploy** reads/writes `crucible_challenge` and drives the same Proxmox
  provisioning path documented in [05-lanes-and-provisioning.md](05-lanes-and-provisioning.md).

### Data (`clinic_db`) — highlights

`profiles`, `intakes`, `real_client_intakes`, `risk_assets`, `risk_findings`,
`risk_snapshots`, `cis_ram_assessments`/`cis_ram_safeguards`, `security_documents`,
`generated_documents`, `interview_sessions`, `nice_framework_reference`,
`insurance_readiness`, plus instructor/bookkeeping tables. A handful of
table names (`deployed_groups`, `account_schedules`, `generated_documents`,
`instructor_working_sets`, `vuln_scripts`) also exist in `cybercore_db` — an
artifact of the CiaB→CyberCore split; the copies in `clinic_db` are the ones this
plugin uses.

---

## CLE — Cyber Learning Environment

> [modules/crucible/plugins/cle/](../front-end/modules/crucible/plugins/cle/)
> · database `cle_db` · mount `/cle` · API under `/`

**What it is:** **instructor tooling** for managing classes — the LMS-lite layer
over the range. Small and focused, and mostly instructor/admin-gated.

**What it does:** instructors create **courses**, enroll **students**, attach
**course materials** and **labs**, review **submissions**, and track **sessions**.
It ties courses to the lane/VM system so a course can provision lab environments
for its roster.

### Capabilities (by route area)

| Area | Routes | What it covers |
|------|--------|----------------|
| Courses | `courses.js`, `course-students.js` | Course CRUD, roster management, enrollment. |
| Students | `students.js` | Student directory within a course. |
| Labs / VMs | `labs.js`, `vms.js`, `templates.js` | Attach labs to courses; provision/track per-course VMs. |
| Provisioning | `utils/lane-provision.js` | Bridges course labs into the core lane system. |
| Consoles | `guacamole.js` | Guacamole console access for course VMs. |
| Sessions | `sessions.js` | Session/activity log (`cle_activity_log`). |

### Access control — important

CLE course-scoped routes must gate on the **shared, admin-aware** access helper
([utils/course-access.js](../front-end/modules/crucible/plugins/cle/utils/course-access.js),
`canManageCourse`/`getManagedCourse`) — **not** a raw `instructor_id` comparison.
An admin needs to manage any course, and an instructor only their own; the helper
enforces both. This is a known correctness requirement — see the pattern before
adding new course routes.

### Data (`cle_db`)

`cle_course`, `cle_course_enrollment`, `cle_course_material`,
`cle_student_submission`, `cle_activity_log`.

---

## At a glance

| | CiaB | CLE |
|---|------|-----|
| Purpose | Risk-assessment training (student-facing + AI) | Class/course management (instructor-facing) |
| Database | `clinic_db` (large) | `cle_db` (small) |
| Mount | `/ciab` | `/cle` |
| Primary role | student + instructor | instructor + admin |
| Ties into core via | profile → vuln-app lane deploy | course → lab lane provision |

---

That completes the documentation set. Back to the [index](README.md). If you
change how any subsystem works, update the matching doc in the same PR — these
files are only useful if they stay honest.
