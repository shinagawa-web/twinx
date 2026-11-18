# Intervention log

Add one row for every input from a human: decisions, corrections, approvals and questions that changed the course. Decisions made before the experiment starts go here too.

Kinds:

- decision: the human chose between options
- correction: the human rejected or changed what the agent proposed or wrote
- approval: the human let the agent's proposal go ahead unchanged
- question: the human asked something, and the answer changed the plan

| Date | Stage | Kind | Trigger | Outcome |
|---|---|---|---|---|
| 2026-11-18 | Before start | correction | The agent proposed a first scope of static file serving and proxying over HTTP/1.1 only | Judged too narrow; expanded to five stages by adding gzip, TLS, HTTP/2 and caching |
| 2026-11-18 | Before start | decision | A name was needed | Chose twinx from three candidates (the agent recommended another one) |
| 2026-11-18 | Before start | decision | A home for the code was needed | A private repository under shinagawa-web |
| 2026-11-18 | Before start | decision | Whether to write an article about the results | Decide after the experiment ends |
| 2026-11-18 | Before start | question | The human did not see how the loop would run without them | The agent spelled out the driver, the Finder, the Fixer and the judge; the design itself did not change |
| 2026-11-18 | Before start | approval | The agent proposed writing the design and this log first, before any Rust code | Went ahead |
| 2026-11-18 | Before start | correction | The design and this log were written in Japanese | Everything in the repository is written in English |
| 2026-11-18 | Before start | correction | The README said running twinx in production is not a goal | Removed as unnecessary |
| 2026-11-18 | Before start | correction | The README listed performance as out of scope for judging | Removed; only nginx's C modules and Lua stay out of scope |
| 2026-11-18 | Before start | approval | The Mac user cannot reach Docker (the socket belongs to another user) and Rust is not installed; the agent proposed a dedicated Lima VM | Created the VM |
| 2026-11-18 | Before start | correction | The agent said Claude Code would need a login inside the VM | Not needed: as in other verification work, Claude Code stays on the Mac and runs commands in the VM through one script (scripts/run.sh) |
| 2026-11-18 | Before start | question | How the loop would move off the Mac | All state lives in git, and only scripts/run.sh knows whether it is on the Mac or on Linux |
| 2026-11-18 | Before start | question | Whether Claude Code on the web could run the loop | It can: its sessions are Ubuntu VMs with Docker and Rust. Decided to prepare for running the loop there, with scheduled tasks, and to move the pass/fail judge to GitHub Actions so it stays outside Claude |
| 2026-11-18 | Before start | correction | The log held only three decisions and missed the rest of the conversation, such as the execution environment | Log every human input as it happens, until the human starts working through GitHub issues |
| 2026-11-18 | Before start | decision | Logging interventions was a rule only the current session knew | Wrote it into CLAUDE.md so that other sessions follow it |
| 2026-11-18 | Before start | decision | nginx names itself as nginx/1.30.6 in the pages it generates, so twinx would have to claim to be nginx to pass | Option A of two: twinx names itself, and the harness replaces both names, and recounts Content-Length, before comparing |
| 2026-11-18 | Before start | approval | Five local commits were waiting to be pushed, and the next step was the GitHub Actions judge | Pushed, and went on to the judge |
| 2026-11-18 | Before start | approval | The agent proposed writing the Fixer and Finder rules and the cloud setup script next | Went ahead |
| 2026-11-18 | Before start | question | The step "create a new environment in claude.ai/code" did not say where or how | The agent spelled out the screens from the documentation; the plan did not change |
| 2026-11-18 | Before start | approval | The cloud environment, the GitHub App and a first session had to be set up by hand | Set them up; the harness ran in the cloud and nginx answered all four cases |
| 2026-11-18 | Before start | decision | The scheduled run needed a model, and changing it mid-experiment would make the results incomparable | Opus 5.5 (claude-opus-5-5) for the whole experiment |
| 2026-11-18 | Before start | approval | The agent proposed registering the hourly scheduled run | Registered as routine trig_01YX3pTLi2c3KYXT33CabyPp; the first run fires at 2026-11-18T10:34:00Z, which is when the experiment starts |
| 2026-11-18 | Before start | correction | The routine kept the account connectors (Claude Docs, Claude Code Remote), which the loop does not need and which could change its conditions | Removed them from the routine |
| 2026-11-18 | Before start | decision | The first run was set for 19:34 JST, too late in the day to review its results | Start at 2026-11-19 08:30 JST (2026-11-18T23:30:00Z) with a one-off run, then hourly from 09:30 JST |
