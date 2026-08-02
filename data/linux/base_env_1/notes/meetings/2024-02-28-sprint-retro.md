# Sprint 14 Retro — Feb 28

## What went well
- Shipped the dataset catalog API ahead of schedule
- On-call rotation was quiet this sprint
- New hire (Daniel) ramped up quickly on the pipeline codebase

## What didn't go well
- Deploy on Tuesday broke staging for 2 hours because of a missing env var
- Code review backlog grew — some PRs sat for 3+ days
- The integration test suite is flaky again (Postgres container timeouts)

## Action items
- Add env var validation at startup (Marcus)
- Set up PR review reminders in Slack (Jonas)
- Investigate test container timeout — might need to bump resource limits (Daniel)
