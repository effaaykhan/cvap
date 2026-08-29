---
name: weekly-checkpoint
description: Check progress against the eight-week plan and flag scope creep.
argument-hint: "[week-number]"
disable-model-invocation: true
---

# Week $ARGUMENTS checkpoint

## Current state

```!
git log --oneline --since="7 days ago" | head -40
```

```!
git diff --stat HEAD~20 2>/dev/null | tail -5
```

## Assess

Read `docs/execution-plan.md` §3 for this week's deliverable and §2 for the frozen scope.

Report, briefly:

1. **Deliverable met?** The plan states one concrete thing per week that must run. State
   whether it does, and if not, what is missing.
2. **Scope creep.** Anything built this week that falls under the out-of-scope list in §2:
   CVE matching, credentialed assessment, DAST, API testing, SAST, cloud, containers,
   agents, reporting engine, Kubernetes. Name it plainly.
3. **Debt taken.** Shortcuts that will need paying back, and whether any of them touch
   scope enforcement, tenancy, or credentials — those cannot be deferred.
4. **Slippage.** If behind, the plan's cut order is: default-credential rules first,
   then OS guessing, then the exposure view. Recommend against that order.

Be blunt about slippage. The plan has no buffer, so a week lost is a week lost.
