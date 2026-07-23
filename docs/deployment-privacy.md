# Privacy and data protection guidance for deployers

This platform observes employee activity: which AI tools people use, on
which devices, with which account domains. In most jurisdictions that makes
deploying it a form of workplace monitoring, and in GDPR terms it will
usually warrant a Data Protection Impact Assessment (DPIA) before rollout.
This document is a starting checklist, not legal advice. Involve whoever
owns data protection in your organisation before you deploy.

## What this platform collects, and what it deliberately does not

Collected per finding: tool name, surface, OS, device identifier, username,
account domain, an evidence path, severity, timestamp.

Deliberately not collected: message or page content, browsing history beyond matches 
against the registry of known AI domains, keystrokes, file contents, credentials or 
tokens belonging to users.

How usernames are handled: for sign-ins on an approved corporate domain, the 
username (the local part of the work email) is recorded in the user field, because that 
identity is already known to IT. For personal-domain accounts the user field is left 
empty and only the domain is kept.

On endpoint collectors the username is the device's console account name, which is 
already visible to IT through the MDM.

The design intent is to answer "is a managed device using an unmanaged AI
account" with the minimum identifiable data that still supports a
conversation with the right person.

## The paste guard inspects content locally

The browser extension's paste guard scans text at the moment of paste or
drop into a known AI tool. That inspection happens on the device, inside
the page, and your DPIA should name it plainly rather than let "no content
collected" imply "no content touched". What keeps it proportionate:

- The pasted text is never transmitted, stored, or included in any
  finding, truncated or otherwise. Reports carry the detector id (e.g.
  payment_card), the action taken, the tool, the device and a timestamp.
- The "overridden" action records that a person chose to proceed past a
  warning. Tell staff this is recorded: it is the one paste-guard datum
  about a decision rather than a clipboard.
- What is scanned for is reviewable and centrally controlled: the detector
  list and its deliberate exclusions are open in `extension/src/guard.js`,
  and the classification markings come from your own document
  classification policy via managed configuration.
- Typed content, clipboard images and file uploads are not scanned.

## DPIA checklist

Work through these before deployment. Most map directly onto ICO / GDPR
Article 35 expectations; adapt to your jurisdiction.

**Purpose and lawful basis**
- [ ] State the purpose in one sentence. The intended one: identify
      unmanaged AI tool usage on managed devices to bring it under
      appropriate licensing, security and data governance.
- [ ] Identify your lawful basis (typically legitimate interests for
      security monitoring of corporate devices). Document the balancing
      test: the data is minimal, and the more intrusive alternatives
      (server-side content inspection, proxy interception) are avoided;
      the paste guard's inspection is client-side only and reports no
      content.
- [ ] Confirm scope is corporate-managed devices and corporate cloud
      tenants only. This tool has no visibility into personal devices,
      and you should keep it that way.

**Transparency**
- [ ] Tell staff before rollout. An acceptable-use or monitoring policy
      that names the platform, what it collects, what it does not, and
      what happens with findings. Silent deployment of monitoring is both
      a legal risk and a trust cost that outlasts any incident.
- [ ] Make the registry reviewable internally. People should be able to
      see what counts as an AI tool.

**Data minimisation and retention**
- [ ] Set retention on your log store and stick to it. Findings older
      than your stated window should age out; the dashboards here default
      to 7-day views for a reason.
- [ ] Do not extend the finding schema with content-bearing fields.

**Access and use**
- [ ] Scope dashboard and log access to the people who act on findings.
      A finding names a person; the audience for that is small.
- [ ] Decide and document the response path before the first finding: who
      talks to whom, and with what intent. This platform's findings are
      licensing and governance conversations, not disciplinary evidence.
      If your organisation intends to use them for discipline, that
      materially changes the DPIA and the transparency obligations.
- [ ] Alerting routes findings to a channel. Treat that channel's
      membership as an access control.

**Accuracy and challenge**
- [ ] Have a route for someone to say "that finding is wrong or
      explained". Test accounts, shared machines and IT staff doing their
      jobs will all appear; the platform reports signals, not conclusions.

**Security of the monitoring data itself**
- [ ] The log store is a map of who uses what on which machine. Apply
      the SECURITY.md guidance: restrict the Loki tenant or equivalent,
      protect the receiver token, TLS on ingest.

## A note on proportionality

The strongest privacy argument for this design over the alternatives is
what it does not do. It does not intercept traffic, inspect content, or
inventory general browsing. It matches known AI tool identifiers and reads
account domains from local tool configuration. If a regulator or works
council asks why this approach, that is the answer: it is the least
intrusive design that still closes the visibility gap.