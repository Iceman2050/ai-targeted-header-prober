> **ARCHIVED — merged into [header-hunter](https://github.com/Iceman2050/header-hunter).**
>
> The Signals Corps angle (AI-directive header names, AI-suggestive name
> fragments, hidden-payload patterns) now lives in header-hunter's analyzer,
> with its README section and tests. This repo is read-only; please use
> header-hunter instead.

# ai-targeted-header-prober

**Your site's HTTP headers may be talking to AI agents behind your back.**

On 2026-10-16, Signals Corps reported scanning 217M Common Crawl responses: **7,959 sites send AI-targeted headers**, and 30 were attempting **indirect prompt injection** through them (WebProNews; also The Register). Response headers never render in browsers — this is an injection channel invisible to humans.

`ai-targeted-header-prober` audits any URL's raw HTTP response headers for:
- **AI-directive headers** (`x-ai-scraper`, `x-llm-policy`, …) — machine-readable instructions aimed at scrapers/agents
- **Hidden injection payloads** — instruction patterns (`ignore previous instructions`, `curl … | sh`, …) hiding in header values → CRITICAL
- **AI-crawler policies** — `x-robots-tag` naming AI bots (visibility, not a finding)

## What it does NOT detect
Body-content injection, MCP traffic, or prompt attacks in page text. It audits headers only. A clean report means "no AI-targeted headers or hidden payloads detected", never a safety certification.

## Usage
```
python -m ai_targeted_header_prober https://example.com
```

Only probe sites you are authorized to test (or your own infrastructure). Non-public targets are refused.

## Built by Ingenious AI

This tool is built and maintained by **Ingenious AI**. Get early access to our AI security platforms:

- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20DisclosureGuard
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ModelMinder
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20TermsWatch
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Vibe-Code%20Audit
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Rogue-Agent%20Defense
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20BreachHunter
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ChatBreaker
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Agent%20Flight%20Recorder
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Agent%20Auth%20Gateway
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20DomainGuard
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ContentCraft%20AI


> Built by Ingenious AI
