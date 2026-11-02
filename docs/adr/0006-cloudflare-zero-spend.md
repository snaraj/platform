# ADR 0006: Cloudflare zero infrastructure spend

- Status: Accepted
- Date: 2026-08-08

## Decision

Cloudflare infrastructure must cost $0. The account boundary is exactly two
active domain zones, each on the Free website plan. Registrar renewals for those
two domains are the only authorized Cloudflare charges and remain classified
separately from infrastructure. The allowlist contains those existing Free
zones, authoritative/proxied DNS, Universal SSL, DNSSEC, Cloudflare Tunnel, and
Zero Trust features whose Free entitlement is verified immediately before use.

Pro is the next paid website plan and is not authorized. The observed 2026-08-08
list price is $20 per domain/month with annual commitment or $25 month-to-month,
so two Pro zones would illustrate $40 or $50 monthly before tax. These figures
document the denied boundary; they never grant approval and must be refreshed
from Cloudflare before any future decision.

Workers, Pages Functions, storage, databases, queues, AI, media, Argo, Spectrum,
Load Balancing, Cache Reserve, paid/usage-based rate limiting, paid certificates,
paid security, trials, upgrades, subscriptions, and unknown products are denied.

Current official documentation reviewed on 2026-08-08 adds a contractual
boundary for `naranjo.online`'s proposed heavy-media use: the self-serve
Application Services terms require Free, Pro, and Business customers to use a
qualifying paid service for video and other large-file patterns. No safe file,
traffic, or bandwidth threshold is published. The documented 512 MB maximum
cacheable file size for Free/Pro/Business is only a technical cache limit;
larger responses bypass cache, and neither BYPASS nor `no-store` bypasses the
service terms or the proxied Tunnel path. Therefore deliberate large-media
delivery remains disabled and is a zero-spend `NO-GO`. Ordinary site pages and
modest UI assets remain subject to the existing audit and launch gates.

## Enforcement

Owner-approved product boundaries, read-only subscription audits and
least-privilege tokens without Billing Write or Registrar Write are primary
controls. Provider changes require a current scope decision, before/after
observations and a verified rollback. The separate audit token may have
Billing Read. Budget alerts are delayed secondary detection and never authorize
or stop spend. Failure means downtime, never paid fallback.

Official evidence:

- <https://www.cloudflare.com/service-specific-terms-application-services/>
- <https://developers.cloudflare.com/fundamentals/reference/policies-compliances/delivering-videos-with-cloudflare/>
- <https://developers.cloudflare.com/cache/concepts/default-cache-behavior/>
- <https://developers.cloudflare.com/tunnel/routing/>

## Amendment (2026-11-01)

The owner authorized a third Free zone, `hospedajedonlolo.com`, on 2026-11-01.
The account boundary in the decision above is therefore three active domain
zones, each on the Free website plan. Prior lines are left byte for byte
intact.

- Its Registrar renewal is the only charge this zone authorizes, classified
  separately from infrastructure like the other two. No product, plan, add-on
  or certificate is added.
- The zone was hardened before onboarding: DNSSEC active; a null MX, SPF
  `-all` and DMARC `p=reject` (the domain sends no mail); and CAA limited to
  the certificate authorities Universal SSL uses.
- The site's delivered page includes one video of about 20 MB. The
  heavy-media terms boundary recorded above applies to it unchanged: under
  the self-serve terms, video through the proxied edge needs a qualifying
  paid service, and no zero-spend product meets that. Its public delivery
  therefore stays a `NO-GO`. The site verifies the film on its volume but
  does not serve it (`site.Withheld` in the site repository), and the page
  shows its poster image. Only the owner can lift this boundary, through an
  explicit decision followed by a reviewed change in both repositories.

## Amendment (2026-11-02): the hospedajedonlolo.com film

The owner lifted the `NO-GO` above for exactly one file (issue #432). After
reviewing the live site, the owner was offered three choices: serve the film
from pie5 through the site's own Tunnel, accept the risk that the self-serve
terms let the provider limit or disable sites that serve video without its
paid video products; move it to an unlisted third-party embed loaded on
click; or keep it withheld. The owner chose to serve it. Prior lines are left
byte for byte intact.

- Scope: `don-lolo.mp4`, 19,997,437 bytes, SHA-256
  `084fa3c51ef60288b71477d889701e13a80406bda4a0464ebb10408afe688ebf`, served
  from the site's read-only media volume at `/assets/don-lolo.mp4` by
  snaraj/hospedajedonlolo.com v0.1.2 and later. Every other large-media case
  stays a `NO-GO`, naranjo.online's heavy media included.
- Zero spend is unchanged: no product, plan, add-on, trial or paid video
  service is added. If the provider objects, the failure is limited or
  disabled delivery for the zone, never a charge, and the response is to
  withhold the film again, never to buy a fallback.
- Rollback: a site release that withholds the film again, or selecting an
  earlier site release in snaraj/platform-k8s-infra.

## Amendment (2026-11-02): a fourth Free zone

A read of the account through Cloudflare's `cf` CLI on 2026-11-02, with the
default (OAuth) login, shows a fourth domain zone, `sloptube.fun`. The owner
delegated the decision on 2026-11-02, and the zone was kept, because deleting
an owner-created zone cannot be undone. Prior lines are left byte for byte
intact.

- Facts read on 2026-11-02: the zone is active on the Free website plan at $0;
  it was created on 2026-10-08; it has exactly one Universal certificate pack
  and no paid pack. It is an owner project and is not served by this
  platform.
- The account boundary in the decision above is therefore four active domain
  zones, each on the Free website plan.
- The edge hardening targets apply to the three platform zones
  (`naranjo.online`, `lidersea.com` and `hospedajedonlolo.com`) only. The
  owner-run account audit holds `sloptube.fun` to the zero-spend checks: the
  Free plan, a zero-priced subscription with no priced component, and
  Universal certificate packs only.
- The zero-spend boundary and every denied product above stay unchanged. No
  product, plan, add-on or certificate is added.
