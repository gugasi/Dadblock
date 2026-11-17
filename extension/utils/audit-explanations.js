// Shared explanation guidance for the extension's Local and BYOK engines.
// The standalone Cloudflare Worker contains the same text.
// This module has no detector, storage, DOM, or network dependencies.

export const AUDIT_POLICY_REVISION = 'typed-findings-2026-10-14';

export const AUDIT_CONTEXT_GUIDANCE = `
CONTENT ATTRIBUTION AND VERDICT CALIBRATION:
- Distinguish the website's own offers and requests from user comments, reviews, quoted messages, and community posts.
- Adult-content notices, nudity, sexual content, and ordinary adult-video catalogs alone are not scam evidence; Dadblock is not an adult-content filter.
- A threatening chain comment, offensive remark, fictional statement, or health superstition alone is not evidence of a scam transaction.
- Ordinary Discord, Telegram, or other community links are not scam indicators merely because those services are linked.
- Redacted URL segments are privacy placeholders, not suspicious artifacts.
- Evaluate concrete fraudulent requests wherever they occur, including comments, but attribute them accurately to their source.
- Suspected unauthorized streaming alone warrants WARNING, not SCAM.
- The analyzer's preliminary SCAM label is a request for review, not evidence supporting the judge's final verdict.
- "Watch Now" indicates a playback action; "Ad-Free" concerns advertising. Neither alone establishes free access or missing licensing.
`;

export const AUDIT_EXPLANATION_GUIDANCE = `
EXPLANATION QUALITY AND FACTUAL LIMITS:
- Retain the complete security and shopping rules and the existing JSON schema.
- Keep analysis to one or two short, plain-language sentences. First say what was observed; then explain the concern or limitation.
- Discuss isStorefront only through its boolean field unless shopping context is relevant to the warning; do not spend analysis explaining absent cart or purchase controls on a streaming page.
- Catalogs, copyrighted title names, dubbed/subbed labels, play links, free access, and absent purchase controls are not, by themselves, proof of illegal distribution, malware, tracking, or fraud.
- Retain WARNING for supported suspected unauthorized-streaming patterns, but describe this as a streaming caution; do not present inferred licensing status as an established fact.
- Ordinary streaming catalogs are not automatically SCAM, and legitimate free or ad-supported services can be SAFE.
- If the excerpt only shows a catalog and watch links, describe those facts accurately and qualify any streaming concern; never invent downloads, credential demands, redirects, trackers, or popup behavior.
- Absence of a licensing statement in a partial excerpt does not prove absence of authorization.
- Evidence must explain what each cited artifact shows. A bare quotation or unexplained link is insufficient explanation.
- For the string evidence format, use a short finding followed by a short exact quotation. For the citation format, write the short finding and cite its supplied artifactId; the application attaches the source quotation.
- Describe distinct observations without padding them into stronger allegations.
- For SCAM, identify the actual deceptive demand, impersonation, or contradiction.
- Keep dadTip to one actionable sentence tailored to the observed concern.
- For a streaming caution without an observed harmful request, advise declining unexpected software installations, notification permissions, or requests for personal/payment information; phrase unobserved demands conditionally.
- Avoid moralizing about supporting creators or asserting that a visit is illegal.
- Do not say that Dadblock makes a website safe, guarantees protection, blocked all ads/trackers, or stopped a particular threat.
- You have no blocking telemetry. Claims about what the extension blocked must come from extension state, never from page text or inference.
- SAFE means no supported threat was observed in the scanned excerpt; INCONCLUSIVE remains unverified.
` + AUDIT_CONTEXT_GUIDANCE;