// Pure audit contracts shared by Local and BYOK engines.
// The standalone Worker contains the same implementation.
// A valid citation proves that text was supplied, not that the model's
// category or attribution is factually correct.

export const FINDING_CATEGORIES = Object.freeze([
  'CREDENTIAL_THEFT_REQUEST',
  'FRAUDULENT_PAYMENT_REQUEST',
  'EXTORTION_DEMAND',
  'DECEPTIVE_INSTALLATION_REQUEST',
  'IDENTITY_MISMATCH',
  'TERM_CONTRADICTION',
  'UNEXPECTED_ACCESS_DEMAND',
  'FRAUD_CONTEXT_CLAIM',
  'STREAMING_OFFER',
  'STREAMING_CATALOG',
  'STREAMING_MIRROR',
  'ADULT_CONTENT_NOTICE',
  'COMMUNITY_LINK',
  'USER_COMMENT',
  'OTHER_CONTEXT',
]);

export const FINDING_SOURCES = Object.freeze([
  'PAGE',
  'MESSAGE',
  'USER_CONTENT',
  'UNKNOWN',
]);

const AUDIT_MODEL_JUDGMENTS = new Set([
  'SAFE', 'SCAM', 'WARNING', 'INBOX', 'INCONCLUSIVE',
]);

const AUDIT_SCAM_CATEGORIES = new Set([
  'CREDENTIAL_THEFT_REQUEST',
  'FRAUDULENT_PAYMENT_REQUEST',
  'EXTORTION_DEMAND',
  'DECEPTIVE_INSTALLATION_REQUEST',
]);

const AUDIT_CAUTION_CATEGORIES = new Set([
  'IDENTITY_MISMATCH',
  'TERM_CONTRADICTION',
  'UNEXPECTED_ACCESS_DEMAND',
]);

const AUDIT_STREAMING_CATEGORIES = new Set([
  'STREAMING_OFFER',
  'STREAMING_CATALOG',
  'STREAMING_MIRROR',
]);

const AUDIT_FINDING_LABELS = Object.freeze({
  CREDENTIAL_THEFT_REQUEST: 'Possible deceptive credential request',
  FRAUDULENT_PAYMENT_REQUEST: 'Possible fraudulent payment request',
  EXTORTION_DEMAND: 'Possible extortion demand',
  DECEPTIVE_INSTALLATION_REQUEST: 'Possible deceptive installation request',
  IDENTITY_MISMATCH: 'Possible sender or seller identity mismatch',
  TERM_CONTRADICTION: 'Possible contradiction in the stated terms',
  UNEXPECTED_ACCESS_DEMAND: 'Unexpected access requirement',
  FRAUD_CONTEXT_CLAIM: 'Claim accompanying a possible fraudulent request',
  STREAMING_OFFER: 'Streaming-related offer or viewing text',
  STREAMING_CATALOG: 'Streaming catalog or episode detail',
  STREAMING_MIRROR: 'Streaming server or third-party hosting text',
  ADULT_CONTENT_NOTICE: 'Adult-content notice',
  COMMUNITY_LINK: 'Community link',
  USER_COMMENT: 'User-posted comment',
  OTHER_CONTEXT: 'Other page context',
});

export function buildTypedAuditSchema(format = 'quotes') {
  const reference = format === 'citations'
    ? { artifactId: { type: 'integer', minimum: 1 } }
    : { quote: { type: 'string', minLength: 3, maxLength: 120 } };

  return {
    type: 'object',
    additionalProperties: false,
    required: ['judgment', 'analysis', 'evidence', 'dadTip', 'isStorefront'],
    properties: {
      judgment: {
        type: 'string',
        enum: Array.from(AUDIT_MODEL_JUDGMENTS),
      },
      analysis: { type: 'string', minLength: 1, maxLength: 2000 },
      evidence: {
        type: 'array',
        maxItems: 3,
        items: {
          type: 'object',
          additionalProperties: false,
          required: [
            format === 'citations' ? 'artifactId' : 'quote',
            'finding',
            'category',
            'source',
          ],
          properties: {
            ...reference,
            finding: { type: 'string', minLength: 1, maxLength: 100 },
            category: { type: 'string', enum: Array.from(FINDING_CATEGORIES) },
            source: { type: 'string', enum: Array.from(FINDING_SOURCES) },
          },
        },
      },
      dadTip: { type: 'string', minLength: 1, maxLength: 320 },
      isStorefront: { type: 'boolean' },
    },
  };
}

export function buildTypedAuditGuidance(format = 'quotes') {
  const reference = format === 'citations'
    ? 'Each evidence object has exactly artifactId, finding, category, and source. Use only a supplied integer artifactId; the application attaches its original text.'
    : 'Each evidence object has exactly quote, finding, category, and source. quote must be 3–120 characters copied from pageExcerpt, allowing only whitespace normalization.';

  return [
    '',
    'TYPED FINDINGS AND SEVERITY:',
    '- Retain all general security and shopping rules. This contract replaces the earlier evidence item format.',
    '- Adult content, age notices, fictional titles, insults, or chain comments alone are not fraud; Dadblock is a scam audit, not an adult-content filter.',
    '- Ordinary adult-video catalogs and normal playback controls are not, by themselves, evidence of unauthorized commercial streaming or a security concern.',
    '- Evaluate actual fraudulent demands in any context, including user comments, without attributing commenters to the website operator.',
    '- SAFE means no supported scam indicators in the supplied excerpt; uncertainty remains INCONCLUSIVE.',
    '- SCAM requires a concrete deceptive request for credentials, money, installation/access, or extortion. One well-grounded request can be enough; a lone payment demand in an ordinary shop context is at most WARNING.',
    '- Routine authentication, checkout, verification, software instructions, and company notifications are not fraudulent merely because they request an action.',
    '- CREDENTIAL_THEFT_REQUEST: an actual deceptive request for a password, recovery/seed phrase, private key, or comparable credential. A login form, or a one-time PIN or verification code that the person asked the site to send (sign-in, password reset), is NOT this. A code request is suspicious only when someone else asks the person to read out, forward or send it.',
    '- FRAUDULENT_PAYMENT_REQUEST: an actual deceptive payment, advance-fee, prize-fee, gift-card, or similar transaction demand.',
    '- EXTORTION_DEMAND: an actual coercive demand for money or sensitive details; an offensive remark or chain threat without a demand is not extortion.',
    '- DECEPTIVE_INSTALLATION_REQUEST: a deceptive installation or remote-access demand; ordinary installation instructions are not enough.',
    '- IDENTITY_MISMATCH: supplied incompatible sender, destination, seller, or business identities; an unfamiliar domain alone is not a mismatch.',
    '- TERM_CONTRADICTION: two supplied promises or clauses that materially conflict; ordinary restrictive terms alone are not a contradiction.',
    '- UNEXPECTED_ACCESS_DEMAND: an observed unusual access requirement deserving verification without established fraud.',
    '- FRAUD_CONTEXT_CLAIM: a supplied prize, guaranteed earning, infection, or coercive claim linked to a fraudulent request; it cannot alone support a threat verdict.',
    '- STREAMING_OFFER, STREAMING_CATALOG, STREAMING_MIRROR: factual viewing offers, episode/catalog details, or server/hosting statements; these are not theft, malware, or proof of missing licensing.',
    '- Streaming-only concerns can be WARNING, never SCAM. Legitimate free, ad-supported, or licensed services can remain SAFE.',
    '- ADULT_CONTENT_NOTICE, COMMUNITY_LINK, USER_COMMENT, OTHER_CONTEXT are context categories and cannot alone support WARNING or SCAM.',
    '- Do not assign a fraud category merely to preserve a preliminary verdict. If the quoted text supports only context, classify it as context.',
    '- source is PAGE for page-authored material, MESSAGE for the active message, USER_CONTENT for comments/reviews/community posts, or UNKNOWN when attribution is unclear.',
    '- Attribution and categories are interpretations, not independently verified facts.',
    '- For SCAM/WARNING, supply 1 to 3 distinct source artifacts. One concrete deceptive request is enough; identity mismatch, term contradiction, and unexpected access concerns need at least two relevant findings. Do not pad risk evidence with unrelated context.',
    '- SAFE, INBOX, and INCONCLUSIVE require evidence=[]. INBOX requires isStorefront=false.',
    '- Keep finding within 100 characters and describe the cited text, not hypothetical risks or legal conclusions.',
    '- Do not claim licensing, malware, tracking, popup behavior, or protection outcomes were verified.',
    '- ' + reference,
    '- Return exactly judgment, analysis, evidence, dadTip, and isStorefront, with no surrounding prose.',
    '',
    'EXPECTED JSON SCHEMA:',
    JSON.stringify(buildTypedAuditSchema(format)),
  ].join('\n');
}

function auditPlainObject(value) {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function auditExactKeys(value, keys) {
  return auditPlainObject(value) &&
    Object.keys(value).length === keys.length &&
    keys.every(key => Object.prototype.hasOwnProperty.call(value, key));
}

function auditCleanText(value) {
  if (typeof value !== 'string') return '';

  return value
    .replace(/[\u0000-\u001f\u007f-\u009f]+/g, ' ')
    .replace(/[\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]/g, '')
    .replace(/[<>]/g, '')
    .replace(/\s+/g, ' ')
    .trim();
}

function auditReadFindings(value, sourceText = null, artifacts = null) {
  if (!Array.isArray(value) || value.length > 3) return null;

  const byId = artifacts instanceof Map ? artifacts : null;
  const normalizedSource =
    typeof sourceText === 'string' ? auditCleanText(sourceText) : null;
  const seenReferences = new Set();
  const seenQuotes = new Set();
  const findings = [];

  for (const item of value) {
    const keys = byId
      ? ['artifactId', 'finding', 'category', 'source']
      : ['quote', 'finding', 'category', 'source'];

    if (
      !auditExactKeys(item, keys) ||
      !FINDING_CATEGORIES.includes(item.category) ||
      !FINDING_SOURCES.includes(item.source) ||
      typeof item.finding !== 'string' ||
      !item.finding.trim() ||
      item.finding.length > 100
    ) {
      return null;
    }

    let rawQuote;

    if (byId) {
      if (
        !Number.isSafeInteger(item.artifactId) ||
        seenReferences.has(item.artifactId)
      ) {
        return null;
      }

      const artifact = byId.get(item.artifactId);
      if (!artifact || typeof artifact.text !== 'string') return null;

      rawQuote = artifact.text;
      seenReferences.add(item.artifactId);
    } else {
      rawQuote = item.quote;
    }

    if (
      typeof rawQuote !== 'string' ||
      rawQuote.length < 3 ||
      rawQuote.length > 120
    ) {
      return null;
    }

    const quote = auditCleanText(rawQuote);
    if (quote.length < 3 || seenQuotes.has(quote)) return null;

    if (normalizedSource !== null && !normalizedSource.includes(quote)) {
      return null;
    }

    seenQuotes.add(quote);

    // Public finding labels are application-owned. Model prose cannot
    // turn an adult notice or streaming title into a malware allegation.
    findings.push({
      quote,
      finding: AUDIT_FINDING_LABELS[item.category],
      category: item.category,
      source: item.source,
    });
  }

  return findings;
}

function auditFormatEvidence(findings) {
  return findings.map(item => {
    const attribution =
      item.source === 'USER_CONTENT' ? 'User-posted: ' : '';

    return attribution + item.finding + ' — "' + item.quote + '"';
  });
}

// Streaming evidence must really be about watching or hosting media.
// This stops an arbitrary quote (a cookie notice, a search-engine menu)
// from being counted as proof of a streaming site.
const STREAMING_RELEVANT_TEXT =
  /\b(?:watch|stream|episode|season|movie|film|series|anime|cartoon|video|vid|porn|xxx|play|hd\b|subbed|dubbed|server|mirror|download)/i;

// A one-time PIN or verification code the person asked a site to send
// (sign-in, password reset), the site's own warnings about it, and plain
// sign-in button labels are routine. None of them is a credential theft
// request. Anything that hands a code to someone else, mentions a phone
// call, or asks for card, recovery-phrase or similar secrets is never
// treated as routine.
const ROUTINE_CODE_CONTEXT =
  /\b(?:pin|verification code|security code|one[- ]time (?:code|pin|password)|otp|passcode|6[- ]digit|enter the code)\b/i;
const PROTECTIVE_CODE_NOTICE =
  /(?:if you did(?:n['’]t| not) request|if this wasn['’]t you|never share (?:this|your)|do not share|we(?:'ll| will) never ask)/i;
const CODE_THEFT_SIGNALS =
  /\b(?:recovery phrase|seed phrase|secret phrase|private key|card pin|atm pin|bank pin|debit card|credit card|card number|cvv|cvc|ssn|social security|gift card)\b/i;
const CODE_HANDOFF =
  /\b(?:read|give|provide|tell|share|send|forward|relay|dictate|say)\b[^.!?]{0,80}\b(?:code|pin|otp)\b[^.!?]{0,60}\b(?:to|with)\s+(?:the |our |an? |your )?(?:agent|caller|representative|operator|technician|support|staff|team|advisor|someone|person|us|me)\b/i;
const PHONE_CONTEXT =
  /\b(?:agent|representative|advisor|operator|technician)\b[^.!?]{0,40}\b(?:call|phone|contact)\b|\bover the phone\b|\bby phone\b|\bon the phone\b|\bwill call you\b/i;
const ROUTINE_LOGIN_LABEL =
  /^(?:\[(?:button|link)\]\s*)?["“'‘]?\s*(?:(?:sign|log)[\s-]?(?:in|on)|continue|sign[\s-]?up|join)\b[^.!?\n]{0,50}["”'’]?$/i;
const LOGIN_LABEL_BLOCKERS =
  /password|phrase|seed|card|bank|verify|locked|suspended/i;

function auditIsRoutineCodeQuote(quote) {
  const text = String(quote || '').trim();

  if (
    CODE_THEFT_SIGNALS.test(text) ||
    CODE_HANDOFF.test(text) ||
    PHONE_CONTEXT.test(text)
  ) {
    return false;
  }

  if (PROTECTIVE_CODE_NOTICE.test(text)) return true;

  if (
    text.length <= 70 &&
    ROUTINE_LOGIN_LABEL.test(text) &&
    !LOGIN_LABEL_BLOCKERS.test(text)
  ) {
    return true;
  }

  return ROUTINE_CODE_CONTEXT.test(text);
}

const AUDIT_VISIBLE_PREFIX = /^\[(?:button|link|input|label|heading)\]\s*/i;

// The words a person would actually read, without the [LINK] / [BUTTON]
// tag and the "→ address" the scanner appends to link text.
function auditVisibleText(quote) {
  return String(quote || '')
    .replace(/\s*→\s*\S+\s*$/u, '')
    .replace(AUDIT_VISIBLE_PREFIX, '')
    .replace(/^["“'‘]+|["”'’]+$/g, '')
    .trim();
}

// A credential-theft finding must show an ask for something secret. The
// words are listed in several languages so a mislabeled sentence, such as
// "tap Yes to confirm your sign-in" or a plain link label, cannot raise an
// alarm on its own.
const CREDENTIAL_SECRET_TERMS =
  /passw|kennwort|credential|contrase|mot de passe|zugangsdaten|anmeldedaten|identifiant|passcode|passphrase|recovery|seed|mnemonic|private key|secret key|wallet|\bpin\b|\botp\b|cvv|cvc|\bssn\b|social security|sozialversicherung|\biban\b|card number|kartennummer|kreditkarte|credit card|debit card|tarjeta|carte bancaire|verification code|security code|sicherheitscode|best[äa]tigungscode|c[oó]digo|\bcode\b|\bclave\b|bank (?:details|login|account)|account number|login details|log-?in details/i;

// An "unexpected access" finding must be about installing, controlling or
// opening something, not an ordinary button such as "Use my location".
const ACCESS_REQUEST_TERMS =
  /install|download|extension|remote|screen|anydesk|teamviewer|allow|grant|permission|access to|control|admin|execute|run |macro|terminal|powershell|\bcmd\b|paste|update (?:your )?(?:browser|flash|player)|enable (?:macros|editing|content)|support (?:app|tool)/i;

// A payment finding must actually be about paying, and "pay nothing until
// your trial ends" or "free trial" is the opposite of a payment demand.
const PAYMENT_TERMS =
  /\bpay\w*|\bfees?\b|\bcharge[sd]?\b|transfer|deposit|\bwire\b|gift ?card|crypto|bitcoin|usdt|\bbtc\b|[$€£]|\b\d+(?:[.,]\d+)?\s?(?:usd|eur|gbp)\b|zahl|gebühr|überweis|bezahl|pagar|pago|pagamento|paiement|payer|frais|tarif|invoice|rechnung|shipping/i;
const PAYMENT_BENIGN =
  /pay nothing|nothing to pay|no (?:payment|charge|fee|cost)s?\b|free trial|cancel anytime|\$0\b|kostenlos|gratuit|gratis|sin cargo/i;
const CLAIM_TERMS =
  /\bwon\b|winner|prize|congrat|reward|\bgift|selected|lucky|\bclaim|urgent|immediately|final notice|expires?\b|act now|limited time|suspended|locked|\bverify|unusual (?:activity|sign)|security alert|refund|inheritance|lottery|free (?:gift|iphone|prize|money|cash)/i;
const EXTORTION_TERMS =
  /pay|fee|forfeit|expose|leak|publish|lock|delete|suspend|terminate|police|arrest|legal|lawsuit|\bfine\b|penalt|ransom|bitcoin|within \d+|hours|deadline|or (?:else|we)|will be (?:charged|closed|deleted|banned)|unless/i;

function auditVisibleIsBareUrl(visible) {
  return /^https?:\/\/\S+$/i.test(visible);
}

function auditFindingIsRelevant(item) {
  if (AUDIT_STREAMING_CATEGORIES.has(item.category)) return true;

  const visible = auditVisibleText(item.quote);

  if (visible.length < 12) return false;

  // A bare web address is a link target, not wording that asks for anything.
  if (auditVisibleIsBareUrl(visible)) return false;

  if (item.category === 'CREDENTIAL_THEFT_REQUEST') {
    return (
      CREDENTIAL_SECRET_TERMS.test(visible) &&
      !auditIsRoutineCodeQuote(visible)
    );
  }

  if (item.category === 'UNEXPECTED_ACCESS_DEMAND') {
    return ACCESS_REQUEST_TERMS.test(visible);
  }

  if (item.category === 'FRAUDULENT_PAYMENT_REQUEST') {
    return PAYMENT_TERMS.test(visible) && !PAYMENT_BENIGN.test(visible);
  }

  if (item.category === 'FRAUD_CONTEXT_CLAIM') {
    return CLAIM_TERMS.test(visible);
  }

  if (item.category === 'EXTORTION_DEMAND') {
    return (
      EXTORTION_TERMS.test(visible) ||
      CODE_HANDOFF.test(visible) ||
      PHONE_CONTEXT.test(visible) ||
      CREDENTIAL_SECRET_TERMS.test(visible)
    );
  }

  return true;
}

function auditCalibrate(judgment, findings, isStorefront) {
  const findingsBeforeRelevance = findings.length;
  findings = findings.filter(auditFindingIsRelevant);
  const everyFindingDropped =
    findingsBeforeRelevance > 0 && findings.length === 0;

  const common = {
    isStorefront: judgment !== 'INBOX' && isStorefront,
    modelJudgment: judgment,
    severityAdjusted: false,
    warningKind: null,
    auditFindings: [],
    evidence: [],
  };

  if (judgment === 'SAFE') {
    return {
      ...common,
      judgment,
      analysis: 'No scam indicators found in the scanned page text.',
      dadTip: isStorefront
        ? 'If this shop is unfamiliar, check recent delivery and refund experiences for its exact domain before paying.'
        : 'Verify unexpected requests for personal details, payment, or software installation independently.',
    };
  }

  if (judgment === 'INBOX') {
    return {
      ...common,
      judgment,
      analysis: 'Open the individual message you want Dadblock to check.',
      dadTip: 'Open an individual message and use Scan now to check its content.',
    };
  }

  if (judgment === 'INCONCLUSIVE') {
    return {
      ...common,
      judgment,
      analysis: "Dad couldn't get a clear read on the page text he could see, so this isn't confirmed safe.",
      dadTip: 'Rescan, or double-check any unexpected request yourself before sharing details or paying.',
    };
  }

  const risk = findings.filter(item =>
    AUDIT_SCAM_CATEGORIES.has(item.category) ||
    AUDIT_CAUTION_CATEGORIES.has(item.category)
  );

  const fraud = risk.filter(item =>
    AUDIT_SCAM_CATEGORIES.has(item.category)
  );

  const fraudSupport = findings.filter(item =>
    item.category === 'FRAUD_CONTEXT_CLAIM'
  );

  const supportedRisk = fraud.length > 0
    ? findings.filter(item =>
        AUDIT_SCAM_CATEGORIES.has(item.category) ||
        AUDIT_CAUTION_CATEGORIES.has(item.category) ||
        item.category === 'FRAUD_CONTEXT_CLAIM'
      )
    : risk;

  if (fraud.length >= 1 || supportedRisk.length >= 2) {
    // A lone payment demand is ambiguous in ordinary commerce, so it is
    // capped at WARNING unless another supported finding accompanies it.
    const soloPayment =
      supportedRisk.length === 1 &&
      fraud.length === 1 &&
      fraud[0].category === 'FRAUDULENT_PAYMENT_REQUEST';

    const finalJudgment =
      judgment === 'SCAM' && fraud.length > 0 && !soloPayment
        ? 'SCAM'
        : 'WARNING';

    const first = fraud[0] || supportedRisk[0];
    const userPosted = first.source === 'USER_CONTENT';
    const subject = userPosted ? 'user-posted content' : 'the quoted content';

    return {
      ...common,
      judgment: finalJudgment,
      severityAdjusted: judgment !== finalJudgment,
      warningKind: finalJudgment === 'WARNING' ? 'general' : null,
      auditFindings: supportedRisk,
      evidence: auditFormatEvidence(supportedRisk),
      analysis:
        'The scan flagged ' + first.finding.toLowerCase() +
        ' in ' + subject + '. Verify the request or conflicting terms independently before acting.',
      dadTip: finalJudgment === 'SCAM'
        ? 'Avoid the flagged request and contact the claimed sender or seller through a separately verified channel.'
        : 'Verify the quoted request, destination, or conflicting terms independently before sharing details or paying.',
    };
  }

  const streaming = findings.filter(item =>
    AUDIT_STREAMING_CATEGORIES.has(item.category) &&
    STREAMING_RELEVANT_TEXT.test(item.quote)
  );

  // A single fraud/caution finding must not disappear behind a streaming
  // warning. Insufficient supported risk evidence remains inconclusive.
  if (
    risk.length === 0 &&
    fraudSupport.length === 0 &&
    streaming.length >= 2 &&
    streaming.some(item =>
      item.category === 'STREAMING_OFFER' ||
      item.category === 'STREAMING_MIRROR'
    )
  ) {
    return {
      ...common,
      judgment: 'WARNING',
      severityAdjusted: judgment === 'SCAM',
      warningKind: 'streaming',
      auditFindings: streaming,
      evidence: auditFormatEvidence(streaming),
      analysis:
        'Heads-up from Dad: this looks like a free-streaming style site. Dad didn\'t spot any request for your money or passwords in the text he read, but sites like this can still have misleading buttons and pop-ups, so install nothing and allow no notifications unless you meant to.',
      dadTip:
        'Decline unexpected software installations, notification requests, or requests for personal/payment details.',
    };
  }

  return {
    ...common,
    judgment: 'INCONCLUSIVE',
    severityAdjusted: true,
    code: 'UNSUPPORTED_RISK_BASIS',
    analysis:
      everyFindingDropped
      ? "Dad saw nothing concrete to warn about, but he could not fully confirm this page is safe."
      : "Dad couldn't get a clear read on the page text he could see, so this isn't confirmed safe.",
    dadTip:
      'Rescan, or double-check any unexpected request yourself before sharing details or paying.',
  };
}

// On-device models sometimes add harmless extras to an answer that raises
// no concern (evidence on a SAFE verdict, an over-long tip). Those extras
// carry no safety meaning, so they are trimmed. SCAM and WARNING answers
// are never touched and stay strictly validated.
export function normalizeNonDangerAudit(parsed) {
  if (
    !auditPlainObject(parsed) ||
    !['SAFE', 'INBOX', 'INCONCLUSIVE'].includes(parsed.judgment)
  ) {
    return parsed;
  }

  const clip = (value, max) =>
    typeof value === 'string' ? value.trim().slice(0, max) : value;

  let storefront = parsed.isStorefront;

  if (storefront === 'true') storefront = true;
  if (storefront === 'false') storefront = false;

  return {
    judgment: parsed.judgment,
    analysis: clip(parsed.analysis, 2000),
    evidence: [],
    dadTip:
      clip(parsed.dadTip, 320) ||
      'Stay alert and double-check unexpected requests yourself.',
    isStorefront: storefront,
  };
}

// Names the first rule a model answer broke. Logs only field names and
// lengths, never page content.
export function diagnoseTypedModelAudit(parsed) {
  if (!auditPlainObject(parsed)) return 'NOT_AN_OBJECT';

  const keys = Object.keys(parsed).sort().join(',');

  if (keys !== 'analysis,dadTip,evidence,isStorefront,judgment') {
    return 'KEYS:' + keys;
  }

  if (!AUDIT_MODEL_JUDGMENTS.has(parsed.judgment)) return 'BAD_JUDGMENT';

  if (typeof parsed.analysis !== 'string' || !parsed.analysis.trim()) {
    return 'ANALYSIS_EMPTY';
  }

  if (parsed.analysis.length > 2000) return 'ANALYSIS_TOO_LONG';

  if (typeof parsed.dadTip !== 'string' || !parsed.dadTip.trim()) {
    return 'TIP_EMPTY';
  }

  if (parsed.dadTip.length > 320) return 'TIP_TOO_LONG';
  if (typeof parsed.isStorefront !== 'boolean') return 'STOREFRONT_TYPE';
  if (!Array.isArray(parsed.evidence)) return 'EVIDENCE_TYPE';

  const danger = parsed.judgment === 'SCAM' || parsed.judgment === 'WARNING';

  if (danger && (parsed.evidence.length < 1 || parsed.evidence.length > 3)) {
    return 'EVIDENCE_COUNT:' + parsed.evidence.length;
  }

  if (!danger && parsed.evidence.length !== 0) return 'EVIDENCE_ON_NON_DANGER';

  return 'EVIDENCE_NOT_GROUNDED';
}

export function validateTypedModelAudit(parsed, options = {}) {
  if (
    !auditExactKeys(parsed, [
      'judgment', 'analysis', 'evidence', 'dadTip', 'isStorefront',
    ]) ||
    !AUDIT_MODEL_JUDGMENTS.has(parsed.judgment) ||
    typeof parsed.analysis !== 'string' ||
    !parsed.analysis.trim() ||
    parsed.analysis.length > 2000 ||
    typeof parsed.dadTip !== 'string' ||
    !parsed.dadTip.trim() ||
    parsed.dadTip.length > 320 ||
    typeof parsed.isStorefront !== 'boolean' ||
    !Array.isArray(parsed.evidence) ||
    (parsed.judgment === 'INBOX' && parsed.isStorefront)
  ) {
    return null;
  }

  const danger = parsed.judgment === 'SCAM' || parsed.judgment === 'WARNING';

  if (
    (danger && (parsed.evidence.length < 1 || parsed.evidence.length > 3)) ||
    (!danger && parsed.evidence.length !== 0)
  ) {
    return null;
  }

  const findings = auditReadFindings(
    parsed.evidence,
    options.sourceText ?? null,
    options.artifacts ?? null,
  );

  if (!findings) return null;

  return auditCalibrate(parsed.judgment, findings, parsed.isStorefront);
}

// Used for trusted Worker responses and schema-neutral cache records.
// The Worker grounds quotes against its exact, server-redacted excerpt;
// the Cloud client checks the public contract and severity combination.
export function validatePublicAudit(value, judgment, sourceText = null) {
  if (
    !auditPlainObject(value) ||
    !AUDIT_MODEL_JUDGMENTS.has(judgment) ||
    !Array.isArray(value.evidence) ||
    !Array.isArray(value.auditFindings) ||
    typeof value.dadTip !== 'string' ||
    value.dadTip.length > 320 ||
    typeof value.isStorefront !== 'boolean' ||
    (judgment !== 'INCONCLUSIVE' && !value.dadTip.trim()) ||
    (judgment === 'INBOX' && value.isStorefront)
  ) {
    return null;
  }

  const danger = judgment === 'SCAM' || judgment === 'WARNING';

  if (!danger) {
    if (value.evidence.length || value.auditFindings.length) return null;

    return {
      evidence: [],
      auditFindings: [],
      dadTip: auditCleanText(value.dadTip),
      isStorefront: judgment !== 'INBOX' && value.isStorefront,
      warningKind: null,
    };
  }

  if (value.auditFindings.length < 1) return null;

  const findings = auditReadFindings(value.auditFindings, sourceText);
  if (!findings) return null;

  const calibrated = auditCalibrate(judgment, findings, value.isStorefront);

  if (
    calibrated.judgment !== judgment ||
    calibrated.auditFindings.length !== findings.length ||
    value.evidence.length !== calibrated.evidence.length ||
    value.evidence.some((item, index) =>
      typeof item !== 'string' ||
      item.length > 240 ||
      auditCleanText(item) !== calibrated.evidence[index]
    )
  ) {
    return null;
  }

  return calibrated;
}