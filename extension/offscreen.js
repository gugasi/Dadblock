// ============================================================================
// DADBLOCK OFFSCREEN DOCUMENT — on-device Prompt API host
//
// The Prompt API runs in a document context. The service-worker local detector
// communicates with this host through chrome.runtime.sendMessage.
//
// PROTOCOL v1
//   request:
//     {
//       target: 'offscreen',
//       type: 'DADBLOCK_LOCAL_AI',
//       protocol: 1,
//       op,
//       requestId,
//       payload
//     }
//
//   response:
//     { ok: true, protocol: 1, requestId, data }
//     { ok: false, protocol: 1, requestId, error: { code, message } }
//
//   operations:
//     ping | availability | status | init | prompt | cancel | reset
//
// Judge prompts accept an optional evidenceFormat:
//   'strings'   — compatible with the existing detector; default
//   'citations' — legacy internal source IDs
//   'typed-citations' — source IDs plus category and attribution
//
// Prompt text is never logged. This document keeps no persistent state.
// ============================================================================

(() => {
  'use strict';

  const PROTOCOL_VERSION = 1;
  const MESSAGE_TYPE = 'DADBLOCK_LOCAL_AI';
  const MESSAGE_TARGET = 'offscreen';

  const ROLES = ['analyzer', 'judge'];

  // Existing judge response format remains available so this host can be
  // installed before replacing modes/local/detector.js.
  const JUDGE_RESPONSE_CONSTRAINT = {
    type: 'object',
    additionalProperties: false,
    required: [
      'judgment',
      'analysis',
      'evidence',
      'dadTip',
      'isStorefront',
    ],
    properties: {
      judgment: {
        type: 'string',
        enum: [
          'SAFE',
          'SCAM',
          'WARNING',
          'INBOX',
          'INCONCLUSIVE',
        ],
      },
      analysis: {
        type: 'string',
      },
      evidence: {
        type: 'array',
        maxItems: 3,
        items: {
          type: 'string',
        },
      },
      dadTip: {
        type: 'string',
      },
      isStorefront: {
        type: 'boolean',
      },
    },
  };

  // The detector supplies numbered excerpts and validates every returned ID.
  // It then builds the public evidence strings from the original excerpts.
  //
  // This host does not infer whether an artifact ID is valid; that requires
  // the detector's per-scan source table.
  const JUDGE_CITATION_RESPONSE_CONSTRAINT = {
    type: 'object',
    additionalProperties: false,
    required: [
      'judgment',
      'analysis',
      'evidence',
      'dadTip',
      'isStorefront',
    ],
    properties: {
      judgment: {
        type: 'string',
        enum: [
          'SAFE',
          'SCAM',
          'WARNING',
          'INBOX',
          'INCONCLUSIVE',
        ],
      },
      analysis: {
        type: 'string',
      },
      evidence: {
        type: 'array',
        maxItems: 3,
        items: {
          type: 'object',
          additionalProperties: false,
          required: [
            'artifactId',
            'finding',
          ],
          properties: {
            artifactId: {
              type: 'integer',
              minimum: 1,
            },
            finding: {
              type: 'string',
              minLength: 1,
              maxLength: 100,
            },
          },
        },
      },
      dadTip: {
        type: 'string',
      },
      isStorefront: {
        type: 'boolean',
      },
    },
  };

  // Typed findings use a separate format so older clients remain compatible.
  const JUDGE_TYPED_CITATION_RESPONSE_CONSTRAINT = {
    "type": "object",
    "additionalProperties": false,
    "required": [
      "judgment",
      "analysis",
      "evidence",
      "dadTip",
      "isStorefront"
    ],
    "properties": {
      "judgment": {
        "type": "string",
        "enum": [
          "SAFE",
          "SCAM",
          "WARNING",
          "INBOX",
          "INCONCLUSIVE"
        ]
      },
      "analysis": {
        "type": "string",
        "minLength": 1,
        "maxLength": 2000
      },
      "evidence": {
        "type": "array",
        "maxItems": 3,
        "items": {
          "type": "object",
          "additionalProperties": false,
          "required": [
            "artifactId",
            "finding",
            "category",
            "source"
          ],
          "properties": {
            "artifactId": {
              "type": "integer",
              "minimum": 1
            },
            "finding": {
              "type": "string",
              "minLength": 1,
              "maxLength": 100
            },
            "category": {
              "type": "string",
              "enum": [
                "CREDENTIAL_THEFT_REQUEST",
                "FRAUDULENT_PAYMENT_REQUEST",
                "EXTORTION_DEMAND",
                "DECEPTIVE_INSTALLATION_REQUEST",
                "IDENTITY_MISMATCH",
                "TERM_CONTRADICTION",
                "UNEXPECTED_ACCESS_DEMAND",
                "FRAUD_CONTEXT_CLAIM",
                "STREAMING_OFFER",
                "STREAMING_CATALOG",
                "STREAMING_MIRROR",
                "ADULT_CONTENT_NOTICE",
                "COMMUNITY_LINK",
                "USER_COMMENT",
                "OTHER_CONTEXT"
              ]
            },
            "source": {
              "type": "string",
              "enum": [
                "PAGE",
                "MESSAGE",
                "USER_CONTENT",
                "UNKNOWN"
              ]
            }
          }
        }
      },
      "dadTip": {
        "type": "string",
        "minLength": 1,
        "maxLength": 320
      },
      "isStorefront": {
        "type": "boolean"
      }
    }
  };

  const INIT_TIMEOUT_MS = 55000;
  const MAX_PROMPT_CHARS = 16000;
  const MAX_SYSTEM_PROMPT_CHARS = 60000;

  const DEFAULT_TIMEOUT_MS = 30000;
  const MIN_TIMEOUT_MS = 1000;
  const MAX_TIMEOUT_MS = 120000;

  const MAX_CONCURRENT_PROMPTS = 2;
  const IDLE_TEARDOWN_MS = 10 * 60 * 1000;

  const root =
    typeof self !== 'undefined'
      ? self
      : globalThis;

  // ==========================================================================
  // ERRORS
  // ==========================================================================

  class HostError extends Error {
    constructor(code, message) {
      super(message);

      this.name = 'HostError';
      this.code = code;
    }
  }

  // ==========================================================================
  // STATE
  // ==========================================================================

  const state = {
    sessions: {
      analyzer: null,
      judge: null,
    },

    configs: {
      analyzer: null,
      judge: null,
    },

    initKey: null,

    downloadPromise: null,
    downloadProgress: 0,
    lastDownloadError: null,

    idleTimer: null,
    lifecycleGeneration: 0,
    initializing: null,

    activeJobs: new Map(),
    queue: [],
    running: 0,
  };

  let initChain = Promise.resolve();

  // ==========================================================================
  // PROMPT API DISCOVERY AND AVAILABILITY
  // ==========================================================================

  function getPromptApi() {
    if (
      typeof root.LanguageModel !== 'undefined' &&
      root.LanguageModel
    ) {
      return {
        kind: 'LanguageModel',
        api: root.LanguageModel,
      };
    }

    if (
      root.ai &&
      root.ai.languageModel
    ) {
      return {
        kind: 'ai.languageModel',
        api: root.ai.languageModel,
      };
    }

    return null;
  }

  // Older Chrome names:
  //   no / after-download / readily
  //
  // Current names:
  //   unavailable / downloadable / downloading / available
  //
  // Unknown values never imply that the model is ready.
  function normalizeAvailability(raw) {
    switch (String(raw)) {
      case 'available':
      case 'readily':
        return 'readily';

      case 'downloadable':
      case 'after-download':
        return 'downloadable';

      case 'downloading':
        return 'downloading';

      default:
        return 'unavailable';
    }
  }

  async function queryAvailability() {
    const found = getPromptApi();

    if (!found) {
      return {
        availability: 'api-not-available',
        api: 'none',
      };
    }

    try {
      let raw;

      if (
        typeof found.api.availability === 'function'
      ) {
        const languageOptions =
          found.kind === 'LanguageModel'
            ? { expectedOutputs: [{ type: 'text', languages: ['en'] }] }
            : undefined;

        try {
          raw = await found.api.availability(languageOptions);
        } catch {
          raw = await found.api.availability();
        }
      } else if (
        typeof found.api.capabilities === 'function'
      ) {
        const capabilities =
          await found.api.capabilities();

        raw =
          capabilities &&
          capabilities.available;
      } else {
        return {
          availability: 'api-not-available',
          api: found.kind,
        };
      }

      return {
        availability: normalizeAvailability(raw),
        api: found.kind,
      };
    } catch (error) {
      console.warn(
        '[Dadblock Offscreen] availability() failed:',
        errName(error)
      );

      return {
        availability: 'error',
        api: found.kind,
      };
    }
  }

  // ==========================================================================
  // SMALL HELPERS
  // ==========================================================================

  function errName(error) {
    return error && error.name
      ? String(error.name)
      : 'Error';
  }

  function safeDestroy(session) {
    try {
      if (
        session &&
        typeof session.destroy === 'function'
      ) {
        session.destroy();
      }
    } catch {
      // The session may already have been destroyed.
    }
  }

  function fnv1a(value) {
    let hash = 0x811c9dc5;

    for (
      let index = 0;
      index < value.length;
      index++
    ) {
      hash ^= value.charCodeAt(index);
      hash = Math.imul(hash, 0x01000193);
    }

    return (hash >>> 0).toString(16);
  }

  function clamp(value, minimum, maximum) {
    return Math.min(
      maximum,
      Math.max(minimum, value)
    );
  }

  function sessionsReady() {
    return !!(
      state.sessions.analyzer &&
      state.sessions.judge
    );
  }

  // ==========================================================================
  // SESSION AND JOB LIFECYCLE
  // ==========================================================================

  function destroySessions() {
    safeDestroy(state.sessions.analyzer);
    safeDestroy(state.sessions.judge);

    state.sessions = {
      analyzer: null,
      judge: null,
    };

    state.configs = {
      analyzer: null,
      judge: null,
    };

    state.initKey = null;
  }

  function cancelQueuedJob(jobId, error) {
    const index = state.queue.findIndex(
      item => item.jobId === jobId
    );

    if (index < 0) {
      return false;
    }

    const [item] = state.queue.splice(
      index,
      1
    );

    item.reject(error);

    return true;
  }

  function abortAllJobs(reason) {
    for (
      const [jobId, job] of state.activeJobs
    ) {
      job.cancelled = true;

      try {
        job.controller.abort(
          new Error(reason)
        );
      } catch {
        // Ignore repeated cancellation.
      }

      cancelQueuedJob(
        jobId,
        new HostError(
          'ABORTED',
          'The scan was cancelled.'
        )
      );
    }
  }

  function touch() {
    if (state.idleTimer) {
      clearTimeout(state.idleTimer);
    }

    state.idleTimer = setTimeout(
      () => {
        state.idleTimer = null;

        if (
          state.activeJobs.size === 0 &&
          state.running === 0 &&
          state.queue.length === 0 &&
          !state.initializing
        ) {
          // The detector can reinitialize after SESSION_NOT_READY.
          destroySessions();
        } else {
          touch();
        }
      },
      IDLE_TEARDOWN_MS
    );
  }

  function teardownAll(reason) {
    // Invalidate initialization requests already queued or in flight.
    state.lifecycleGeneration++;

    if (state.initializing) {
      try {
        state.initializing.controller.abort(
          new Error(reason)
        );
      } catch {
        // Ignore repeated cancellation.
      }
    }

    abortAllJobs(reason);
    destroySessions();

    if (state.idleTimer) {
      clearTimeout(state.idleTimer);
      state.idleTimer = null;
    }
  }

  // ==========================================================================
  // INITIALIZATION CONFIGURATION
  // ==========================================================================

  function validateRoleConfig(config, label) {
    if (
      !config ||
      typeof config !== 'object'
    ) {
      throw new HostError(
        'BAD_REQUEST',
        `Missing ${label} config.`
      );
    }

    const {
      systemPrompt,
      temperature,
      topK,
    } = config;

    if (
      typeof systemPrompt !== 'string' ||
      !systemPrompt.trim() ||
      systemPrompt.length > MAX_SYSTEM_PROMPT_CHARS
    ) {
      throw new HostError(
        'BAD_REQUEST',
        `Invalid ${label} system prompt.`
      );
    }

    const validated = {
      systemPrompt,
    };

    if (
      temperature !== undefined ||
      topK !== undefined
    ) {
      // Extensions must provide both sampling parameters together.
      if (
        !Number.isFinite(temperature) ||
        !Number.isInteger(topK) ||
        topK < 1
      ) {
        throw new HostError(
          'BAD_REQUEST',
          `Invalid ${label} sampling parameters.`
        );
      }

      validated.temperature = temperature;
      validated.topK = topK;
    }

    return validated;
  }

  function validateInitPayload(payload) {
    if (
      !payload ||
      typeof payload !== 'object'
    ) {
      throw new HostError(
        'BAD_REQUEST',
        'Missing init payload.'
      );
    }

    return {
      allowDownload:
        payload.allowDownload !== false,
      analyzer: validateRoleConfig(
        payload.analyzer,
        'analyzer'
      ),
      judge: validateRoleConfig(
        payload.judge,
        'judge'
      ),
    };
  }

  function computeInitKey(config) {
    const part = roleConfig => (
      `${fnv1a(roleConfig.systemPrompt)}.` +
      `${roleConfig.systemPrompt.length}.` +
      `${roleConfig.temperature}.` +
      `${roleConfig.topK}`
    );

    return (
      `${part(config.analyzer)}|` +
      `${part(config.judge)}`
    );
  }

  function buildCreateOptions(roleConfig) {
    const options = {
      initialPrompts: [
        {
          role: 'system',
          content: roleConfig.systemPrompt,
        },
      ],
    };

    if (
      getPromptApi()?.kind === 'LanguageModel'
    ) {
      options.expectedOutputs = [
        {
          type: 'text',
          languages: ['en'],
        },
      ];
    } else {
      options.outputLanguage = 'en';
    }

    if (
      roleConfig.temperature !== undefined
    ) {
      options.temperature =
        roleConfig.temperature;

      options.topK =
        roleConfig.topK;
    }

    return options;
  }

  // A new model download generally needs transient user activation.
  // An offscreen document cannot supply that activation. Preserve the
  // best-effort probe and expose any failure through the status operation.
  function startModelDownload(found) {
    if (state.downloadPromise) {
      return {
        started: true,
        inProgress: true,
      };
    }

    try {
      state.lastDownloadError = null;

      state.downloadPromise = found.api
        .create({
          monitor(monitor) {
            monitor.addEventListener(
              'downloadprogress',
              event => {
                const loaded = Number(
                  event && event.loaded
                );

                state.downloadProgress =
                  Number.isFinite(loaded)
                    ? clamp(loaded, 0, 1)
                    : 0;
              }
            );
          },
        })
        .then(
          warmSession => {
            safeDestroy(warmSession);
            state.downloadProgress = 1;
          },
          error => {
            state.lastDownloadError =
              errName(error);
          }
        )
        .finally(() => {
          state.downloadPromise = null;
        });

      return {
        started: true,
        inProgress: false,
      };
    } catch (error) {
      state.lastDownloadError =
        errName(error);

      return {
        started: false,
        inProgress: false,
      };
    }
  }

  function assertInitCurrent(job) {
    if (job.timedOut) {
      throw new HostError(
        'TIMEOUT',
        'Local AI initialization took too long.'
      );
    }

    if (
      job.generation !== state.lifecycleGeneration ||
      job.controller.signal.aborted
    ) {
      throw new HostError(
        'ABORTED',
        'Local AI initialization was cancelled.'
      );
    }
  }

  async function doInit(config, generation) {
    if (
      generation !== state.lifecycleGeneration
    ) {
      throw new HostError(
        'ABORTED',
        'Local AI initialization was cancelled.'
      );
    }

    const key = computeInitKey(config);

    if (
      state.initKey === key &&
      sessionsReady()
    ) {
      touch();

      return {
        availability: 'readily',
        api: 'cached',
        sessionsReady: true,
        reused: true,
      };
    }

    const job = {
      generation,
      controller: new AbortController(),
      timedOut: false,
      timer: null,
    };

    state.initializing = job;

    job.timer = setTimeout(
      () => {
        job.timedOut = true;

        try {
          job.controller.abort(
            new Error('initialization timeout')
          );
        } catch {
          // Ignore repeated cancellation.
        }
      },
      INIT_TIMEOUT_MS
    );

    let analyzer = null;
    let judge = null;

    try {
      assertInitCurrent(job);

      const probe = await raceAbort(
        queryAvailability(),
        job.controller.signal
      );

      assertInitCurrent(job);

      if (
        probe.availability === 'api-not-available' ||
        probe.availability === 'unavailable' ||
        probe.availability === 'error'
      ) {
        abortAllJobs('model unavailable');
        destroySessions();

        return {
          availability: probe.availability,
          api: probe.api,
          sessionsReady: false,
        };
      }

      if (
        probe.availability === 'downloadable' ||
        probe.availability === 'downloading'
      ) {
        abortAllJobs('model downloading');
        destroySessions();

        const found = getPromptApi();

        const download =
          config.allowDownload && found
            ? startModelDownload(found)
            : {
                started: false,
                inProgress: false,
              };

        return {
          availability: probe.availability,
          api: probe.api,
          sessionsReady: false,
          downloadStarted: download.started,
        };
      }

      const found = getPromptApi();

      if (!found) {
        abortAllJobs('model API unavailable');
        destroySessions();

        return {
          availability: 'api-not-available',
          api: 'none',
          sessionsReady: false,
        };
      }

      // Reconfiguration cancels jobs using the previous configuration.
      // An unchanged initialization took the cached path above.
      abortAllJobs('session configuration changed');
      destroySessions();

      analyzer = await raceAbort(
        found.api.create({
          ...buildCreateOptions(config.analyzer),
          signal: job.controller.signal,
        }),
        job.controller.signal,
        safeDestroy
      );

      assertInitCurrent(job);

      judge = await raceAbort(
        found.api.create({
          ...buildCreateOptions(config.judge),
          signal: job.controller.signal,
        }),
        job.controller.signal,
        safeDestroy
      );

      assertInitCurrent(job);

      state.sessions = {
        analyzer,
        judge,
      };

      state.configs = {
        analyzer: config.analyzer,
        judge: config.judge,
      };

      state.initKey = key;

      touch();

      return {
        availability: 'readily',
        api: probe.api,
        sessionsReady: true,
        reused: false,
      };
    } catch (error) {
      safeDestroy(analyzer);
      safeDestroy(judge);

      // A reset or timeout must not install sessions that finished late.
      assertInitCurrent(job);

      if (error instanceof HostError) {
        throw error;
      }

      console.warn(
        '[Dadblock Offscreen] Session creation failed:',
        errName(error)
      );

      return {
        availability: 'error',
        api: getPromptApi()?.kind || 'none',
        sessionsReady: false,
        errorName: errName(error),
      };
    } finally {
      clearTimeout(job.timer);

      if (state.initializing === job) {
        state.initializing = null;
      }
    }
  }

  // Serialize initialization. A reset also invalidates queued requests.
  function handleInit(payload) {
    const config =
      validateInitPayload(payload);

    const generation =
      state.lifecycleGeneration;

    const run = initChain.then(
      () => doInit(config, generation),
      () => doInit(config, generation)
    );

    initChain = run.catch(() => {});

    return run;
  }

  // ==========================================================================
  // PROMPT PAYLOAD VALIDATION
  // ==========================================================================

  function validatePromptPayload(payload) {
    if (
      !payload ||
      typeof payload !== 'object'
    ) {
      throw new HostError(
        'BAD_REQUEST',
        'Missing prompt payload.'
      );
    }

    if (!ROLES.includes(payload.role)) {
      throw new HostError(
        'BAD_REQUEST',
        'Unknown session role.'
      );
    }

    if (
      typeof payload.text !== 'string' ||
      payload.text.length === 0 ||
      payload.text.length > MAX_PROMPT_CHARS
    ) {
      throw new HostError(
        'BAD_REQUEST',
        'Prompt text is missing or too long.'
      );
    }

    if (
      typeof payload.jobId !== 'string' ||
      !/^[A-Za-z0-9_-]{4,64}$/.test(payload.jobId)
    ) {
      throw new HostError(
        'BAD_REQUEST',
        'Invalid job id.'
      );
    }

    const timeoutMs =
      Number.isFinite(payload.timeoutMs)
        ? clamp(
            payload.timeoutMs,
            MIN_TIMEOUT_MS,
            MAX_TIMEOUT_MS
          )
        : DEFAULT_TIMEOUT_MS;

    const evidenceFormat =
      payload.evidenceFormat === undefined
        ? 'strings'
        : payload.evidenceFormat;

    if (
      !['strings', 'citations', 'typed-citations'].includes(evidenceFormat) ||
      (
        payload.role !== 'judge' &&
        evidenceFormat !== 'strings'
      )
    ) {
      throw new HostError(
        'BAD_REQUEST',
        'Invalid evidence format.'
      );
    }

    return {
      role: payload.role,
      text: payload.text,
      jobId: payload.jobId,
      timeoutMs,
      evidenceFormat,
    };
  }

  // ==========================================================================
  // PER-JOB SESSION ISOLATION
  // ==========================================================================

  // Never prompt the shared baseline session. Each page receives a pristine
  // clone, or a fresh session from its stored system configuration.
  async function createEphemeralSession(role, signal) {
    const base = state.sessions[role];

    if (!base) {
      throw new HostError(
        'SESSION_NOT_READY',
        'Local AI session is not initialised.'
      );
    }

    if (typeof base.clone === 'function') {
      try {
        return await base.clone({
          signal,
        });
      } catch (error) {
        if (signal.aborted) {
          throw error;
        }

        // Fall through to a fresh session.
      }
    }

    const config = state.configs[role];
    const found = getPromptApi();

    if (!config || !found) {
      throw new HostError(
        'SESSION_NOT_READY',
        'Local AI session is not initialised.'
      );
    }

    return found.api.create({
      ...buildCreateOptions(config),
      signal,
    });
  }

  // Settle cancellation even when the browser API ignores its signal.
  // A clone or create operation that resolves later is explicitly destroyed.
  function raceAbort(
    promise,
    signal,
    cleanupLateValue = null
  ) {
    return new Promise((resolve, reject) => {
      let settled = false;

      const onAbort = () => {
        if (settled) {
          return;
        }

        settled = true;

        signal.removeEventListener(
          'abort',
          onAbort
        );

        reject(
          signal.reason ||
          new Error('aborted')
        );
      };

      signal.addEventListener(
        'abort',
        onAbort,
        {
          once: true,
        }
      );

      Promise.resolve(promise).then(
        value => {
          signal.removeEventListener(
            'abort',
            onAbort
          );

          if (settled) {
            if (cleanupLateValue) {
              try {
                cleanupLateValue(value);
              } catch {
                // Cleanup is best effort.
              }
            }

            return;
          }

          settled = true;
          resolve(value);
        },
        error => {
          signal.removeEventListener(
            'abort',
            onAbort
          );

          if (settled) {
            return;
          }

          settled = true;
          reject(error);
        }
      );

      if (signal.aborted) {
        onAbort();
      }
    });
  }

  function mapPromptError(error, job) {
    if (error instanceof HostError) {
      return error;
    }

    if (job.timedOut) {
      return new HostError(
        'TIMEOUT',
        'The on-device model took too long.'
      );
    }

    if (
      job.cancelled ||
      errName(error) === 'AbortError'
    ) {
      return new HostError(
        'ABORTED',
        'The scan was cancelled.'
      );
    }

    if (
      errName(error) === 'QuotaExceededError'
    ) {
      return new HostError(
        'INPUT_TOO_LARGE',
        'The page text exceeds the model context window.'
      );
    }

    return new HostError(
      'PROMPT_FAILED',
      `The on-device model failed (${errName(error)}).`
    );
  }

  async function executePrompt(payload, job) {
    let session = null;

    try {
      if (
        job.timedOut ||
        Date.now() >= job.deadline
      ) {
        job.timedOut = true;

        throw new HostError(
          'TIMEOUT',
          'The on-device model took too long.'
        );
      }

      if (
        job.cancelled ||
        job.controller.signal.aborted
      ) {
        throw new HostError(
          'ABORTED',
          'The scan was cancelled.'
        );
      }

      session = await raceAbort(
        createEphemeralSession(
          payload.role,
          job.controller.signal
        ),
        job.controller.signal,
        safeDestroy
      );

      if (
        job.timedOut ||
        Date.now() >= job.deadline
      ) {
        job.timedOut = true;

        throw new HostError(
          'TIMEOUT',
          'The on-device model took too long.'
        );
      }

      if (
        job.cancelled ||
        job.controller.signal.aborted
      ) {
        throw new HostError(
          'ABORTED',
          'The scan was cancelled.'
        );
      }

      const options = {
        signal: job.controller.signal,
      };

      if (
        payload.role === 'judge' &&
        getPromptApi()?.kind === 'LanguageModel'
      ) {
        options.responseConstraint =
          payload.evidenceFormat === 'typed-citations'
            ? JUDGE_TYPED_CITATION_RESPONSE_CONSTRAINT
            : payload.evidenceFormat === 'citations'
              ? JUDGE_CITATION_RESPONSE_CONSTRAINT
              : JUDGE_RESPONSE_CONSTRAINT;

        // The complete contract is supplied by the detector's prompts.
        options.omitResponseConstraintInput = true;
      }

      const text = await raceAbort(
        session.prompt(
          payload.text,
          options
        ),
        job.controller.signal
      );

      // Check the absolute deadline as well as the timer. A delayed timer
      // callback must not permit a response after its budget expired.
      if (
        job.timedOut ||
        Date.now() >= job.deadline
      ) {
        job.timedOut = true;

        throw new HostError(
          'TIMEOUT',
          'The on-device model took too long.'
        );
      }

      if (
        job.cancelled ||
        job.controller.signal.aborted
      ) {
        throw new HostError(
          'ABORTED',
          'The scan was cancelled.'
        );
      }

      if (typeof text !== 'string') {
        throw new HostError(
          'PROMPT_FAILED',
          'The on-device model returned a non-text response.'
        );
      }

      return {
        text,
      };
    } catch (error) {
      throw mapPromptError(error, job);
    } finally {
      safeDestroy(session);
    }
  }

  // ==========================================================================
  // QUEUE AND DEADLINES
  // ==========================================================================

  function runQueued(task, jobId) {
    return new Promise((resolve, reject) => {
      state.queue.push({
        task,
        jobId,
        resolve,
        reject,
      });

      pump();
    });
  }

  function pump() {
    while (
      state.running < MAX_CONCURRENT_PROMPTS &&
      state.queue.length > 0
    ) {
      const item = state.queue.shift();

      const job = state.activeJobs.get(
        item.jobId
      );

      if (
        !job ||
        job.cancelled ||
        job.timedOut
      ) {
        item.reject(
          new HostError(
            job?.timedOut
              ? 'TIMEOUT'
              : 'ABORTED',
            job?.timedOut
              ? 'The on-device model took too long.'
              : 'The scan was cancelled.'
          )
        );

        continue;
      }

      state.running++;

      Promise.resolve()
        .then(item.task)
        .then(
          item.resolve,
          item.reject
        )
        .finally(() => {
          state.running--;
          pump();
          touch();
        });
    }
  }

  function handlePrompt(payload) {
    const validated =
      validatePromptPayload(payload);

    if (
      !state.sessions[validated.role]
    ) {
      return Promise.reject(
        new HostError(
          'SESSION_NOT_READY',
          'Local AI session is not initialised.'
        )
      );
    }

    if (
      state.activeJobs.has(validated.jobId)
    ) {
      return Promise.reject(
        new HostError(
          'BAD_REQUEST',
          'Duplicate job id.'
        )
      );
    }

    const job = {
      controller: new AbortController(),
      timedOut: false,
      cancelled: false,
      deadline:
        Date.now() + validated.timeoutMs,
      timer: null,
    };

    state.activeJobs.set(
      validated.jobId,
      job
    );

    touch();

    // The budget includes queue waiting, cloning, and inference.
    job.timer = setTimeout(
      () => {
        job.timedOut = true;

        try {
          job.controller.abort(
            new Error('timeout')
          );
        } catch {
          // Ignore repeated cancellation.
        }

        cancelQueuedJob(
          validated.jobId,
          new HostError(
            'TIMEOUT',
            'The on-device model took too long.'
          )
        );
      },
      validated.timeoutMs
    );

    return runQueued(
      () => executePrompt(validated, job),
      validated.jobId
    ).finally(() => {
      clearTimeout(job.timer);

      if (
        state.activeJobs.get(validated.jobId) === job
      ) {
        state.activeJobs.delete(
          validated.jobId
        );
      }

      touch();
    });
  }

  function handleCancel(payload) {
    const jobId = payload?.jobId;

    if (typeof jobId !== 'string') {
      throw new HostError(
        'BAD_REQUEST',
        'Invalid job id.'
      );
    }

    const job = state.activeJobs.get(
      jobId
    );

    if (!job) {
      return {
        cancelled: false,
      };
    }

    job.cancelled = true;

    try {
      job.controller.abort(
        new Error('cancelled')
      );
    } catch {
      // Ignore repeated cancellation.
    }

    cancelQueuedJob(
      jobId,
      new HostError(
        'ABORTED',
        'The scan was cancelled.'
      )
    );

    return {
      cancelled: true,
    };
  }

  async function handleStatus() {
    const probe = await queryAvailability();

    return {
      availability: probe.availability,
      api: probe.api,
      sessionsReady: sessionsReady(),
      activeJobs: state.activeJobs.size,
      queued: state.queue.length,
      downloadInProgress:
        !!state.downloadPromise,
      downloadProgress:
        state.downloadProgress,
      lastDownloadError:
        state.lastDownloadError,
    };
  }

  // ==========================================================================
  // PROTOCOL DISPATCH
  // ==========================================================================

  async function dispatch(message) {
    if (
      message.protocol !== PROTOCOL_VERSION
    ) {
      throw new HostError(
        'BAD_REQUEST',
        'Unsupported protocol version.'
      );
    }

    switch (message.op) {
      case 'ping': {
        const found = getPromptApi();

        return {
          ready: true,
          protocol: PROTOCOL_VERSION,
          api:
            found ? found.kind : 'none',
        };
      }

      case 'availability':
        return queryAvailability();

      case 'status':
        return handleStatus();

      case 'init':
        return handleInit(
          message.payload
        );

      case 'prompt':
        return handlePrompt(
          message.payload
        );

      case 'cancel':
        return handleCancel(
          message.payload
        );

      case 'reset':
        teardownAll('reset');

        return {
          reset: true,
        };

      default:
        throw new HostError(
          'BAD_REQUEST',
          'Unknown operation.'
        );
    }
  }

  function success(requestId, data) {
    return {
      ok: true,
      protocol: PROTOCOL_VERSION,
      requestId:
        requestId || null,
      data,
    };
  }

  function failure(requestId, error) {
    const known =
      error instanceof HostError;

    if (!known) {
      console.error(
        '[Dadblock Offscreen] Unexpected error:',
        errName(error)
      );
    }

    return {
      ok: false,
      protocol: PROTOCOL_VERSION,
      requestId:
        requestId || null,
      error: {
        code:
          known
            ? error.code
            : 'INTERNAL',
        message:
          known
            ? error.message
            : 'Unexpected error in the local AI host.',
      },
    };
  }

  // Only extension documents and the service worker can drive the model.
  // Content scripts are rejected because sender.tab is present.
  function isTrustedSender(sender) {
    if (
      !sender ||
      sender.id !== chrome.runtime.id
    ) {
      return false;
    }

    if (sender.tab) {
      return false;
    }

    return (
      typeof sender.url === 'string' &&
      sender.url.startsWith(
        chrome.runtime.getURL('')
      )
    );
  }

  chrome.runtime.onMessage.addListener(
    (message, sender, sendResponse) => {
      // Leave unrelated messages for other extension listeners.
      if (
        !message ||
        message.target !== MESSAGE_TARGET ||
        message.type !== MESSAGE_TYPE
      ) {
        return false;
      }

      if (!isTrustedSender(sender)) {
        return false;
      }

      const requestId =
        typeof message.requestId === 'string'
          ? message.requestId
          : null;

      dispatch(message).then(
        data => sendResponse(
          success(requestId, data)
        ),
        error => sendResponse(
          failure(requestId, error)
        )
      );

      return true;
    }
  );

  root.addEventListener(
    'pagehide',
    event => {
      if (event.isTrusted) {
        teardownAll('pagehide');
      }
    }
  );

  root.addEventListener(
    'unhandledrejection',
    event => {
      console.error(
        '[Dadblock Offscreen] Unhandled rejection:',
        errName(
          event && event.reason
        )
      );
    }
  );

  console.log(
    '[Dadblock Offscreen] Local AI host ready.'
  );
})();
