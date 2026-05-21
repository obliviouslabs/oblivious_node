#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { createHash, randomBytes, X509Certificate } from 'node:crypto';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const DEFAULT_PHALA_VERIFY_API = 'https://cloud-api.phala.com/api/v1/attestations/verify';
const DSTACK_RUNTIME_EVENT_TYPE = 0x08000001;

function usage() {
  console.error(
    'Usage: node deploy/phala/verify_client_tdx.mjs <app-base-url> [expected-mrtd] [--strict-digests] [--attested-tls] [--tls-domain <domain>] [--pccs-url <url>] [--verifier-bin <path>] [--dstack-verifier-url <url>] [--require-dstack-verifier] [--phala-api] [--simulator-fixture]'
  );
  console.error('Default behavior verifies the quote locally and does not call Phala.');
  console.error(
    '--simulator-fixture uses the dstack simulator zero-report-data quote fixture; use the default fresh challenge on real TDX.'
  );
}

function scriptDir() {
  return dirname(fileURLToPath(import.meta.url));
}

function repoRoot() {
  return resolve(scriptDir(), '../..');
}

function normalizeHex(value, field) {
  if (typeof value !== 'string') {
    throw new Error(`${field} is missing`);
  }
  const hex = value.startsWith('0x') ? value.slice(2) : value;
  if (!/^[0-9a-fA-F]*$/.test(hex)) {
    throw new Error(`${field} is not hex`);
  }
  if (hex.length % 2 !== 0) {
    throw new Error(`${field} hex must contain an even number of characters`);
  }
  return hex.toLowerCase();
}

async function fetchJson(url, options) {
  const response = await fetch(url, options);
  const body = await response.text();
  if (!response.ok) {
    throw new Error(`${url} returned HTTP ${response.status}: ${body}`);
  }
  try {
    return JSON.parse(body);
  } catch (err) {
    throw new Error(`${url} returned non-JSON body: ${err.message}`);
  }
}

function eventLogEvents(eventLog) {
  if (!eventLog) {
    return [];
  }
  if (typeof eventLog === 'string') {
    try {
      return JSON.parse(eventLog);
    } catch {
      return [];
    }
  }
  return Array.isArray(eventLog) ? eventLog : [];
}

function parseJsonString(value) {
  if (typeof value !== 'string') {
    return value;
  }
  try {
    return JSON.parse(value);
  } catch {
    return value;
  }
}

function extractAppCompose(info) {
  const tcbInfo = parseJsonString(info?.tcb_info ?? info?.tcbInfo);
  return (
    tcbInfo?.app_compose ??
    tcbInfo?.appCompose ??
    info?.app_compose ??
    info?.appCompose ??
    null
  );
}

function dockerComposeFromAppCompose(appCompose) {
  if (!appCompose) {
    return null;
  }
  try {
    const parsed = typeof appCompose === 'string' ? JSON.parse(appCompose) : appCompose;
    return parsed?.docker_compose_file ?? parsed?.dockerComposeFile ?? null;
  } catch {
    return null;
  }
}

function checkPinnedImages(dockerComposeYaml) {
  if (!dockerComposeYaml) {
    return [];
  }
  return dockerComposeYaml
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.startsWith('image:'))
    .filter((line) => !line.includes('@sha256:'));
}

function parseArgs(argv) {
  const flags = {
    strictDigests: false,
    dstackVerifierUrl: process.env.DSTACK_VERIFIER_URL || '',
    requireDstackVerifier: false,
    phalaApi: false,
    simulatorFixture: false,
    attestedTls: false,
    tlsDomain: process.env.ATTESTED_TLS_DOMAIN || '',
    pccsUrl: process.env.PCCS_URL || '',
    verifierBin: process.env.TDX_QUOTE_VERIFIER_BIN || '',
  };
  const positional = [];
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--strict-digests') {
      flags.strictDigests = true;
    } else if (arg === '--require-dstack-verifier') {
      flags.requireDstackVerifier = true;
    } else if (arg === '--phala-api') {
      flags.phalaApi = true;
    } else if (arg === '--simulator-fixture') {
      flags.simulatorFixture = true;
    } else if (arg === '--attested-tls') {
      flags.attestedTls = true;
    } else if (arg === '--tls-domain') {
      flags.tlsDomain = argv[i + 1] || '';
      i += 1;
      if (!flags.tlsDomain) {
        throw new Error('missing value for --tls-domain');
      }
    } else if (arg === '--dstack-verifier-url') {
      flags.dstackVerifierUrl = argv[i + 1] || '';
      i += 1;
      if (!flags.dstackVerifierUrl) {
        throw new Error('missing value for --dstack-verifier-url');
      }
    } else if (arg === '--pccs-url') {
      flags.pccsUrl = argv[i + 1] || '';
      i += 1;
      if (!flags.pccsUrl) {
        throw new Error('missing value for --pccs-url');
      }
    } else if (arg === '--verifier-bin') {
      flags.verifierBin = argv[i + 1] || '';
      i += 1;
      if (!flags.verifierBin) {
        throw new Error('missing value for --verifier-bin');
      }
    } else {
      positional.push(arg);
    }
  }
  if (positional.length < 1 || positional.length > 2) {
    usage();
    process.exit(2);
  }
  return {
    appBaseUrl: new URL(positional[0]),
    expectedMrtd: positional[1] ? normalizeHex(positional[1], 'expected MRTD') : null,
    ...flags,
  };
}

function verifierCommand(verifierBin) {
  if (verifierBin) {
    return { command: verifierBin, prefixArgs: [] };
  }

  const releaseBin = resolve(
    scriptDir(),
    'tdx_quote_verifier/target/release/tdx_quote_verifier'
  );
  const releaseProbe = spawnSync('test', ['-x', releaseBin]);
  if (releaseProbe.status === 0) {
    return { command: releaseBin, prefixArgs: [] };
  }

  const manifestPath = resolve(scriptDir(), 'tdx_quote_verifier/Cargo.toml');
  return {
    command: 'cargo',
    prefixArgs: ['run', '--release', '--quiet', '--manifest-path', manifestPath, '--'],
  };
}

function verifyQuoteLocally({ quote, reportData, expectedMrtd, pccsUrl, verifierBin }) {
  const { command, prefixArgs } = verifierCommand(verifierBin);
  const args = [
    ...prefixArgs,
    '--quote-hex',
    `0x${normalizeHex(quote, 'attestation.quote')}`,
    '--report-data-hex',
    `0x${reportData}`,
  ];
  if (expectedMrtd) {
    args.push('--expected-mrtd', `0x${expectedMrtd}`);
  }
  if (pccsUrl) {
    args.push('--pccs-url', pccsUrl);
  }

  const result = spawnSync(command, args, {
    cwd: repoRoot(),
    encoding: 'utf8',
    maxBuffer: 32 * 1024 * 1024,
  });
  if (result.status !== 0) {
    throw new Error((result.stderr || result.stdout || 'TDX quote verifier failed').trim());
  }
  return JSON.parse(result.stdout);
}

function sha256Hex(data) {
  return createHash('sha256').update(data).digest('hex');
}

function sha512Hex(data) {
  return createHash('sha512').update(data).digest('hex');
}

function attestedTlsReportPayload(domain, certificateSha256, challenge) {
  return `domain=${domain}\ncertificate_sha256=0x${certificateSha256}\nchallenge=0x${challenge}\n`;
}

function certificatePublicKeyPin(certificatePem) {
  const certificate = new X509Certificate(certificatePem);
  const spkiDer = certificate.publicKey.export({ type: 'spki', format: 'der' });
  return `sha256//${createHash('sha256').update(spkiDer).digest('base64')}`;
}

async function verifyAttestedTlsCertificate(opts, info) {
  const domain = (opts.tlsDomain || opts.appBaseUrl.hostname).toLowerCase();
  const challenge = randomBytes(32).toString('hex');
  const url = new URL('/attested_tls_cert', opts.appBaseUrl);
  url.searchParams.set('domain', domain);
  url.searchParams.set('challenge', `0x${challenge}`);

  const response = await fetchJson(url);
  const certificate = response.certificate;
  if (typeof certificate !== 'string' || !certificate.includes('BEGIN CERTIFICATE')) {
    throw new Error('/attested_tls_cert did not return a PEM certificate');
  }
  if (response.domain !== domain) {
    throw new Error(`attested TLS domain mismatch: expected ${domain}, got ${response.domain}`);
  }
  if (normalizeHex(response.challenge, 'attested TLS challenge') !== challenge) {
    throw new Error('attested TLS challenge mismatch');
  }

  const certificateSha256 = sha256Hex(certificate);
  const reportedCertificateSha256 = normalizeHex(
    response.certificate_sha256,
    'attested TLS certificate_sha256'
  );
  if (certificateSha256 !== reportedCertificateSha256) {
    throw new Error(
      `attested TLS certificate hash mismatch: calculated ${certificateSha256}, reported ${reportedCertificateSha256}`
    );
  }

  const reportData = sha512Hex(attestedTlsReportPayload(domain, certificateSha256, challenge));
  const reportedReportData = normalizeHex(response.report_data, 'attested TLS report_data');
  if (reportData !== reportedReportData) {
    throw new Error(
      `attested TLS report_data mismatch: calculated ${reportData}, reported ${reportedReportData}`
    );
  }

  const attestation = response.attestation;
  const localQuote = verifyQuoteLocally({
    quote: attestation?.quote,
    reportData,
    expectedMrtd: opts.expectedMrtd,
    pccsUrl: opts.pccsUrl,
    verifierBin: opts.verifierBin,
  });
  verifyRtmr3EventLog(attestation, localQuote);
  verifyComposeHash(info, attestation, opts.strictDigests);
  const pin = certificatePublicKeyPin(certificate);
  console.log('attested_tls_quote_verified=true');
  console.log(`attested_tls_domain=${domain}`);
  console.log(`attested_tls_certificate_sha256=0x${certificateSha256}`);
  console.log(`attested_tls_pin=${pin}`);
  return { pin, localQuote };
}

function eventDigest(event, imr) {
  const eventType = Number(event.event_type ?? event.eventType);
  if (Number(event.imr) === 3 && eventType === DSTACK_RUNTIME_EVENT_TYPE) {
    const eventTypeBytes = Buffer.alloc(4);
    eventTypeBytes.writeUInt32LE(eventType);
    const payload = Buffer.from(
      normalizeHex(event.event_payload ?? event.eventPayload ?? '', `event payload for imr${imr}`),
      'hex'
    );
    const eventName = Buffer.from(event.event ?? '', 'utf8');
    return createHash('sha384')
      .update(Buffer.concat([eventTypeBytes, Buffer.from(':'), eventName, Buffer.from(':'), payload]))
      .digest();
  }

  return Buffer.from(normalizeHex(event.digest, `event digest for imr${imr}`), 'hex');
}

function replayRtmr(events, imr) {
  let mr = Buffer.alloc(48, 0);
  for (const event of events) {
    if (Number(event.imr) !== imr) {
      continue;
    }
    const digest = eventDigest(event, imr);
    if (digest.length > 48) {
      throw new Error(`event digest for imr${imr} is longer than 48 bytes`);
    }
    const padded = Buffer.alloc(48, 0);
    digest.copy(padded);
    mr = createHash('sha384').update(Buffer.concat([mr, padded])).digest();
  }
  return `0x${mr.toString('hex')}`;
}

function verifyRtmr3EventLog(attestation, localQuote) {
  const events = eventLogEvents(attestation.event_log ?? attestation.eventLog);
  if (events.length === 0) {
    console.warn('warning: event_log unavailable, skipping local RTMR3 replay');
    return;
  }
  const replayed = replayRtmr(events, 3);
  if (replayed !== localQuote.rtmr3) {
    throw new Error(`RTMR3 replay mismatch: replayed ${replayed}, quote ${localQuote.rtmr3}`);
  }
  console.log(`rtmr3_replay=${replayed}`);
}

function verifyComposeHash(info, attestation, strictDigests) {
  const appCompose = extractAppCompose(info);
  const events = eventLogEvents(attestation.event_log ?? attestation.eventLog);
  const composeEvent = events.find((event) => event.event === 'compose-hash');

  if (appCompose && composeEvent?.event_payload) {
    const appComposeBytes = typeof appCompose === 'string' ? appCompose : JSON.stringify(appCompose);
    const calculatedComposeHash = createHash('sha256').update(appComposeBytes).digest('hex');
    const attestedComposeHash = normalizeHex(composeEvent.event_payload, 'compose-hash event');
    if (calculatedComposeHash !== attestedComposeHash) {
      throw new Error(
        `compose-hash mismatch: calculated ${calculatedComposeHash}, attested ${attestedComposeHash}`
      );
    }
    console.log(`compose_hash=0x${calculatedComposeHash}`);
  } else {
    console.warn('warning: compose-hash check skipped because app_compose or event_log was unavailable');
  }

  const unpinnedImages = checkPinnedImages(dockerComposeFromAppCompose(appCompose));
  if (unpinnedImages.length > 0) {
    const message = `unpinned image references found: ${unpinnedImages.join(', ')}`;
    if (strictDigests) {
      throw new Error(message);
    }
    console.warn(`warning: ${message}`);
  }
}

async function verifyWithLocalDstackVerifier(verifierUrl, attestation, required) {
  if (!verifierUrl) {
    return;
  }
  try {
    const result = await fetchJson(new URL('/verify', verifierUrl), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(attestation),
    });
    if (result.is_valid !== true && result.success !== true) {
      throw new Error(JSON.stringify(result));
    }
    console.log('dstack_verifier=valid');
  } catch (err) {
    if (required) {
      throw err;
    }
    console.warn(`warning: local dstack-verifier check skipped/failed: ${err.message}`);
  }
}

async function compareWithPhalaApi(quote) {
  const verifyApi = process.env.PHALA_ATTESTATION_VERIFY_API || DEFAULT_PHALA_VERIFY_API;
  const verification = await fetchJson(verifyApi, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ hex: normalizeHex(quote, 'attestation.quote') }),
  });
  if (verification?.quote?.verified !== true) {
    throw new Error('Phala API comparison failed');
  }
  console.log(`phala_api_checksum=${verification.checksum ?? ''}`);
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  let reportData;
  if (process.env.REPORT_DATA_HEX) {
    reportData = normalizeHex(process.env.REPORT_DATA_HEX, 'REPORT_DATA_HEX');
  } else if (opts.simulatorFixture) {
    reportData = '0'.repeat(128);
  } else {
    reportData = randomBytes(32).toString('hex');
  }

  if (opts.simulatorFixture && !process.env.REPORT_DATA_HEX) {
    console.warn(
      'warning: using dstack simulator zero-report-data fixture; this verifies the fixture locally but is not a fresh challenge'
    );
  }

  if (reportData.length > 128) {
    throw new Error('REPORT_DATA_HEX must be at most 64 bytes');
  }

  const attestationUrl = new URL('/attestation', opts.appBaseUrl);
  attestationUrl.searchParams.set('report_data', `0x${reportData}`);
  const attestation = await fetchJson(attestationUrl);

  const localQuote = verifyQuoteLocally({
    quote: attestation.quote,
    reportData,
    expectedMrtd: opts.expectedMrtd,
    pccsUrl: opts.pccsUrl,
    verifierBin: opts.verifierBin,
  });
  verifyRtmr3EventLog(attestation, localQuote);

  let info = null;
  try {
    info = await fetchJson(new URL('/info', opts.appBaseUrl));
  } catch (err) {
    console.warn(`warning: /info unavailable, skipping compose checks: ${err.message}`);
  }
  verifyComposeHash(info, attestation, opts.strictDigests);

  if (opts.attestedTls) {
    await verifyAttestedTlsCertificate(opts, info);
  }

  await verifyWithLocalDstackVerifier(
    opts.dstackVerifierUrl,
    attestation,
    opts.requireDstackVerifier
  );

  if (opts.phalaApi) {
    await compareWithPhalaApi(attestation.quote);
  }

  console.log('local_quote_verified=true');
  console.log(`tee_type=${localQuote.tee_type}`);
  console.log(`mrtd=${localQuote.mrtd}`);
  console.log(`rtmr0=${localQuote.rtmr0}`);
  console.log(`rtmr1=${localQuote.rtmr1}`);
  console.log(`rtmr2=${localQuote.rtmr2}`);
  console.log(`rtmr3=${localQuote.rtmr3}`);
}

main().catch((err) => {
  console.error(`verification failed: ${err.message}`);
  process.exit(1);
});
