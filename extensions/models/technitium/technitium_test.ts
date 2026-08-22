/**
 * Unit tests for the pure logic and method wiring of `@thomas/technitium`. These
 * cover the bits where a silent bug would be costly: the `{status,response}`
 * envelope unwrap (and its error-throwing), the comma-join + 255-char guard for
 * list URLs, the record rData → query-param mapping (incl. the `new*` prefixing
 * for updates), the multipart body builder, and the factory instance-name
 * uniqueness. Method tests drive `execute` against scripted responses via the
 * `__setTechnitiumTransport` seam and a minimal fake context. No network I/O.
 */
import {
  __setTechnitiumTransport,
  buildMultipart,
  coerceArray,
  joinListUrls,
  model,
  namesFrom,
  prefixNew,
  recordInstanceName,
  slug,
  unwrapEnvelope,
} from "./technitium.ts";

function assertEquals(actual: unknown, expected: unknown, msg?: string): void {
  const a = JSON.stringify(actual);
  const e = JSON.stringify(expected);
  if (a !== e) {
    throw new Error(
      `assertEquals failed${
        msg ? ` (${msg})` : ""
      }\n  actual:   ${a}\n  expected: ${e}`,
    );
  }
}
function assert(cond: unknown, msg?: string): void {
  if (!cond) throw new Error(`assert failed${msg ? `: ${msg}` : ""}`);
}
function assertThrows(fn: () => unknown, includes?: string): void {
  let threw = false;
  try {
    fn();
  } catch (e) {
    threw = true;
    if (includes && !(e instanceof Error && e.message.includes(includes))) {
      throw new Error(`expected error including "${includes}", got: ${e}`);
    }
  }
  if (!threw) throw new Error("expected function to throw");
}
async function assertRejects(
  fn: () => Promise<unknown>,
  includes?: string,
): Promise<void> {
  let threw = false;
  try {
    await fn();
  } catch (e) {
    threw = true;
    if (includes && !(e instanceof Error && e.message.includes(includes))) {
      throw new Error(`expected error including "${includes}", got: ${e}`);
    }
  }
  if (!threw) throw new Error("expected promise to reject");
}

// ----- pure helpers --------------------------------------------------------

Deno.test("unwrapEnvelope returns the response on status ok", () => {
  assertEquals(
    unwrapEnvelope({ status: "ok", response: { zones: [1] } }, "ctx"),
    { zones: [1] },
  );
  // ok with no response object degrades to {}
  assertEquals(unwrapEnvelope({ status: "ok" }, "ctx"), {});
  // an envelope-less object is treated as having no response
  assertEquals(unwrapEnvelope({ foo: 1 }, "ctx"), {});
});

Deno.test("unwrapEnvelope throws on error / invalid-token, surfacing errorMessage", () => {
  assertThrows(
    () => unwrapEnvelope({ status: "error", errorMessage: "boom" }, "GET /x"),
    "boom",
  );
  assertThrows(
    () => unwrapEnvelope({ status: "invalid-token" }, "GET /x"),
    "invalid-token",
  );
});

Deno.test("coerceArray pulls the array out from any of the given keys", () => {
  assertEquals(coerceArray({ zones: [{ a: 1 }] }, "zones"), [{ a: 1 }]);
  assertEquals(coerceArray({ records: [{ a: 1 }] }, "zones", "records"), [{
    a: 1,
  }]);
  assertEquals(coerceArray({ nope: 1 }, "zones"), []);
});

Deno.test("namesFrom collects distinct names from string and object entries across keys", () => {
  assertEquals(
    namesFrom(
      { zones: ["a.com", { name: "b.com" }], records: [{ domain: "c.com" }] },
      "zones",
      "records",
    ),
    ["a.com", "b.com", "c.com"],
  );
  // a domain appearing in both arrays is deduped (it's used as a unique key)
  assertEquals(
    namesFrom(
      { zones: ["sentry.io"], records: [{ name: "sentry.io" }] },
      "zones",
      "records",
    ),
    ["sentry.io"],
  );
  assertEquals(namesFrom({ zones: "notarray" }, "zones"), []);
});

Deno.test("joinListUrls comma-joins and flags entries over 255 chars", () => {
  assertEquals(
    joinListUrls(["http://a", "http://b"]).joined,
    "http://a,http://b",
  );
  const long = "http://x/" + "a".repeat(300);
  const r = joinListUrls(["http://ok", long]);
  assertEquals(r.tooLong, [long]);
  assertEquals(r.joined.split(",").length, 2);
});

Deno.test("prefixNew maps rData keys to Technitium new* params", () => {
  assertEquals(prefixNew({ ipAddress: "1.2.3.4", ttl: 300 }), {
    newIpAddress: "1.2.3.4",
    newTtl: 300,
  });
  assertEquals(prefixNew({ cname: "x.com" }), { newCname: "x.com" });
});

Deno.test("slug flattens dotted domains into a safe instance-name fragment", () => {
  assertEquals(slug("foo.example.com"), "foo-example-com");
  assertEquals(slug("_dmarc.example.com"), "_dmarc-example-com");
  assertEquals(slug(""), "root");
  // wildcard label must NOT collapse onto its bare form
  assertEquals(slug("*.s3.example.com"), "star-s3-example-com");
  assert(slug("*.s3.example.com") !== slug("s3.example.com"));
});

Deno.test("recordInstanceName is identity-stable, case-normalized, and collision-free per record", () => {
  // deterministic: same record → same name no matter which method produced it
  assertEquals(
    recordInstanceName("ex.com", "nas.ex.com", "A", { ipAddress: "10.0.0.5" }),
    recordInstanceName("ex.com", "nas.ex.com", "A", { ipAddress: "10.0.0.5" }),
  );
  // DNS is case-insensitive: name case and type case don't fork the identity
  assertEquals(
    recordInstanceName("ex.com", "NAS.ex.com", "app", {
      appName: "S",
      classPath: "S.A",
      data: "{}",
    }),
    recordInstanceName("ex.com", "nas.ex.com", "APP", {
      appName: "S",
      classPath: "S.A",
      data: "{}",
    }),
  );
  // two A records at one name stay distinct — no positional index to collide on
  assert(
    recordInstanceName("ex.com", "nas.ex.com", "A", {
      ipAddress: "10.0.0.5",
    }) !==
      recordInstanceName("ex.com", "nas.ex.com", "A", {
        ipAddress: "10.0.0.6",
      }),
    "distinct rData must yield distinct instance names",
  );
  // shape: rec-<zone>-<name>-<TYPE>-<hash>
  assert(
    /^rec-ex-com-nas-ex-com-A-[0-9a-z]+$/.test(
      recordInstanceName("ex.com", "nas.ex.com", "A", {
        ipAddress: "10.0.0.5",
      }),
    ),
    "unexpected instance-name shape",
  );
  // a wildcard record and its bare sibling — identical rData — stay distinct
  // (the bug that aborted record_list on a zone holding both s3 + *.s3)
  const appData = { appName: "Split Horizon", classPath: "S.A", data: "{}" };
  assert(
    recordInstanceName("ex.com", "*.s3.ex.com", "APP", appData) !==
      recordInstanceName("ex.com", "s3.ex.com", "APP", appData),
    "wildcard and bare record must yield distinct instance names",
  );
});

Deno.test("buildMultipart frames a single file part with the boundary", () => {
  const bytes = new Uint8Array([1, 2, 3]);
  const { body, contentType, boundary } = buildMultipart(
    "fileToUpload",
    "b.zip",
    bytes,
  );
  assert(contentType.includes(boundary), "content-type carries the boundary");
  const text = new TextDecoder().decode(body);
  assert(
    text.includes(`name="fileToUpload"; filename="b.zip"`),
    "part header present",
  );
  assert(text.includes(`--${boundary}--`), "closing boundary present");
  // the raw file bytes are embedded between the headers and the trailer
  assert(body.includes(2), "file bytes embedded");
});

// ----- method wiring (transport seam + fake context) -----------------------

type Call = { method: string; path: string; params?: Record<string, unknown> };
type WriteCall = {
  specName: string;
  name: string;
  data: Record<string, unknown>;
};

const TEST_GLOBALS = {
  baseUrl: "https://dns.test:5380",
  apiToken: "test-token",
  skipTlsVerify: false,
};

function makeContext() {
  const written: WriteCall[] = [];
  const seen = new Set<string>();
  const noop = (_m: string, _p?: unknown): void => {};
  const context = {
    globalArgs: TEST_GLOBALS,
    logger: { info: noop, debug: noop, warning: noop, error: noop },
    writeResource: (
      specName: string,
      name: string,
      data: Record<string, unknown>,
    ): Promise<WriteCall> => {
      if (seen.has(name)) {
        return Promise.reject(
          new Error(`Duplicate data instance name '${name}'`),
        );
      }
      seen.add(name);
      const h = { specName, name, data };
      written.push(h);
      return Promise.resolve(h);
    },
  };
  return { context, written };
}

type MethodDef = {
  execute: (
    args: unknown,
    context: unknown,
  ) => Promise<{ dataHandles: unknown[] }>;
};
function method(name: string): MethodDef {
  return (model.methods as unknown as Record<string, MethodDef>)[name];
}

function scriptTransport(
  calls: Call[],
  responder: (c: Call) => Record<string, unknown>,
): void {
  __setTechnitiumTransport(
    (_g, m, p, params): Promise<Record<string, unknown>> => {
      const call: Call = { method: m, path: p, params };
      calls.push(call);
      return Promise.resolve(responder(call));
    },
  );
}

/**
 * Responder for write tests: the read-back GET (`/zones/records/get`) returns
 * `records`; every other call (the mutation POST) returns an empty envelope.
 * Lets a test stage the live state that post-write verification reads back.
 */
function recordsResponder(
  records: Record<string, unknown>[],
): (c: Call) => Record<string, unknown> {
  return (c) => c.path.endsWith("/zones/records/get") ? { records } : {};
}

Deno.test("blocking_set_state posts only enableBlocking and emits settings", async () => {
  const calls: Call[] = [];
  scriptTransport(calls, () => ({
    enableBlocking: true,
    blockListUrls: ["http://a"],
    allowListUrls: [],
  }));
  try {
    const { context, written } = makeContext();
    await method("blocking_set_state").execute({ enable: true }, context);
    assertEquals(calls[0].method, "POST");
    assertEquals(calls[0].path, "/settings/set");
    assertEquals(calls[0].params, { enableBlocking: true });
    assertEquals(written[0].specName, "settings");
    assertEquals(written[0].data.enableBlocking, true);
    assertEquals(written[0].data.blockListUrls, ["http://a"]);
  } finally {
    __setTechnitiumTransport(null);
  }
});

Deno.test("blocking_set_lists comma-joins only the lists provided", async () => {
  const calls: Call[] = [];
  scriptTransport(calls, () => ({}));
  try {
    const { context } = makeContext();
    await method("blocking_set_lists").execute(
      { blockListUrls: ["http://a", "http://b"] },
      context,
    );
    assertEquals(calls[0].params, { blockListUrls: "http://a,http://b" });
    assert(
      !("allowListUrls" in (calls[0].params ?? {})),
      "allowListUrls not sent when omitted",
    );
  } finally {
    __setTechnitiumTransport(null);
  }
});

Deno.test("blocking_temporary_disable records the till timestamp", async () => {
  const calls: Call[] = [];
  scriptTransport(
    calls,
    () => ({ temporaryDisableBlockingTill: "2026-05-23T10:00:00Z" }),
  );
  try {
    const { context, written } = makeContext();
    await method("blocking_temporary_disable").execute(
      { minutes: 30 },
      context,
    );
    assertEquals(calls[0].path, "/settings/temporaryDisableBlocking");
    assertEquals(calls[0].params, { minutes: 30 });
    assertEquals(written[0].specName, "operationResult");
    assert(
      String(written[0].data.detail).includes("2026-05-23T10:00:00Z"),
      "till surfaced in detail",
    );
  } finally {
    __setTechnitiumTransport(null);
  }
});

Deno.test("web_service_set_tls maps args to webService* params and emits settings", async () => {
  const calls: Call[] = [];
  scriptTransport(calls, () => ({
    webServiceEnableTls: true,
    webServiceTlsPort: 53443,
    webServiceUseSelfSignedTlsCertificate: false,
    webServiceTlsCertificatePath: "wildcard.example.com.pfx",
    webServiceHttpToTlsRedirect: false,
  }));
  try {
    const { context, written } = makeContext();
    await method("web_service_set_tls").execute({
      certificatePath: "wildcard.example.com.pfx",
      certificatePassword: "s3cret",
      useSelfSignedCertificate: false,
    }, context);
    assertEquals(calls[0].method, "POST");
    assertEquals(calls[0].path, "/settings/set");
    assertEquals(calls[0].params, {
      webServiceTlsCertificatePath: "wildcard.example.com.pfx",
      webServiceTlsCertificatePassword: "s3cret",
      webServiceUseSelfSignedTlsCertificate: false,
    });
    assertEquals(written[0].specName, "settings");
    assertEquals(written[0].data.webServiceUseSelfSignedTlsCertificate, false);
    assertEquals(written[0].data.webServiceTlsCertificatePath, "wildcard.example.com.pfx");
  } finally {
    __setTechnitiumTransport(null);
  }
});

Deno.test("web_service_set_tls sends only the fields provided (redirect-only)", async () => {
  const calls: Call[] = [];
  scriptTransport(calls, () => ({ webServiceHttpToTlsRedirect: true }));
  try {
    const { context } = makeContext();
    await method("web_service_set_tls").execute(
      { httpToTlsRedirect: true },
      context,
    );
    assertEquals(calls[0].params, { webServiceHttpToTlsRedirect: true });
  } finally {
    __setTechnitiumTransport(null);
  }
});

Deno.test("web_service_set_tls throws when no fields are provided", async () => {
  const calls: Call[] = [];
  scriptTransport(calls, () => ({}));
  try {
    const { context } = makeContext();
    let threw = false;
    try {
      await method("web_service_set_tls").execute({}, context);
    } catch (_e) {
      threw = true;
    }
    assert(threw, "expected an error when no TLS fields provided");
    assertEquals(calls.length, 0, "no API call should be made");
  } finally {
    __setTechnitiumTransport(null);
  }
});

Deno.test("dnssec_validation_set posts only dnssecValidation and emits settings", async () => {
  const calls: Call[] = [];
  scriptTransport(calls, () => ({ dnssecValidation: true }));
  try {
    const { context, written } = makeContext();
    await method("dnssec_validation_set").execute({ enable: true }, context);
    assertEquals(calls[0].method, "POST");
    assertEquals(calls[0].path, "/settings/set");
    assertEquals(calls[0].params, { dnssecValidation: true });
    assertEquals(written[0].specName, "settings");
    assertEquals(written[0].data.dnssecValidation, true);
  } finally {
    __setTechnitiumTransport(null);
  }
});

Deno.test("zone_create posts zone+type and writes a created zone", async () => {
  const calls: Call[] = [];
  scriptTransport(calls, () => ({}));
  try {
    const { context, written } = makeContext();
    await method("zone_create").execute({
      zone: "lab.example.com",
      type: "Primary",
    }, context);
    assertEquals(calls[0].path, "/zones/create");
    assertEquals(calls[0].params, { zone: "lab.example.com", type: "Primary" });
    assertEquals(written[0].name, "zone-lab-example-com");
    assertEquals(written[0].data.action, "created");
  } finally {
    __setTechnitiumTransport(null);
  }
});

Deno.test("zone_list is a factory with unique slugged instance names", async () => {
  const calls: Call[] = [];
  scriptTransport(calls, () => ({
    zones: [{ name: "a.com", type: "Primary" }, {
      name: "b.com",
      disabled: true,
    }],
  }));
  try {
    const { context, written } = makeContext();
    const out = await method("zone_list").execute({}, context);
    assertEquals(out.dataHandles.length, 2);
    assertEquals(written.map((w) => w.name), ["zone-a-com", "zone-b-com"]);
    assertEquals(written[1].data.disabled, true);
  } finally {
    __setTechnitiumTransport(null);
  }
});

Deno.test("record_add spreads rData into flat query params", async () => {
  const calls: Call[] = [];
  scriptTransport(
    calls,
    recordsResponder([{ type: "A", rData: { ipAddress: "1.2.3.4" } }]),
  );
  try {
    const { context } = makeContext();
    await method("record_add").execute(
      {
        zone: "example.com",
        domain: "www.example.com",
        type: "A",
        ttl: 300,
        rData: { ipAddress: "1.2.3.4" },
      },
      context,
    );
    assertEquals(calls[0].path, "/zones/records/add");
    assertEquals(calls[0].params, {
      domain: "www.example.com",
      type: "A",
      zone: "example.com",
      ttl: 300,
      ipAddress: "1.2.3.4",
    });
    // a read-back GET follows the mutating POST
    assertEquals(calls[1].path, "/zones/records/get");
  } finally {
    __setTechnitiumTransport(null);
  }
});

Deno.test("record_update maps newRData to new* params and keeps identifying rData", async () => {
  const calls: Call[] = [];
  scriptTransport(
    calls,
    recordsResponder([{ type: "A", rData: { ipAddress: "2.2.2.2" } }]),
  );
  try {
    const { context } = makeContext();
    await method("record_update").execute(
      {
        zone: "example.com",
        domain: "www.example.com",
        type: "A",
        rData: { ipAddress: "1.1.1.1" },
        newRData: { ipAddress: "2.2.2.2" },
      },
      context,
    );
    assertEquals(calls[0].params, {
      domain: "www.example.com",
      type: "A",
      zone: "example.com",
      ipAddress: "1.1.1.1",
      newIpAddress: "2.2.2.2",
    });
  } finally {
    __setTechnitiumTransport(null);
  }
});

Deno.test("record_add maps APP rData to appName/classPath/recordData (not raw data)", async () => {
  const calls: Call[] = [];
  scriptTransport(
    calls,
    recordsResponder([{
      type: "APP",
      rData: {
        appName: "SplitHorizon",
        classPath: "SplitHorizon.SimpleAddress",
        data: '{"local":["A"],"tailscale":["B"]}',
      },
    }]),
  );
  try {
    const { context } = makeContext();
    await method("record_add").execute(
      {
        zone: "zone",
        domain: "x.zone",
        type: "APP",
        // `data` is the key record_list reads APP content back under
        rData: {
          appName: "SplitHorizon",
          classPath: "SplitHorizon.SimpleAddress",
          data: '{"local":["A"],"tailscale":["B"]}',
        },
      },
      context,
    );
    assertEquals(calls[0].path, "/zones/records/add");
    assertEquals(calls[0].params, {
      domain: "x.zone",
      type: "APP",
      zone: "zone",
      appName: "SplitHorizon",
      classPath: "SplitHorizon.SimpleAddress",
      recordData: '{"local":["A"],"tailscale":["B"]}',
    });
    // the bug: a raw `data` param would be ignored by Technitium → empty record
    assert(!("data" in (calls[0].params ?? {})), "no raw `data` param sent");
  } finally {
    __setTechnitiumTransport(null);
  }
});

Deno.test("record_update writes APP content via recordData with no new* params", async () => {
  const calls: Call[] = [];
  scriptTransport(
    calls,
    recordsResponder([{
      type: "APP",
      rData: {
        appName: "SplitHorizon",
        classPath: "SplitHorizon.SimpleAddress",
        data: '{"local":["C"]}',
      },
    }]),
  );
  try {
    const { context } = makeContext();
    await method("record_update").execute(
      {
        zone: "zone",
        domain: "x.zone",
        type: "APP",
        rData: {
          appName: "SplitHorizon",
          classPath: "SplitHorizon.SimpleAddress",
          data: "{}",
        },
        newRData: {
          appName: "SplitHorizon",
          classPath: "SplitHorizon.SimpleAddress",
          data: '{"local":["C"]}',
        },
      },
      context,
    );
    assertEquals(calls[0].path, "/zones/records/update");
    assertEquals(calls[0].params, {
      domain: "x.zone",
      type: "APP",
      zone: "zone",
      appName: "SplitHorizon",
      classPath: "SplitHorizon.SimpleAddress",
      recordData: '{"local":["C"]}',
    });
    // the bug: prefixNew would emit `newData`, which Technitium ignores → empty
    const p = calls[0].params ?? {};
    assert(!("newData" in p), "no newData param");
    assert(!("data" in p), "no raw `data` param");
    assert(!("newRData" in p), "no newRData param");
  } finally {
    __setTechnitiumTransport(null);
  }
});

Deno.test("record_get reads one domain live (listZone false) and writes a zoneRecord each", async () => {
  const calls: Call[] = [];
  scriptTransport(calls, () => ({
    records: [
      { name: "x.zone", type: "A", ttl: 300, rData: { ipAddress: "1.2.3.4" } },
      {
        name: "x.zone",
        type: "APP",
        rData: {
          appName: "SplitHorizon",
          classPath: "SplitHorizon.SimpleAddress",
          data: '{"local":["A"]}',
        },
      },
    ],
  }));
  try {
    const { context, written } = makeContext();
    const out = await method("record_get").execute(
      { zone: "zone", domain: "x.zone" },
      context,
    );
    assertEquals(calls[0].path, "/zones/records/get");
    assertEquals(calls[0].params, {
      domain: "x.zone",
      listZone: false,
      zone: "zone",
    });
    assertEquals(out.dataHandles.length, 2);
    // deterministic identity-based names (shared with the mutators), live rData verbatim
    assertEquals(written.map((w) => w.name), [
      recordInstanceName("zone", "x.zone", "A", { ipAddress: "1.2.3.4" }),
      recordInstanceName("zone", "x.zone", "APP", {
        appName: "SplitHorizon",
        classPath: "SplitHorizon.SimpleAddress",
        data: '{"local":["A"]}',
      }),
    ]);
    assertEquals(written[0].data.rData, { ipAddress: "1.2.3.4" });
    assertEquals(written[1].data.action, "observed");
  } finally {
    __setTechnitiumTransport(null);
  }
});

Deno.test("record_add and record_get address the same instance for one record (no duplicate)", async () => {
  const calls: Call[] = [];
  scriptTransport(
    calls,
    recordsResponder([{
      name: "www.example.com",
      type: "A",
      rData: { ipAddress: "1.2.3.4" },
    }]),
  );
  try {
    const { context: addCtx, written: addWritten } = makeContext();
    await method("record_add").execute(
      {
        zone: "example.com",
        domain: "www.example.com",
        type: "A",
        rData: { ipAddress: "1.2.3.4" },
      },
      addCtx,
    );
    const { context: getCtx, written: getWritten } = makeContext();
    await method("record_get").execute(
      { zone: "example.com", domain: "www.example.com" },
      getCtx,
    );
    // the whole point of identity-based naming: one record → one instance name,
    // whether it was added or later read back
    assertEquals(addWritten[0].name, getWritten[0].name);
  } finally {
    __setTechnitiumTransport(null);
  }
});

Deno.test("record_update throws when read-back shows empty APP data (SERVFAIL landmine)", async () => {
  const calls: Call[] = [];
  // Technitium accepts the POST but the live APP record has empty data — the
  // exact silent-corruption that took the zone down. Verification must catch it.
  scriptTransport(
    calls,
    recordsResponder([{
      type: "APP",
      rData: {
        appName: "SplitHorizon",
        classPath: "SplitHorizon.SimpleAddress",
        data: "",
      },
    }]),
  );
  try {
    const { context, written } = makeContext();
    await assertRejects(
      () =>
        method("record_update").execute(
          {
            zone: "zone",
            domain: "x.zone",
            type: "APP",
            newRData: {
              appName: "SplitHorizon",
              classPath: "SplitHorizon.SimpleAddress",
              data: '{"local":["C"]}',
            },
          },
          context,
        ),
      "read-back failed",
    );
    // a false success must NOT be recorded
    assertEquals(written.length, 0);
  } finally {
    __setTechnitiumTransport(null);
  }
});

Deno.test("record_delete throws when read-back shows the record still present", async () => {
  const calls: Call[] = [];
  scriptTransport(
    calls,
    recordsResponder([{ type: "A", rData: { ipAddress: "1.2.3.4" } }]),
  );
  try {
    const { context, written } = makeContext();
    await assertRejects(
      () =>
        method("record_delete").execute(
          {
            zone: "example.com",
            domain: "www.example.com",
            type: "A",
            rData: { ipAddress: "1.2.3.4" },
          },
          context,
        ),
      "still",
    );
    assertEquals(written.length, 0);
  } finally {
    __setTechnitiumTransport(null);
  }
});

Deno.test("allowed_list factory writes one listEntry per domain", async () => {
  const calls: Call[] = [];
  scriptTransport(
    calls,
    () => ({ zones: ["ads.example.com", "track.example.com"] }),
  );
  try {
    const { context, written } = makeContext();
    await method("allowed_list").execute({}, context);
    assertEquals(written.map((w) => w.specName), ["listEntry", "listEntry"]);
    assertEquals(written.map((w) => w.name), [
      "allowed-ads-example-com",
      "allowed-track-example-com",
    ]);
    assertEquals(written[0].data.list, "allowed");
  } finally {
    __setTechnitiumTransport(null);
  }
});
