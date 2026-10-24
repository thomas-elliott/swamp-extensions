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
  buildRequest,
  checkListUrls,
  coerceArray,
  dataName,
  dnsKey,
  joinListUrls,
  model,
  namesFrom,
  prefixNew,
  recordInstanceName,
  requestTarget,
  SETTINGS_SECTIONS,
  settingsSectionFlags,
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
});

Deno.test("unwrapEnvelope refuses a reply that is not a Technitium response", () => {
  // e.g. a proxy's login page served with 200: HTML, or JSON without status
  assertThrows(
    () => unwrapEnvelope("<html>login</html>", "GET /x"),
    "not a Technitium",
  );
  assertThrows(() => unwrapEnvelope({ foo: 1 }, "GET /x"), "not a Technitium");
  assertThrows(() => unwrapEnvelope(null, "GET /x"), "not a Technitium");
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

Deno.test("dataName prefixes the spec, so two specs sharing a key differ", () => {
  assertEquals(dataName("settings"), "settings");
  assertEquals(dataName("zone", "example.com"), "zone:example.com");
  assert(
    dataName("zone", "example.com") !== dataName("cacheEntry", "example.com"),
  );
});

Deno.test("dnsKey keeps dots, so a-b and a.b do not collide", () => {
  assertEquals(dnsKey("Foo.Example.com."), "foo.example.com");
  assert(dnsKey("a-b.example.com") !== dnsKey("a.b.example.com"));
  assert(dnsKey("*.s3.example.com") !== dnsKey("s3.example.com"));
  // characters swamp rejects, or that would blur the ':' separators, are escaped
  assertEquals(
    dnsKey("0/26.2.0.192.in-addr.arpa"),
    "0%2F26.2.0.192.in-addr.arpa",
  );
  assertEquals(dnsKey("a:b\\c%d"), "a%3Ab%5Cc%25d");
});

Deno.test("recordInstanceName is identity-stable, case-normalized, and distinct per record", () => {
  // deterministic: same record → same name no matter which method produced it
  assertEquals(
    recordInstanceName("ex.com", "nas.ex.com", "A", { ipAddress: "10.0.0.5" }),
    recordInstanceName("ex.com", "nas.ex.com", "A", { ipAddress: "10.0.0.5" }),
  );
  // DNS is case-insensitive: name case and type case don't change the instance name
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
  // two A records at one name stay distinct; names use no positional index
  assert(
    recordInstanceName("ex.com", "nas.ex.com", "A", {
      ipAddress: "10.0.0.5",
    }) !==
      recordInstanceName("ex.com", "nas.ex.com", "A", {
        ipAddress: "10.0.0.6",
      }),
    "distinct rData must yield distinct instance names",
  );
  // shape: zoneRecord:<zone>:<name>:<TYPE>:<hash>
  assert(
    /^zoneRecord:ex\.com:nas\.ex\.com:A:[0-9a-z]+$/.test(
      recordInstanceName("ex.com", "nas.ex.com", "A", {
        ipAddress: "10.0.0.5",
      }),
    ),
    "unexpected instance-name shape",
  );
  // a wildcard record and its bare name, with identical rData, stay distinct
  // (the bug that aborted record_list on a zone holding both s3 + *.s3)
  const appData = { appName: "Split Horizon", classPath: "S.A", data: "{}" };
  assert(
    recordInstanceName("ex.com", "*.s3.ex.com", "APP", appData) !==
      recordInstanceName("ex.com", "s3.ex.com", "APP", appData),
    "wildcard and bare record must yield distinct instance names",
  );
  // a-b and a.b with identical rData stay distinct (slug used to map both to a-b)
  assert(
    recordInstanceName("ex.com", "a-b.ex.com", "A", {
      ipAddress: "1.2.3.4",
    }) !==
      recordInstanceName("ex.com", "a.b.ex.com", "A", { ipAddress: "1.2.3.4" }),
  );
  // rData values keep their case: TXT data is case-sensitive
  assert(
    recordInstanceName("ex.com", "t.ex.com", "TXT", { text: "Hello" }) !==
      recordInstanceName("ex.com", "t.ex.com", "TXT", { text: "hello" }),
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

type LogCall = {
  level: string;
  message: string;
  props: Record<string, unknown>;
};

function makeContext() {
  const written: WriteCall[] = [];
  const logs: LogCall[] = [];
  const seen = new Set<string>();
  const log =
    (level: string) =>
    (message: string, props?: Record<string, unknown>): void => {
      logs.push({ level, message, props: props ?? {} });
    };
  const context = {
    globalArgs: TEST_GLOBALS,
    logger: {
      info: log("info"),
      debug: log("debug"),
      warn: log("warn"),
      error: log("error"),
    },
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
  return { context, written, logs };
}

type MethodDef = {
  execute: (
    args: unknown,
    context: unknown,
  ) => Promise<{ dataHandles: unknown[] }>;
};
// Arguments go through the method's schema first, as swamp does, so defaults
// apply and the schema itself is tested.
function method(name: string): MethodDef {
  const m = (model.methods as unknown as Record<
    string,
    MethodDef & { arguments: { parse: (v: unknown) => unknown } }
  >)[name];
  return {
    execute: (args, context) => m.execute(m.arguments.parse(args), context),
  };
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

// Technitium has no allow-list setting: allow lists are `!`-prefixed entries
// in blockListUrls. Changing one side must keep the other.
Deno.test("blocking_set_lists replaces only the list provided, in the one setting", async () => {
  const calls: Call[] = [];
  scriptTransport(
    calls,
    (c) =>
      c.path === "/settings/get"
        ? { blockListUrls: ["http://old", "!http://allow"] }
        : { blockListUrls: ["http://a", "http://b", "!http://allow"] },
  );
  try {
    const { context, written } = makeContext();
    await method("blocking_set_lists").execute(
      { blockListUrls: ["http://a", "http://b"] },
      context,
    );
    assertEquals(calls[1].params, {
      blockListUrls: "http://a,http://b,!http://allow",
    });
    assertEquals(written[0].data.blockListUrls, ["http://a", "http://b"]);
    assertEquals(written[0].data.allowListUrls, ["http://allow"]);
  } finally {
    __setTechnitiumTransport(null);
  }
});

Deno.test("blocking_set_lists clears with false when both lists end up empty", async () => {
  const calls: Call[] = [];
  scriptTransport(calls, () => ({ blockListUrls: ["http://old"] }));
  try {
    const { context } = makeContext();
    await method("blocking_set_lists").execute({ blockListUrls: [] }, context);
    assertEquals(calls[1].params, { blockListUrls: "false" });
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
    assertEquals(
      written[0].data.webServiceTlsCertificatePath,
      "wildcard.example.com.pfx",
    );
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
    assertEquals(written[0].name, "zone:lab.example.com");
    assertEquals(written[0].data.action, "created");
  } finally {
    __setTechnitiumTransport(null);
  }
});

Deno.test("zone_create joins a catalog zone when catalog is given", async () => {
  const calls: Call[] = [];
  scriptTransport(calls, () => ({}));
  try {
    const { context, written } = makeContext();
    await method("zone_create").execute({
      zone: "2.0.192.in-addr.arpa",
      type: "Primary",
      catalog: "catalog.example.com",
    }, context);
    assertEquals(calls[0].params, {
      zone: "2.0.192.in-addr.arpa",
      type: "Primary",
      catalog: "catalog.example.com",
    });
    assertEquals(written[0].data.catalog, "catalog.example.com");
  } finally {
    __setTechnitiumTransport(null);
  }
});

Deno.test("zone_list surfaces catalog membership", async () => {
  const calls: Call[] = [];
  scriptTransport(calls, () => ({
    zones: [{ name: "a.com", type: "Primary", catalog: "cat.example.com" }],
  }));
  try {
    const { context, written } = makeContext();
    await method("zone_list").execute({}, context);
    assertEquals(written[0].data.catalog, "cat.example.com");
  } finally {
    __setTechnitiumTransport(null);
  }
});

Deno.test("zone_list is a factory with unique spec-prefixed instance names", async () => {
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
    assertEquals(written.map((w) => w.name), ["zone:a.com", "zone:b.com"]);
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

// `records/update` resets ttl, disable, comments and expiryTtl to defaults when
// they are not sent, so the method reads the record first and sends them back.
// The responder serves both the pre-read (matches 1.1.1.1) and the read-back
// (matches 2.2.2.2).
const UPDATE_LIVE_RECORDS = [
  {
    type: "A",
    ttl: 300,
    disabled: true,
    comments: "keep me",
    expiryTtl: 86400,
    rData: { ipAddress: "1.1.1.1" },
  },
  { type: "A", ttl: 300, rData: { ipAddress: "2.2.2.2" } },
];

Deno.test("record_update maps newRData to new* params and carries the record's ttl, disable, comments and expiryTtl", async () => {
  const calls: Call[] = [];
  scriptTransport(calls, recordsResponder(UPDATE_LIVE_RECORDS));
  try {
    const { context, written } = makeContext();
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
    assertEquals(calls[0].path, "/zones/records/get");
    assertEquals(calls[1].path, "/zones/records/update");
    assertEquals(calls[1].params, {
      domain: "www.example.com",
      type: "A",
      zone: "example.com",
      ttl: 300,
      disable: true,
      comments: "keep me",
      expiryTtl: 86400,
      ipAddress: "1.1.1.1",
      newIpAddress: "2.2.2.2",
    });
    assertEquals(written[0].data.ttl, 300);
    assertEquals(written[0].data.disabled, true);
  } finally {
    __setTechnitiumTransport(null);
  }
});

Deno.test("record_update sends the caller's ttl and disable over the record's own", async () => {
  const calls: Call[] = [];
  scriptTransport(calls, recordsResponder(UPDATE_LIVE_RECORDS));
  try {
    const { context } = makeContext();
    await method("record_update").execute(
      {
        zone: "example.com",
        domain: "www.example.com",
        type: "A",
        ttl: 60,
        disable: false,
        rData: { ipAddress: "1.1.1.1" },
        newRData: { ipAddress: "2.2.2.2" },
      },
      context,
    );
    const p = calls[1].params ?? {};
    assertEquals(p.ttl, 60);
    assertEquals(p.disable, false);
    assertEquals(p.comments, "keep me");
  } finally {
    __setTechnitiumTransport(null);
  }
});

Deno.test("record_update throws before the POST when no record matches rData", async () => {
  const calls: Call[] = [];
  scriptTransport(calls, recordsResponder(UPDATE_LIVE_RECORDS));
  try {
    const { context, written } = makeContext();
    await assertRejects(
      () =>
        method("record_update").execute(
          {
            zone: "example.com",
            domain: "www.example.com",
            type: "A",
            rData: { ipAddress: "9.9.9.9" },
            newRData: { ipAddress: "2.2.2.2" },
          },
          context,
        ),
      "no A record at www.example.com",
    );
    assertEquals(calls.map((c) => c.path), ["/zones/records/get"]);
    assertEquals(written.length, 0);
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
    // the pre-read matches the APP record by type alone, whatever rData says
    assertEquals(calls[0].path, "/zones/records/get");
    assertEquals(calls[1].path, "/zones/records/update");
    assertEquals(calls[1].params, {
      domain: "x.zone",
      type: "APP",
      zone: "zone",
      appName: "SplitHorizon",
      classPath: "SplitHorizon.SimpleAddress",
      recordData: '{"local":["C"]}',
    });
    // the bug: prefixNew would emit `newData`, which Technitium ignores → empty
    const p = calls[1].params ?? {};
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
    // identity-based naming gives one record one instance name, whether it was
    // added or later read back
    assertEquals(addWritten[0].name, getWritten[0].name);
  } finally {
    __setTechnitiumTransport(null);
  }
});

// Technitium returns TXT rData with fields the caller never sent. Every writer
// names the record from the server's rData, so all three names agree.
Deno.test("record_add, record_list and record_delete name a TXT record alike", async () => {
  const calls: Call[] = [];
  const rec = {
    name: "t.example.com",
    type: "TXT",
    rData: { text: "hello", splitText: false, characterStrings: ["hello"] },
  };
  let deleted = false;
  scriptTransport(calls, (c) => {
    if (c.path.endsWith("/zones/records/delete")) deleted = true;
    return { zone: { name: "example.com" }, records: deleted ? [] : [rec] };
  });
  try {
    const caller = {
      domain: "t.example.com",
      type: "TXT",
      rData: { text: "hello" },
    };
    const add = makeContext();
    await method("record_add").execute(caller, add.context);
    const list = makeContext();
    await method("record_list").execute({ zone: "example.com" }, list.context);
    const del = makeContext();
    await method("record_delete").execute(caller, del.context);
    assertEquals(add.written[0].name, list.written[0].name);
    assertEquals(del.written[0].name, list.written[0].name);
    assertEquals(del.written[0].data.action, "deleted");
  } finally {
    __setTechnitiumTransport(null);
  }
});

Deno.test("allowed_add and blocked_add on one domain write distinct names", async () => {
  const calls: Call[] = [];
  scriptTransport(calls, () => ({}));
  try {
    const { context, written } = makeContext();
    await method("allowed_add").execute({ domain: "ads.example.com" }, context);
    await method("blocked_add").execute({ domain: "ads.example.com" }, context);
    assertEquals(written.map((w) => w.name), [
      "listEntry:allowed:ads.example.com",
      "listEntry:blocked:ads.example.com",
    ]);
  } finally {
    __setTechnitiumTransport(null);
  }
});

// Without a zone argument the zone is what Technitium reports, so the record
// is filed under example.com, as record_list files it, not www.example.com.
Deno.test("record_add without a zone and record_list address the same instance", async () => {
  const calls: Call[] = [];
  const rec = {
    name: "www.example.com",
    type: "A",
    rData: { ipAddress: "1.2.3.4" },
  };
  scriptTransport(
    calls,
    () => ({ zone: { name: "example.com" }, records: [rec] }),
  );
  try {
    const { context: addCtx, written: addWritten } = makeContext();
    await method("record_add").execute(
      { domain: "www.example.com", type: "A", rData: { ipAddress: "1.2.3.4" } },
      addCtx,
    );
    const { context: listCtx, written: listWritten } = makeContext();
    await method("record_list").execute({ zone: "example.com" }, listCtx);
    assertEquals(addWritten[0].name, listWritten[0].name);
    assertEquals(addWritten[0].data.zone, "example.com");
  } finally {
    __setTechnitiumTransport(null);
  }
});

Deno.test("record_update throws when read-back shows empty APP data", async () => {
  const calls: Call[] = [];
  // Technitium accepts the POST but the live APP record has empty data, which
  // makes the whole zone answer SERVFAIL. Verification must catch it.
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

// Technitium stores what it was sent in its own form: IPv6 compressed and in
// lower case, names without the trailing dot. The write response's
// `addedRecord` is that form, so the read-back compares like with like.
for (
  const [type, sent, stored] of [
    ["AAAA", { ipAddress: "2001:DB8:0:0::1" }, { ipAddress: "2001:db8::1" }],
    ["CNAME", { cname: "target.example.com." }, {
      cname: "target.example.com",
    }],
    ["URI", { uriPriority: 10, uriWeight: 1, uri: "https://example.com/" }, {
      priority: 10,
      weight: 1,
      uri: "https://example.com/",
    }],
    // Sent by number, read back by name: only the server's own copy matches.
    ["DS", { keyTag: 12345, algorithm: 8, digestType: 2, digest: "ab12" }, {
      keyTag: 12345,
      algorithm: "RSASHA256",
      algorithmNumber: 8,
      digestType: "SHA256",
      digestTypeNumber: 2,
      digest: "AB12",
    }],
  ] as const
) {
  Deno.test(`record_add ${type}: read-back and data name use the server's record`, async () => {
    const calls: Call[] = [];
    const rec = { name: "r.example.com", type, ttl: 3600, rData: stored };
    scriptTransport(
      calls,
      (c) =>
        c.path.endsWith("/zones/records/add")
          ? { zone: { name: "example.com" }, addedRecord: rec }
          : { zone: { name: "example.com" }, records: [rec] },
    );
    try {
      const { context, written } = makeContext();
      await method("record_add").execute(
        { domain: "r.example.com", type, rData: sent },
        context,
      );
      assertEquals(
        written[0].name,
        recordInstanceName("example.com", "r.example.com", type, stored),
      );
      assertEquals(written[0].data.rData, stored);
    } finally {
      __setTechnitiumTransport(null);
    }
  });
}

// The pre-read must find the record from the caller's rData, which uses the
// write parameter names and values as typed. Each case has a second record of
// the same type so the right one has to be picked.
for (
  const [type, caller, match, other] of [
    ["AAAA", { ipAddress: "2001:DB8:0:0::2" }, { ipAddress: "2001:db8::2" }, {
      ipAddress: "2001:db8::3",
    }],
    ["MX", { exchange: "Mail.Example.com.", preference: 10 }, {
      exchange: "mail.example.com",
      preference: 10,
    }, { exchange: "mail2.example.com", preference: 20 }],
    ["URI", { uriPriority: 10, uriWeight: 1, uri: "https://a.example/" }, {
      priority: 10,
      weight: 1,
      uri: "https://a.example/",
    }, { priority: 20, weight: 1, uri: "https://a.example/" }],
    ["NAPTR", {
      naptrOrder: 100,
      naptrPreference: 10,
      naptrFlags: "U",
      naptrServices: "E2U+sip",
      naptrRegexp: "!^.*$!sip:x@example.com!",
      naptrReplacement: ".",
    }, {
      order: 100,
      preference: 10,
      flags: "U",
      services: "E2U+sip",
      regexp: "!^.*$!sip:x@example.com!",
      replacement: ".",
    }, {
      order: 200,
      preference: 10,
      flags: "U",
      services: "E2U+sip",
      regexp: "!^.*$!sip:y@example.com!",
      replacement: ".",
    }],
    // Enum fields given as numbers; Technitium reads them back as names.
    ["DS", { keyTag: 1, algorithm: 8, digestType: 2, digest: "ab" }, {
      keyTag: 1,
      algorithm: "RSASHA256",
      algorithmNumber: 8,
      digestType: "SHA256",
      digestTypeNumber: 2,
      digest: "AB",
    }, {
      keyTag: 1,
      algorithm: "ECDSAP256SHA256",
      algorithmNumber: 13,
      digestType: "SHA256",
      digestTypeNumber: 2,
      digest: "AB",
    }],
    [
      "SSHFP",
      {
        sshfpAlgorithm: 4,
        sshfpFingerprintType: 2,
        sshfpFingerprint: "ab",
      },
      { algorithm: "Ed25519", fingerprintType: "SHA256", fingerprint: "AB" },
      {
        algorithm: "RSA",
        fingerprintType: "SHA256",
        fingerprint: "AB",
      },
    ],
    ["TLSA", {
      tlsaCertificateUsage: 3,
      tlsaSelector: 1,
      tlsaMatchingType: 1,
      tlsaCertificateAssociationData: "ab",
    }, {
      certificateUsage: "DANE-EE",
      selector: "SPKI",
      matchingType: "SHA2-256",
      certificateAssociationData: "AB",
    }, {
      certificateUsage: "DANE-TA",
      selector: "SPKI",
      matchingType: "SHA2-256",
      certificateAssociationData: "AB",
    }],
    // A name as the enum spells it (`_`) matches Technitium's `-` form.
    ["TLSA", {
      tlsaCertificateUsage: "DANE_EE",
      tlsaSelector: "SPKI",
      tlsaMatchingType: "SHA2_256",
      tlsaCertificateAssociationData: "ab",
    }, {
      certificateUsage: "DANE-EE",
      selector: "SPKI",
      matchingType: "SHA2-256",
      certificateAssociationData: "AB",
    }, {
      certificateUsage: "DANE-TA",
      selector: "SPKI",
      matchingType: "SHA2-256",
      certificateAssociationData: "AB",
    }],
  ] as const
) {
  Deno.test(`record_update ${type}: the pre-read matches caller rData to the server's form`, async () => {
    const calls: Call[] = [];
    scriptTransport(
      calls,
      recordsResponder([
        { type, ttl: 60, comments: "other", rData: other },
        { type, ttl: 600, comments: "keep me", rData: match },
      ]),
    );
    try {
      const { context } = makeContext();
      await method("record_update").execute(
        {
          zone: "example.com",
          domain: "r.example.com",
          type,
          rData: caller,
          // Unchanged, so the read-back finds the record as it was.
          newRData: caller,
        },
        context,
      );
      assertEquals(calls[1].path, "/zones/records/update");
      assertEquals(calls[1].params?.ttl, 600);
      assertEquals(calls[1].params?.comments, "keep me");
    } finally {
      __setTechnitiumTransport(null);
    }
  });
}

// Technitium has no newCname: records/update reads the new target from
// `cname` and replaces the record with it.
Deno.test("record_update retargets a CNAME by sending the new target as cname", async () => {
  const calls: Call[] = [];
  let target = "old.example.com";
  scriptTransport(calls, (c) => {
    if (c.path.endsWith("/zones/records/update")) {
      target = String(c.params?.cname);
      return {
        zone: { name: "example.com" },
        updatedRecord: {
          name: "www.example.com",
          type: "CNAME",
          rData: { cname: target },
        },
      };
    }
    return {
      zone: { name: "example.com" },
      records: [{
        name: "www.example.com",
        type: "CNAME",
        rData: { cname: target },
      }],
    };
  });
  try {
    const { context, written } = makeContext();
    await method("record_update").execute(
      {
        domain: "www.example.com",
        type: "CNAME",
        rData: { cname: "old.example.com" },
        newRData: { cname: "new.example.com" },
      },
      context,
    );
    const p = calls[1].params ?? {};
    assertEquals(p.cname, "new.example.com");
    assert(!("newCname" in p), "no newCname param");
    assertEquals(written[0].data.rData, { cname: "new.example.com" });
  } finally {
    __setTechnitiumTransport(null);
  }
});

Deno.test("client_resolve sends the API's `dnssec` flag, not the argument name", async () => {
  const calls: Call[] = [];
  scriptTransport(calls, () => ({ result: { RCODE: "NoError", Answer: [] } }));
  try {
    const { context } = makeContext();
    await method("client_resolve").execute(
      {
        domain: "example.com",
        type: "A",
        server: "this-server",
        protocol: "Udp",
        dnssecValidation: true,
      },
      context,
    );
    assertEquals(calls[0].path, "/dnsClient/resolve");
    assertEquals(calls[0].params?.dnssec, true);
    assert(!("dnssecValidation" in (calls[0].params ?? {})));
  } finally {
    __setTechnitiumTransport(null);
  }
});

// ----- settings backup / restore flags ------------------------------------
// The download and upload transports bypass the test seam, so the flag builder
// that produces their query string is tested directly.

const BACKUP_DEFAULTS = settingsSectionFlags(
  {
    authConfig: true,
    clusterConfig: true,
    webServiceSettings: true,
    dnsSettings: true,
    logSettings: true,
    zones: true,
    allowedZones: true,
    blockedZones: true,
    blockLists: true,
    apps: true,
    scopes: true,
    stats: false,
    logs: false,
  },
  undefined,
);

Deno.test("settingsSectionFlags sends every section the API knows, and only those", () => {
  assertEquals(
    Object.keys(BACKUP_DEFAULTS).sort(),
    [...SETTINGS_SECTIONS].sort(),
  );
  // the flag the old code sent, which the API never had
  assert(!("dnsApps" in BACKUP_DEFAULTS));
  // the three sections whose absence made a "full" backup incomplete
  assertEquals(BACKUP_DEFAULTS.dnsSettings, true);
  assertEquals(BACKUP_DEFAULTS.webServiceSettings, true);
  assertEquals(BACKUP_DEFAULTS.logSettings, true);
});

Deno.test("settingsSectionFlags lets options override a default", () => {
  const flags = settingsSectionFlags(
    { ...BACKUP_DEFAULTS } as Parameters<typeof settingsSectionFlags>[0],
    { authConfig: false, logs: true },
  );
  assertEquals(flags.authConfig, false);
  assertEquals(flags.logs, true);
  assertEquals(flags.zones, true);
});

Deno.test("settingsSectionFlags rejects a section name the API does not know", () => {
  assertThrows(
    () =>
      settingsSectionFlags(
        { ...BACKUP_DEFAULTS } as Parameters<typeof settingsSectionFlags>[0],
        { dnsApps: true },
      ),
    "Unknown settings section(s): dnsApps",
  );
});

// `/allowed/list` browses a label tree, one node per call. This fixture is the
// server's answers with review-a.example.com, sub.review-a.example.com and
// review-b.example.net allowed: the root holds only `com` and `net`, and the
// server walks single-child chains (com → example.com → review-a.example.com)
// itself.
const ALLOWED_TREE: Record<string, Record<string, unknown>> = {
  "": { domain: "", zones: ["com", "net"], records: [] },
  "com": {
    domain: "review-a.example.com",
    zones: ["sub.review-a.example.com"],
    records: [{ name: "review-a.example.com", type: "NS" }],
  },
  "sub.review-a.example.com": {
    domain: "sub.review-a.example.com",
    zones: [],
    records: [{ name: "sub.review-a.example.com", type: "NS" }],
  },
  "net": {
    domain: "review-b.example.net",
    zones: [],
    records: [{ name: "review-b.example.net", type: "NS" }],
  },
};

Deno.test("allowed_list walks the label tree and writes one listEntry per allowed domain", async () => {
  const calls: Call[] = [];
  scriptTransport(
    calls,
    (c) => ALLOWED_TREE[String(c.params?.domain ?? "")] ?? {},
  );
  try {
    const { context, written } = makeContext();
    await method("allowed_list").execute({}, context);
    assert(
      calls.every((c) => c.path === "/allowed/list"),
      "only list calls",
    );
    // Not `com` and `net`, the root's child labels.
    assertEquals(written.map((w) => w.name), [
      "listEntry:allowed:review-a.example.com",
      "listEntry:allowed:review-b.example.net",
      "listEntry:allowed:sub.review-a.example.com",
    ]);
    assertEquals(written[0].data.list, "allowed");
  } finally {
    __setTechnitiumTransport(null);
  }
});

Deno.test("blocked_list with a domain lists only that branch", async () => {
  const calls: Call[] = [];
  scriptTransport(
    calls,
    (c) => ALLOWED_TREE[String(c.params?.domain ?? "")] ?? {},
  );
  try {
    const { context, written } = makeContext();
    await method("blocked_list").execute({ domain: "com" }, context);
    assertEquals(calls[0].path, "/blocked/list");
    assertEquals(written.map((w) => w.name), [
      "listEntry:blocked:review-a.example.com",
      "listEntry:blocked:sub.review-a.example.com",
    ]);
  } finally {
    __setTechnitiumTransport(null);
  }
});

// ----- reachable check -------------------------------------------------------

type CheckDef = {
  execute: (c: unknown) => Promise<{ pass: boolean; errors?: string[] }>;
};
const reachable = (model.checks as unknown as Record<string, CheckDef>)
  .reachable;

// A check receives globalArgs without the schema's defaults, so an unset
// skipTlsVerify reached the transport as undefined.
Deno.test("reachable check applies the schema defaults to globalArgs", async () => {
  let seenSkipTls: unknown;
  __setTechnitiumTransport((g) => {
    seenSkipTls = g.skipTlsVerify;
    return Promise.resolve({ username: "swamp" });
  });
  try {
    const res = await reachable.execute({
      globalArgs: {
        baseUrl: TEST_GLOBALS.baseUrl,
        apiToken: TEST_GLOBALS.apiToken,
      },
    });
    assertEquals(res.pass, true);
    assertEquals(seenSkipTls, false);
  } finally {
    __setTechnitiumTransport(null);
  }
});

// `settings/get` needs Settings:View, which a token scoped to zones lacks; the
// session read needs only a valid token.
Deno.test("reachable check probes the session, which any valid token can read", async () => {
  const calls: Call[] = [];
  scriptTransport(calls, () => ({ username: "swamp" }));
  try {
    const res = await reachable.execute({ globalArgs: TEST_GLOBALS });
    assertEquals(res.pass, true);
    assertEquals(calls.map((c) => `${c.method} ${c.path}`), [
      "GET /user/session/get",
    ]);
  } finally {
    __setTechnitiumTransport(null);
  }
});

Deno.test("reachable check: a definition that fails the schema fails without probing", async () => {
  let called = false;
  __setTechnitiumTransport(() => {
    called = true;
    return Promise.resolve({});
  });
  try {
    const res = await reachable.execute({
      globalArgs: { baseUrl: "https://dns.test:53443" },
    });
    assertEquals(res.pass, false);
    assert(!called, "must not probe with an invalid definition");
  } finally {
    __setTechnitiumTransport(null);
  }
});

// ----- transport -------------------------------------------------------------

Deno.test("requestTarget drops the brackets URL keeps around an IPv6 literal", () => {
  assertEquals(requestTarget(new URL("http://[::1]:5380/api/x?a=1")), {
    hostname: "::1",
    port: 5380,
    path: "/api/x?a=1",
  });
  assertEquals(requestTarget(new URL("https://dns.example/api")), {
    hostname: "dns.example",
    port: 443,
    path: "/api",
  });
});

// ----- settings ---------------------------------------------------------------

Deno.test("blocking_get_settings reads the block-list update interval under the server's key", async () => {
  const calls: Call[] = [];
  scriptTransport(calls, () => ({ blockListUpdateIntervalHours: 24 }));
  try {
    const { context, written } = makeContext();
    await method("blocking_get_settings").execute({}, context);
    assertEquals(written[0].data.blockListUrlUpdateIntervalHours, 24);
  } finally {
    __setTechnitiumTransport(null);
  }
});

Deno.test("checkListUrls rejects URLs the one comma-separated setting cannot hold", () => {
  checkListUrls(["https://a.example/list.txt"], ["https://b.example/allow"]);
  assertThrows(() => checkListUrls(["https://a.example/x,y"]), "comma");
  assertThrows(
    () => checkListUrls(["!https://a.example/"]),
    "pass it in allowListUrls",
  );
  assertThrows(
    () => checkListUrls(undefined, ["!https://a.example/"]),
    "without it",
  );
});

Deno.test("blocking_set_lists refuses a bad URL before changing anything", async () => {
  const calls: Call[] = [];
  scriptTransport(calls, () => ({ blockListUrls: [] }));
  try {
    const { context } = makeContext();
    await assertRejects(
      () =>
        method("blocking_set_lists").execute(
          { allowListUrls: ["!https://a.example/"] },
          context,
        ),
      "Invalid list URL",
    );
    assertEquals(calls.length, 0);
  } finally {
    __setTechnitiumTransport(null);
  }
});

Deno.test("settings_restore refuses a file that is not a zip before uploading it", async () => {
  const dir = await Deno.makeTempDir();
  const file = `${dir}/not-a-backup.zip`;
  await Deno.writeTextFile(file, "<html>login</html>");
  try {
    const { context } = makeContext();
    await assertRejects(
      () => method("settings_restore").execute({ filePath: file }, context),
      "is not a zip file",
    );
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});

// ----- schemas ----------------------------------------------------------------

Deno.test("stats, dnsResponse and queryLog store only the fields their schema names", () => {
  const resources = model.resources as unknown as Record<
    string,
    { schema: { parse: (v: unknown) => Record<string, unknown> } }
  >;
  for (const spec of ["stats", "dnsResponse", "queryLog"]) {
    const base = spec === "stats"
      ? { range: "LastHour" }
      : spec === "dnsResponse"
      ? { server: "s", domain: "d", type: "A", protocol: "Udp" }
      : {};
    const parsed = resources[spec].schema.parse({
      ...base,
      observedAt: "2026-10-11T00:00:00Z",
      unexpected: 1,
    });
    assert(!("unexpected" in parsed), `${spec} keeps an unknown field`);
  }
});

Deno.test("client_resolve stores the parsed result but not other reply fields", async () => {
  const calls: Call[] = [];
  scriptTransport(calls, () => ({
    result: { RCODE: "NoError", Answer: [{ Name: "example.com" }] },
    rawResponses: [],
    somethingNew: true,
  }));
  try {
    const { context, written } = makeContext();
    await method("client_resolve").execute({ domain: "example.com" }, context);
    const data = written[0].data;
    assertEquals(data.rcode, "NoError");
    assertEquals(data.result, {
      RCODE: "NoError",
      Answer: [{ Name: "example.com" }],
    });
    assert(!("somethingNew" in data), "a reply field outside the schema");
  } finally {
    __setTechnitiumTransport(null);
  }
});

Deno.test("dashboard_stats records a Custom range's start and end", async () => {
  const calls: Call[] = [];
  scriptTransport(calls, () => ({ stats: { totalQueries: 5 } }));
  try {
    const { context, written } = makeContext();
    await method("dashboard_stats").execute({
      type: "Custom",
      start: "2026-10-01T00:00:00Z",
      end: "2026-10-02T00:00:00Z",
    }, context);
    assertEquals(written[0].data.start, "2026-10-01T00:00:00Z");
    assertEquals(written[0].data.end, "2026-10-02T00:00:00Z");
  } finally {
    __setTechnitiumTransport(null);
  }
});

// ----- logging ----------------------------------------------------------------

// swamp's logger prints only the props named in the message.
Deno.test("logs name their props in the message, so the values are printed", async () => {
  const calls: Call[] = [];
  scriptTransport(calls, () => ({ zones: [{ name: "a.com" }] }));
  try {
    const { context, logs } = makeContext();
    await method("zone_list").execute({}, context);
    assertEquals(logs.map((l) => l.message), ["Listed {count} zones"]);
    assertEquals(logs[0].props, { count: 1 });
  } finally {
    __setTechnitiumTransport(null);
  }
});

Deno.test("blocking_set_lists warns about a URL over 255 characters", async () => {
  const calls: Call[] = [];
  scriptTransport(calls, () => ({ blockListUrls: [] }));
  try {
    const { context, logs } = makeContext();
    const long = "https://a.example/" + "x".repeat(250);
    await method("blocking_set_lists").execute(
      { blockListUrls: [long] },
      context,
    );
    const warnings = logs.filter((l) => l.level === "warn");
    assertEquals(warnings.length, 1);
    assertEquals(warnings[0].props, { count: 1 });
  } finally {
    __setTechnitiumTransport(null);
  }
});

// ----- zones ------------------------------------------------------------------

Deno.test("zone_create names the zone the server made, not the argument", async () => {
  const calls: Call[] = [];
  scriptTransport(calls, () => ({ domain: "2.0.192.in-addr.arpa" }));
  try {
    const { context, written } = makeContext();
    await method("zone_create").execute({ zone: "192.0.2.0/24" }, context);
    assertEquals(written[0].name, "zone:2.0.192.in-addr.arpa");
    assertEquals(written[0].data.name, "2.0.192.in-addr.arpa");
  } finally {
    __setTechnitiumTransport(null);
  }
});

const ZONE_INFO = {
  name: "lab.example.com",
  type: "Primary",
  disabled: false,
  dnssecStatus: "Unsigned",
  catalog: "catalog.example.com",
};

for (
  const [name, disabled] of [["zone_enable", false], [
    "zone_disable",
    true,
  ]] as const
) {
  Deno.test(`${name} stores the whole zone, not only disabled`, async () => {
    const calls: Call[] = [];
    scriptTransport(
      calls,
      (c) =>
        c.path === "/zones/records/get"
          ? { zone: { ...ZONE_INFO, disabled }, records: [] }
          : {},
    );
    try {
      const { context, written } = makeContext();
      await method(name).execute({ zone: "lab.example.com" }, context);
      assertEquals(written[0].data.type, "Primary");
      assertEquals(written[0].data.catalog, "catalog.example.com");
      assertEquals(written[0].data.disabled, disabled);
    } finally {
      __setTechnitiumTransport(null);
    }
  });
}

Deno.test("zone_delete reads the zone first and stores what was deleted", async () => {
  const calls: Call[] = [];
  scriptTransport(
    calls,
    (c) =>
      c.path === "/zones/records/get" ? { zone: ZONE_INFO, records: [] } : {},
  );
  try {
    const { context, written } = makeContext();
    await method("zone_delete").execute({ zone: "lab.example.com" }, context);
    assertEquals(calls.map((c) => c.path), [
      "/zones/records/get",
      "/zones/delete",
    ]);
    assertEquals(written[0].data.type, "Primary");
    assertEquals(written[0].data.action, "deleted");
  } finally {
    __setTechnitiumTransport(null);
  }
});

// records/get answers with the closest enclosing zone when the named one is
// missing; that zone's details must not be stored under this zone's name.
Deno.test("zone_enable ignores a parent zone returned in place of the named one", async () => {
  const calls: Call[] = [];
  scriptTransport(
    calls,
    (c) =>
      c.path === "/zones/records/get"
        ? { zone: { name: "example.com", type: "Forwarder" }, records: [] }
        : {},
  );
  try {
    const { context, written } = makeContext();
    await method("zone_enable").execute({ zone: "lab.example.com" }, context);
    assertEquals(written[0].data.name, "lab.example.com");
    assertEquals(written[0].data.type, undefined);
  } finally {
    __setTechnitiumTransport(null);
  }
});

// ----- records ----------------------------------------------------------------

Deno.test("record_get and record_list do not store a FWD record's proxy password", async () => {
  const fwd = {
    name: "corp.example",
    type: "FWD",
    rData: {
      protocol: "Udp",
      forwarder: "192.0.2.53",
      proxyType: "Socks5",
      proxyUsername: "u",
      proxyPassword: "hunter2",
    },
  };
  const calls: Call[] = [];
  scriptTransport(
    calls,
    () => ({ zone: { name: "corp.example" }, records: [fwd] }),
  );
  try {
    for (
      const [name, args] of [
        ["record_get", { domain: "corp.example" }],
        ["record_list", { zone: "corp.example" }],
      ] as const
    ) {
      const { context, written } = makeContext();
      await method(name).execute(args, context);
      const rData = written[0].data.rData as Record<string, unknown>;
      assertEquals(rData.proxyUsername, "u");
      assert(!("proxyPassword" in rData), `${name} stored the proxy password`);
    }
  } finally {
    __setTechnitiumTransport(null);
  }
});

Deno.test("record_add stores the server's TTL and disabled state", async () => {
  const calls: Call[] = [];
  const rec = {
    name: "www.example.com",
    type: "A",
    ttl: 3600,
    disabled: false,
    rData: { ipAddress: "192.0.2.1" },
  };
  scriptTransport(
    calls,
    (c) =>
      c.path === "/zones/records/add"
        ? { zone: { name: "example.com" }, addedRecord: rec }
        : { zone: { name: "example.com" }, records: [rec] },
  );
  try {
    const { context, written } = makeContext();
    await method("record_add").execute(
      {
        domain: "www.example.com",
        type: "A",
        rData: { ipAddress: "192.0.2.1" },
      },
      context,
    );
    assertEquals(written[0].data.ttl, 3600);
    assertEquals(written[0].data.disabled, false);
  } finally {
    __setTechnitiumTransport(null);
  }
});

Deno.test("record_list stores the zone as the server names it", async () => {
  const calls: Call[] = [];
  scriptTransport(calls, () => ({
    zone: { name: "example.com" },
    records: [{ name: "example.com", type: "NS", rData: { nameServer: "ns" } }],
  }));
  try {
    const { context, written } = makeContext();
    await method("record_list").execute({ zone: "Example.COM." }, context);
    assertEquals(written[0].data.zone, "example.com");
  } finally {
    __setTechnitiumTransport(null);
  }
});

// An APP update rewrites the whole record; without the current content, a
// newRData with no `data` would leave the record empty (zone SERVFAIL).
Deno.test("record_update on APP keeps the current data when newRData leaves it out", async () => {
  const calls: Call[] = [];
  scriptTransport(
    calls,
    recordsResponder([{
      type: "APP",
      rData: { appName: "Split", classPath: "Split.Simple", data: '{"a":1}' },
    }]),
  );
  try {
    const { context } = makeContext();
    await method("record_update").execute(
      {
        zone: "zone",
        domain: "x.zone",
        type: "APP",
        newRData: { appName: "Split", classPath: "Split.Simple" },
      },
      context,
    );
    assertEquals(calls[1].path, "/zones/records/update");
    assertEquals(calls[1].params?.recordData, '{"a":1}');
  } finally {
    __setTechnitiumTransport(null);
  }
});

// record_delete names its data from the live record it found; a number in the
// caller's DS rData has to find the record Technitium lists by name.
Deno.test("record_delete finds a DS record given its algorithm as a number", async () => {
  const live = {
    name: "child.example.com",
    type: "DS",
    rData: {
      keyTag: 1,
      algorithm: "RSASHA256",
      algorithmNumber: 8,
      digestType: "SHA256",
      digestTypeNumber: 2,
      digest: "AB",
    },
  };
  let deleted = false;
  const calls: Call[] = [];
  scriptTransport(calls, (c) => {
    if (c.path === "/zones/records/delete") deleted = true;
    return c.path === "/zones/records/get"
      ? { zone: { name: "example.com" }, records: deleted ? [] : [live] }
      : {};
  });
  try {
    const { context, written } = makeContext();
    await method("record_delete").execute(
      {
        domain: "child.example.com",
        type: "DS",
        rData: { keyTag: 1, algorithm: 8, digestType: 2, digest: "ab" },
      },
      context,
    );
    assertEquals(
      written[0].name,
      recordInstanceName("example.com", "child.example.com", "DS", live.rData),
    );
  } finally {
    __setTechnitiumTransport(null);
  }
});

// ----- decisions applied 2026-10-11 ------------------------------------------

Deno.test("buildRequest sends the token only in the Authorization header", () => {
  const { url, headers } = buildRequest(TEST_GLOBALS, "/zones/list", {
    a: 1,
  });
  assertEquals(url.searchParams.get("token"), null);
  assert(!url.href.includes(TEST_GLOBALS.apiToken), "token in the URL");
  assertEquals(headers.Authorization, `Bearer ${TEST_GLOBALS.apiToken}`);
  assertEquals(url.searchParams.get("a"), "1");
});

const LOG_ENTRY = {
  rowNumber: 1,
  timestamp: "2026-10-11T00:00:00.000Z",
  clientIpAddress: "192.0.2.10",
  protocol: "Udp",
  responseType: "Recursive",
  rcode: "NoError",
  qname: "example.com",
  qtype: "A",
  qclass: "IN",
  answer: "192.0.2.1",
};

Deno.test("logs_query keys entries on their content and records the page totals", async () => {
  const other = { ...LOG_ENTRY, rowNumber: 2, qname: "example.net" };
  const runQuery = async (entries: unknown[]) => {
    const calls: Call[] = [];
    scriptTransport(calls, () => ({
      pageNumber: 1,
      totalPages: 3,
      totalEntries: 150,
      entries,
    }));
    try {
      const { context, written } = makeContext();
      await method("logs_query").execute({}, context);
      return written;
    } finally {
      __setTechnitiumTransport(null);
    }
  };
  const first = await runQuery([LOG_ENTRY, other]);
  // The same entry at another position in a later query keeps its name.
  const second = await runQuery([{ ...other, rowNumber: 1 }]);
  const firstOther = first.find((w) => w.data.qname === "example.net");
  assertEquals(second[0].name, firstOther?.name);
  assert(second[0].name.startsWith("queryLog:"));
  assert(first[0].name !== first[1].name, "distinct entries share a name");
  const page = first.find((w) => w.specName === "queryLogPage");
  assertEquals(page?.name, "queryLogPage");
  assertEquals(page?.data.totalPages, 3);
  assertEquals(page?.data.totalEntries, 150);
  assertEquals(page?.data.entriesOnPage, 2);
});

Deno.test("logs_query writes an entry repeated to the millisecond once", async () => {
  const calls: Call[] = [];
  scriptTransport(calls, () => ({ entries: [LOG_ENTRY, LOG_ENTRY] }));
  try {
    const { context, written } = makeContext();
    await method("logs_query").execute({}, context);
    assertEquals(written.filter((w) => w.specName === "queryLog").length, 1);
  } finally {
    __setTechnitiumTransport(null);
  }
});

// Technitium reads the password only alongside a path.
Deno.test("web_service_set_tls sends the current path with a password given alone", async () => {
  const calls: Call[] = [];
  scriptTransport(
    calls,
    (c) =>
      c.path === "/settings/get"
        ? { webServiceTlsCertificatePath: "cert.pfx" }
        : {},
  );
  try {
    const { context } = makeContext();
    await method("web_service_set_tls").execute(
      { certificatePassword: "pw" },
      context,
    );
    const set = calls.find((c) => c.path === "/settings/set");
    assertEquals(set?.params?.webServiceTlsCertificatePath, "cert.pfx");
    assertEquals(set?.params?.webServiceTlsCertificatePassword, "pw");
  } finally {
    __setTechnitiumTransport(null);
  }
});

Deno.test("web_service_set_tls rejects a password alone when no certificate is configured", async () => {
  const calls: Call[] = [];
  scriptTransport(calls, () => ({ webServiceTlsCertificatePath: "" }));
  try {
    const { context } = makeContext();
    await assertRejects(
      () =>
        method("web_service_set_tls").execute(
          { certificatePassword: "pw" },
          context,
        ),
      "no certificate is configured",
    );
    assert(!calls.some((c) => c.path === "/settings/set"), "settings changed");
  } finally {
    __setTechnitiumTransport(null);
  }
});

Deno.test("zone_delete on a missing zone reports deleted without deleting", async () => {
  const calls: Call[] = [];
  __setTechnitiumTransport((_g, m, p, params) => {
    calls.push({ method: m, path: p, params });
    return p === "/zones/records/get"
      ? Promise.reject(
        new Error(
          "Technitium GET /zones/records/get: No such zone was found: gone.example",
        ),
      )
      : Promise.resolve({});
  });
  try {
    const { context, written } = makeContext();
    await method("zone_delete").execute({ zone: "gone.example" }, context);
    assertEquals(calls.map((c) => c.path), ["/zones/records/get"]);
    assertEquals(written[0].data.action, "deleted");
    assertEquals(written[0].name, "zone:gone.example");
  } finally {
    __setTechnitiumTransport(null);
  }
});

function existingZoneTransport(calls: Call[], type: string): void {
  __setTechnitiumTransport((_g, m, p, params) => {
    calls.push({ method: m, path: p, params });
    if (p === "/zones/create") {
      return Promise.reject(
        new Error(
          "Technitium POST /zones/create: Zone already exists: lab.example.com",
        ),
      );
    }
    return Promise.resolve({ zone: { ...ZONE_INFO, type }, records: [] });
  });
}

Deno.test("zone_create on an existing zone of the same type reports unchanged", async () => {
  const calls: Call[] = [];
  existingZoneTransport(calls, "Primary");
  try {
    const { context, written } = makeContext();
    await method("zone_create").execute({ zone: "lab.example.com" }, context);
    assertEquals(written[0].data.action, "unchanged");
    assertEquals(written[0].data.type, "Primary");
  } finally {
    __setTechnitiumTransport(null);
  }
});

Deno.test("zone_create on an existing zone of another type still fails", async () => {
  const calls: Call[] = [];
  existingZoneTransport(calls, "Forwarder");
  try {
    const { context, written } = makeContext();
    await assertRejects(
      () => method("zone_create").execute({ zone: "lab.example.com" }, context),
      "Zone already exists",
    );
    assertEquals(written.length, 0);
  } finally {
    __setTechnitiumTransport(null);
  }
});

Deno.test("zone_create on an existing zone in another catalog fails", async () => {
  const calls: Call[] = [];
  existingZoneTransport(calls, "Primary");
  try {
    const { context, written } = makeContext();
    await assertRejects(
      () =>
        method("zone_create").execute(
          { zone: "lab.example.com", catalog: "cat.example.com" },
          context,
        ),
      "in catalog catalog.example.com, not cat.example.com",
    );
    assertEquals(written.length, 0);
  } finally {
    __setTechnitiumTransport(null);
  }
});

Deno.test("zone_create on an existing member of the catalog asked for reports unchanged", async () => {
  __setTechnitiumTransport((_g, _m, p) =>
    p === "/zones/create"
      ? Promise.reject(new Error("Zone already exists: lab.example.com"))
      : Promise.resolve({
        zone: { ...ZONE_INFO, type: "Primary", catalog: "cat.example.com" },
        records: [],
      })
  );
  try {
    const { context, written } = makeContext();
    await method("zone_create").execute(
      { zone: "lab.example.com", catalog: "Cat.Example.com." },
      context,
    );
    assertEquals(written[0].data.action, "unchanged");
  } finally {
    __setTechnitiumTransport(null);
  }
});

Deno.test("zone and listEntry expire after 30 days, like zoneRecord", () => {
  const resources = model.resources as unknown as Record<
    string,
    { lifetime: string }
  >;
  assertEquals(resources.zone.lifetime, "30d");
  assertEquals(resources.listEntry.lifetime, "30d");
});

// ----- record_ensure -------------------------------------------------------

type FakeRecord = { type: string; ttl: number; rData: Record<string, unknown> };

/**
 * A stateful stand-in for one name's records, behaving as Technitium was seen
 * to on a live server: an add without `overwrite` joins the records of its type
 * and sets the TTL of all of them, `overwrite` replaces them, and an update
 * changes the matched record in place.
 */
function fakeName(initial: FakeRecord[]) {
  const records = initial.map((r) => ({ ...r, rData: { ...r.rData } }));
  const calls: Call[] = [];
  scriptTransport(calls, (c) => {
    const p = c.params ?? {};
    const type = String(p.type);
    if (c.path.endsWith("/zones/records/add")) {
      const ttl = Number(p.ttl ?? 3600);
      const added = { type, ttl, rData: { ipAddress: String(p.ipAddress) } };
      if (p.overwrite) {
        for (let i = records.length - 1; i >= 0; i--) {
          if (records[i].type === type) records.splice(i, 1);
        }
      }
      for (const r of records) if (r.type === type) r.ttl = ttl;
      records.push(added);
      return { addedRecord: { name: "www.example.com", ...added } };
    }
    if (c.path.endsWith("/zones/records/update")) {
      const r = records.find((r) =>
        r.type === type && r.rData.ipAddress === p.ipAddress
      )!;
      r.ttl = Number(p.ttl);
      return { updatedRecord: { name: "www.example.com", ...r } };
    }
    return {
      zone: { name: "example.com" },
      records: records.map((r) => ({ name: "www.example.com", ...r })),
    };
  });
  return { calls, records };
}

const ensureA = (ipAddress: string, mode: string, ttl?: number) => ({
  records: [{
    domain: "www.example.com",
    type: "A",
    rData: { ipAddress },
    ttl,
    mode,
  }],
});

Deno.test("record_ensure writes nothing when the record already matches", async () => {
  const { calls } = fakeName([
    { type: "A", ttl: 300, rData: { ipAddress: "192.0.2.1" } },
  ]);
  try {
    const { context, written } = makeContext();
    await method("record_ensure").execute(
      ensureA("192.0.2.1", "replace", 300),
      context,
    );
    assertEquals(calls.map((c) => c.method), ["GET"]);
    assertEquals(written[0].data.action, "unchanged");
    assertEquals(
      written[0].name,
      recordInstanceName("example.com", "www.example.com", "A", {
        ipAddress: "192.0.2.1",
      }),
    );
  } finally {
    __setTechnitiumTransport(null);
  }
});

Deno.test("record_ensure add mode adds beside the others and keeps their TTL", async () => {
  const { calls, records } = fakeName([
    { type: "A", ttl: 600, rData: { ipAddress: "192.0.2.1" } },
  ]);
  try {
    const { context, written } = makeContext();
    await method("record_ensure").execute(ensureA("192.0.2.2", "add"), context);
    const post = calls.find((c) => c.method === "POST")!;
    assertEquals(post.path, "/zones/records/add");
    assertEquals(post.params?.ttl, 600);
    assert(!post.params?.overwrite, "add mode does not overwrite");
    assertEquals(records.map((r) => [r.rData.ipAddress, r.ttl]), [
      ["192.0.2.1", 600],
      ["192.0.2.2", 600],
    ]);
    assertEquals(written[0].data.action, "created");
  } finally {
    __setTechnitiumTransport(null);
  }
});

Deno.test("record_ensure add mode updates a matching record whose TTL differs", async () => {
  const { calls, records } = fakeName([
    { type: "A", ttl: 600, rData: { ipAddress: "192.0.2.1" } },
  ]);
  try {
    const { context, written } = makeContext();
    await method("record_ensure").execute(
      ensureA("192.0.2.1", "add", 120),
      context,
    );
    const post = calls.find((c) => c.method === "POST")!;
    assertEquals(post.path, "/zones/records/update");
    assertEquals(records[0].ttl, 120);
    assertEquals(written[0].data.action, "updated");
    assertEquals(written[0].data.ttl, 120);
  } finally {
    __setTechnitiumTransport(null);
  }
});

Deno.test("record_ensure replace mode overwrites and stores the removed records as deleted", async () => {
  const { calls, records } = fakeName([
    { type: "A", ttl: 300, rData: { ipAddress: "192.0.2.1" } },
    { type: "A", ttl: 300, rData: { ipAddress: "192.0.2.2" } },
  ]);
  try {
    const { context, written } = makeContext();
    await method("record_ensure").execute(
      ensureA("192.0.2.1", "replace"),
      context,
    );
    const post = calls.find((c) => c.method === "POST")!;
    assertEquals(post.params?.overwrite, true);
    assertEquals(post.params?.ttl, 300);
    assertEquals(records.map((r) => r.rData.ipAddress), ["192.0.2.1"]);
    assertEquals(
      written.map((w) => [w.data.rData, w.data.action]),
      [
        [{ ipAddress: "192.0.2.2" }, "deleted"],
        [{ ipAddress: "192.0.2.1" }, "updated"],
      ],
    );
  } finally {
    __setTechnitiumTransport(null);
  }
});

Deno.test("record_ensure creates a missing record, then reports it unchanged on a rerun", async () => {
  fakeName([]);
  try {
    const first = makeContext();
    await method("record_ensure").execute(
      ensureA("192.0.2.1", "replace", 300),
      first.context,
    );
    assertEquals(first.written[0].data.action, "created");
    const second = makeContext();
    await method("record_ensure").execute(
      ensureA("192.0.2.1", "replace", 300),
      second.context,
    );
    assertEquals(second.written[0].data.action, "unchanged");
    assertEquals(second.written[0].name, first.written[0].name);
  } finally {
    __setTechnitiumTransport(null);
  }
});

Deno.test("record_ensure requires a mode on every record", async () => {
  fakeName([]);
  try {
    const { context } = makeContext();
    await assertRejects(() =>
      method("record_ensure").execute(
        { records: [{ domain: "www.example.com", type: "A", rData: {} }] },
        context,
      )
    );
  } finally {
    __setTechnitiumTransport(null);
  }
});

Deno.test("record_ensure refuses a replace that shares its name and type with another entry", async () => {
  const { calls } = fakeName([]);
  try {
    const { context, written } = makeContext();
    await assertRejects(
      () =>
        method("record_ensure").execute(
          {
            records: [
              ...ensureA("192.0.2.1", "add").records,
              ...ensureA("192.0.2.2", "replace").records,
            ],
          },
          context,
        ),
      "a replace must be the only entry",
    );
    assertEquals(calls.length, 0);
    assertEquals(written.length, 0);
  } finally {
    __setTechnitiumTransport(null);
  }
});

Deno.test("record_ensure stops at a failed write and surfaces Technitium's error", async () => {
  __setTechnitiumTransport((_g, _m, p) =>
    p === "/zones/records/add"
      ? Promise.reject(
        new Error("Technitium POST /zones/records/add: Record already exists."),
      )
      : Promise.resolve({
        zone: { name: "example.com" },
        records: [{
          name: "www.example.com",
          type: "CNAME",
          ttl: 3600,
          rData: { cname: "a.example.com" },
        }],
      })
  );
  try {
    const { context, written } = makeContext();
    await assertRejects(
      () =>
        method("record_ensure").execute(
          {
            records: [{
              domain: "www.example.com",
              type: "CNAME",
              rData: { cname: "b.example.com" },
              mode: "add",
            }],
          },
          context,
        ),
      "Record already exists",
    );
    assertEquals(written.length, 0);
  } finally {
    __setTechnitiumTransport(null);
  }
});
