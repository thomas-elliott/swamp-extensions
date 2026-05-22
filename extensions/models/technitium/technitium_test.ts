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
  scriptTransport(calls, () => ({}));
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
  } finally {
    __setTechnitiumTransport(null);
  }
});

Deno.test("record_update maps newRData to new* params and keeps identifying rData", async () => {
  const calls: Call[] = [];
  scriptTransport(calls, () => ({}));
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
