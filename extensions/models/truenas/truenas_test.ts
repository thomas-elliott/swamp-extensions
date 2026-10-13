/**
 * Unit tests for the important logic of `@thomas/truenas`, where an unnoticed bug
 * would be costly: the wss-only transport guard (TrueNAS revokes an API key sent
 * without TLS), port-binding shaping, verify-first resolution, the app.update
 * full-network patch + job-wait, share-access update bodies, the exposure roll-up
 * flags, and the no-op fast paths. No live host: the JSON-RPC transport is faked via
 * the __setTruenasSession seam.
 */
import {
  __setTruenasSession,
  type Json,
  model,
  type RpcSession,
  type SessionFactory,
  websocketUrl,
} from "./truenas.ts";

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
async function rejects(fn: () => Promise<unknown>, re: RegExp): Promise<void> {
  try {
    await fn();
  } catch (e) {
    assert(
      re.test((e as Error).message),
      `expected /${re.source}/, got: ${(e as Error).message}`,
    );
    return;
  }
  throw new Error(`expected rejection matching /${re.source}/`);
}

const GLOBALS = {
  endpoint: "wss://nas.test/api/current",
  apiKey: "test-key",
  timeoutMs: 5000,
};

type Call = { method: string; params: unknown[] };

/**
 * A fake session. `respond(method, params)` returns the canned result for a call;
 * throwing inside it becomes a rejected promise (mirrors the real transport).
 */
function makeFakeSession(
  respond: (method: string, params: unknown[]) => unknown,
) {
  const calls: Call[] = [];
  let closed = false;
  const session: RpcSession = {
    call(method, params) {
      calls.push({ method, params });
      try {
        return Promise.resolve(respond(method, params));
      } catch (e) {
        return Promise.reject(e);
      }
    },
    close() {
      closed = true;
    },
  };
  const factory: SessionFactory = (_g: Json) => Promise.resolve(session);
  return {
    factory,
    calls,
    isClosed: () => closed,
    methods: () => calls.map((c) => c.method),
  };
}

function makeContext() {
  const written: Array<
    { specName: string; name: string; data: Record<string, unknown> }
  > = [];
  const logs: Array<{ msg: string; props?: unknown }> = [];
  const noop = () => {};
  const context = {
    globalArgs: GLOBALS,
    logger: {
      info: (msg: string, props?: unknown) => logs.push({ msg, props }),
      debug: noop,
      warning: noop,
      error: noop,
    },
    writeResource: (
      specName: string,
      name: string,
      data: Record<string, unknown>,
    ) => {
      // Every write must follow the naming rule: swamp keys data by model +
      // name, so the name carries the spec, and it must be a name swamp accepts.
      assert(
        name === specName || name.startsWith(`${specName}:`),
        `data name ${name} must be ${specName} or start with ${specName}:`,
      );
      assert(
        !/[\/\\\0]|\.\./.test(name),
        `data name ${name} holds a character swamp rejects`,
      );
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
const method = (name: string): MethodDef =>
  (model.methods as unknown as Record<string, MethodDef>)[name];
const find = (calls: Call[], m: string): Call | undefined =>
  calls.find((c) => c.method === m);

// ─────────────────────────── websocketUrl (the revoke guard) ───────────────────────────

Deno.test("websocketUrl: bare host becomes wss://host/api/current", () => {
  assertEquals(
    websocketUrl("nas.example.com"),
    "wss://nas.example.com/api/current",
  );
});

Deno.test("websocketUrl: https is upgraded to wss on the default path", () => {
  assertEquals(
    websocketUrl("https://nas.example.com"),
    "wss://nas.example.com/api/current",
  );
  assertEquals(
    websocketUrl("wss://nas.example.com/"),
    "wss://nas.example.com/api/current",
  );
});

Deno.test("websocketUrl: keeps an explicit wss path", () => {
  assertEquals(
    websocketUrl("wss://nas.example.com/api/v25.04.2"),
    "wss://nas.example.com/api/v25.04.2",
  );
});

Deno.test("websocketUrl: REJECTS ws:// (cleartext revokes the key)", () => {
  let threw = false;
  try {
    websocketUrl("ws://nas.example.com/api/current");
  } catch (e) {
    threw = true;
    assert(/non-TLS|cleartext/i.test((e as Error).message));
  }
  assert(threw, "ws:// must throw");
});

Deno.test("websocketUrl: REJECTS ws:// and http:// without a path too", () => {
  for (const endpoint of ["ws://nas.example.com", "http://nas.example.com/"]) {
    let threw = false;
    try {
      websocketUrl(endpoint);
    } catch {
      threw = true;
    }
    assert(threw, `${endpoint} must throw`);
  }
});

Deno.test("websocketUrl: REJECTS http://", () => {
  let threw = false;
  try {
    websocketUrl("http://nas.example.com");
  } catch {
    threw = true;
  }
  assert(threw, "http:// must throw");
});

// ─────────────────────────── app_list ───────────────────────────

const LLDAP_APP = {
  name: "lldap",
  state: "RUNNING",
  custom_app: false,
  version: "1.0",
  human_version: "lldap_1.0",
  config: {
    network: {
      host_network: false,
      networks: [],
      http_port: {
        bind_mode: "published",
        host_ips: ["0.0.0.0"],
        port_number: 30325,
      },
      ldap_port: {
        bind_mode: "published",
        host_ips: ["0.0.0.0"],
        port_number: 389,
      },
      ldaps_port: {
        bind_mode: "published",
        host_ips: ["0.0.0.0"],
        port_number: 636,
        certificate_id: 1,
      },
    },
  },
};

Deno.test("app_list: factory shapes one app per result, sorted port bindings", async () => {
  const fake = makeFakeSession((
    m,
  ) => (m === "app.query" ? [LLDAP_APP] : undefined));
  __setTruenasSession(fake.factory);
  try {
    const { context, written } = makeContext();
    await method("app_list").execute({}, context);
    assertEquals(written.length, 1);
    const app = written[0].data;
    assertEquals(written[0].specName, "app");
    assertEquals(written[0].name, "app:lldap");
    assertEquals(app.hostNetwork, false);
    const ports = app.portBindings as Array<Record<string, unknown>>;
    assertEquals(ports.map((p) => p.portNumber), [389, 636, 30325]);
    const ldap = ports.find((p) => p.portKey === "ldap_port")!;
    assertEquals(ldap.published, true);
    assertEquals(ldap.exposedToAll, true);
    assert(fake.isClosed(), "session must be closed");
  } finally {
    __setTruenasSession(null);
  }
});

// A custom (ix-app) app: ports are an unkeyed top-level list, host_network is
// top-level too (truenas/apps ix-dev/stable/ix-app/questions.yaml).
// An app installed with the UI's "Custom App" form: the `ix-app` catalog app, so
// `custom_app` is false. `custom_app: true` marks an app installed from compose YAML.
const CUSTOM_APP = {
  name: "kopia",
  state: "RUNNING",
  custom_app: false,
  config: {
    host_network: false,
    ports: [
      {
        bind_mode: "published",
        port_number: 51515,
        container_port: 51515,
        protocol: "tcp",
        host_ips: [],
      },
      {
        bind_mode: "exposed",
        port_number: 51516,
        container_port: 51516,
        protocol: "udp",
        host_ips: [],
      },
    ],
  },
};

Deno.test("app_list: shapes a custom app's config.ports list and top-level host_network", async () => {
  const hostNetApp = {
    name: "hostnet",
    custom_app: false,
    config: { host_network: true, ports: [] },
  };
  const fake = makeFakeSession((
    m,
  ) => (m === "app.query" ? [CUSTOM_APP, hostNetApp] : undefined));
  __setTruenasSession(fake.factory);
  try {
    const { context, written } = makeContext();
    await method("app_list").execute({}, context);
    const kopia = written.find((w) => w.name === "app:kopia")!.data;
    assertEquals(kopia.hostNetwork, false);
    assertEquals(kopia.portBindings, [
      {
        portKey: "ports[0]",
        portNumber: 51515,
        protocol: "tcp",
        bindMode: "published",
        hostIps: [],
        published: true,
        exposedToAll: true,
      },
      {
        portKey: "ports[1]",
        portNumber: 51516,
        protocol: "udp",
        bindMode: "exposed",
        hostIps: [],
        published: false,
        exposedToAll: false,
      },
    ]);
    const hostnet = written.find((w) => w.name === "app:hostnet")!.data;
    assertEquals(hostnet.hostNetwork, true);
  } finally {
    __setTruenasSession(null);
  }
});

Deno.test("app_list: empty host IPs and :: count as all interfaces, a LAN IP does not", async () => {
  const port = (port_number: number, host_ips: string[]) => ({
    bind_mode: "published",
    port_number,
    host_ips,
  });
  const app = {
    name: "web",
    config: {
      network: {
        a: port(1001, []),
        b: port(1002, ["::"]),
        c: port(1003, ["0.0.0.0"]),
        d: port(1004, ["192.0.2.252"]),
      },
    },
  };
  const fake = makeFakeSession((m) => (m === "app.query" ? [app] : undefined));
  __setTruenasSession(fake.factory);
  try {
    const { context, written } = makeContext();
    await method("app_list").execute({}, context);
    const ports = written[0].data.portBindings as Array<
      Record<string, unknown>
    >;
    assertEquals(ports.map((p) => [p.portNumber, p.exposedToAll]), [
      [1001, true],
      [1002, true],
      [1003, true],
      [1004, false],
    ]);
  } finally {
    __setTruenasSession(null);
  }
});

// ─────────────────────────── filesystem_list ───────────────────────────

Deno.test("filesystem_list: shapes entries, sorts them, flags truncation", async () => {
  const fake = makeFakeSession((m) =>
    m === "filesystem.listdir"
      ? [
        { name: "offsite", type: "DIRECTORY", size: 4096, is_mountpoint: true },
        { name: "app-config", type: "DIRECTORY", size: 4096 },
      ]
      : undefined
  );
  __setTruenasSession(fake.factory);
  try {
    const { context, written } = makeContext();
    await method("filesystem_list").execute(
      { path: "/mnt/tank/backup", maxEntries: 1 },
      context,
    );
    assertEquals(written[0].specName, "dir-listing");
    assertEquals(written[0].name, "dir-listing:%2Fmnt%2Ftank%2Fbackup");
    const l = written[0].data;
    assertEquals(l.exists, true);
    assertEquals(l.truncated, true, "maxEntries=1 of 2 entries");
    assertEquals(
      (l.entries as Array<Record<string, unknown>>).map((e) => e.name),
      ["app-config"],
      "entries sort by name",
    );
    assertEquals(find(fake.calls, "filesystem.listdir")!.params, [
      "/mnt/tank/backup",
    ]);
    assert(fake.isClosed(), "session must be closed");
  } finally {
    __setTruenasSession(null);
  }
});

Deno.test("filesystem_list: an absent path is data (exists=false), not a failure", async () => {
  const fake = makeFakeSession(() => {
    throw new Error("[ENOENT] /mnt/Backup/apps/paperless does not exist");
  });
  __setTruenasSession(fake.factory);
  try {
    const { context, written } = makeContext();
    await method("filesystem_list").execute(
      { path: "/mnt/Backup/apps/paperless", maxEntries: 500 },
      context,
    );
    const l = written[0].data;
    assertEquals(l.exists, false);
    assertEquals(l.entryCount, 0);
    assert(/ENOENT/.test(String(l.error)), "records the listdir error");
  } finally {
    __setTruenasSession(null);
  }
});

Deno.test("filesystem_list: a JSON-string path list is decoded (CLI --input form)", async () => {
  const fake = makeFakeSession((
    m,
  ) => (m === "filesystem.listdir" ? [] : undefined));
  __setTruenasSession(fake.factory);
  try {
    const { context, written } = makeContext();
    await method("filesystem_list").execute(
      { path: '["/mnt/Backup","/mnt/Backup/apps"]', maxEntries: 500 },
      context,
    );
    assertEquals(written.length, 2, "the JSON blob must not become one path");
    assertEquals(
      fake.calls.map((c) => c.params[0]),
      ["/mnt/Backup", "/mnt/Backup/apps"],
    );
  } finally {
    __setTruenasSession(null);
  }
});

Deno.test("app_storage: finds host paths wherever the app config puts them", async () => {
  const fake = makeFakeSession((m) =>
    m === "app.query"
      ? [{
        name: "kopia",
        config: {
          storage: {
            config: {
              type: "host_path",
              mount_path: "/app/config",
              host_path_config: { path: "/mnt/tank/apps/kopia" },
            },
            additional_storage: [
              {
                type: "host_path",
                mount_path: "/data/backup",
                read_only: true,
                host_path_config: { path: "/mnt/Backup" },
              },
            ],
          },
          // A non-host_path entry must not be collected.
          cache: { type: "ix_volume", mount_path: "/app/cache" },
        },
      }]
      : undefined
  );
  __setTruenasSession(fake.factory);
  try {
    const { context, written } = makeContext();
    await method("app_storage").execute({ app: "kopia" }, context);
    assertEquals(written[0].specName, "app-storage");
    assertEquals(
      written[0].name,
      "app-storage:kopia",
      "a bare app name would clobber app_list's `app` record",
    );
    assertEquals(written[0].data.mountCount, 2, "ix_volume is not a host path");
    const mounts = written[0].data.mounts as Array<Record<string, unknown>>;
    assertEquals(mounts.map((m) => m.mountPath), [
      "/app/config",
      "/data/backup",
    ]);
    assertEquals(mounts[1].hostPath, "/mnt/Backup");
    assertEquals(mounts[1].readOnly, true);
    assertEquals(mounts[1].configPath, "storage.additional_storage[0]");
    assertEquals(find(fake.calls, "app.query")!.params[0], [[
      "name",
      "=",
      "kopia",
    ]]);
  } finally {
    __setTruenasSession(null);
  }
});

Deno.test("app_storage: unknown app is an error, not an empty result", async () => {
  const fake = makeFakeSession((m) => (m === "app.query" ? [] : undefined));
  __setTruenasSession(fake.factory);
  try {
    const { context } = makeContext();
    await rejects(
      () => method("app_storage").execute({ app: "nope" }, context),
      /not found/,
    );
  } finally {
    __setTruenasSession(null);
  }
});

Deno.test("replication_list: instance names are PREFIXED (no nfs/smb id collision)", async () => {
  const fake = makeFakeSession((m) =>
    m === "replication.query"
      ? [{
        id: 3,
        name: "Apps - Backup",
        direction: "PUSH",
        transport: "LOCAL",
        enabled: true,
        auto: true,
        recursive: true,
        source_datasets: ["tank/apps"],
        target_dataset: "Backup/apps",
        readonly: "SET",
        properties: true,
        state: { state: "FINISHED", datetime: { $date: 1785585769000 } },
      }]
      : undefined
  );
  __setTruenasSession(fake.factory);
  try {
    const { context, written } = makeContext();
    await method("replication_list").execute({}, context);
    assertEquals(written[0].specName, "replication-task");
    assertEquals(
      written[0].name,
      "replication-task:3",
      "a bare id would clobber nfs-share 3",
    );
    const t = written[0].data;
    assertEquals(t.recursive, true);
    assertEquals(t.sendsProperties, true);
    assertEquals(t.readonlyPolicy, "SET");
    assertEquals(t.lastRunAt, "2026-08-01T12:02:49.000Z", "{$date} → ISO");
  } finally {
    __setTruenasSession(null);
  }
});

Deno.test("filesystem_list: a LIST of paths fans out over one session", async () => {
  const fake = makeFakeSession((m, p) => {
    if (m !== "filesystem.listdir") return undefined;
    if (p[0] === "/mnt/Backup/apps") {
      return [{ name: "paperless", type: "DIRECTORY", is_mountpoint: true }];
    }
    throw new Error("[ENOENT] does not exist");
  });
  __setTruenasSession(fake.factory);
  try {
    const { context, written } = makeContext();
    await method("filesystem_list").execute(
      { path: ["/mnt/Backup/apps", "/mnt/Backup/nope"], maxEntries: 500 },
      context,
    );
    assertEquals(written.length, 2, "one dir-listing per path");
    assertEquals(written.map((w) => w.name), [
      "dir-listing:%2Fmnt%2FBackup%2Fapps",
      "dir-listing:%2Fmnt%2FBackup%2Fnope",
    ]);
    assertEquals(written[0].data.exists, true);
    assertEquals(
      written[1].data.exists,
      false,
      "ENOENT doesn't abort the fan-out",
    );
    assertEquals(
      fake.calls.filter((c) => c.method === "filesystem.listdir").length,
      2,
    );
  } finally {
    __setTruenasSession(null);
  }
});

Deno.test("filesystem_list: a NON-ENOENT error still fails loudly", async () => {
  const fake = makeFakeSession(() => {
    throw new Error("[EACCES] permission denied");
  });
  __setTruenasSession(fake.factory);
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("filesystem_list").execute(
          { path: "/mnt/Backup", maxEntries: 500 },
          context,
        ),
      /EACCES/,
    );
  } finally {
    __setTruenasSession(null);
  }
});

// ─────────────────────────── exposure_audit ───────────────────────────

const LAN_ONLY_APP = {
  name: "lan",
  config: {
    network: {
      web_port: {
        bind_mode: "published",
        host_ips: ["192.0.2.252"],
        port_number: 8080,
      },
    },
  },
};

Deno.test("exposure_audit: flags plaintext LDAP + all-interface ports + unrestricted shares", async () => {
  const fake = makeFakeSession((m) => {
    switch (m) {
      case "system.info":
        return { hostname: "truenas", version: "25.04.2.6" };
      case "app.query":
        return [LLDAP_APP, CUSTOM_APP, LAN_ONLY_APP];
      case "sharing.nfs.query":
        return [
          {
            id: 1,
            path: "/mnt/a",
            networks: ["192.0.2.0/24"],
            hosts: [],
            enabled: true,
            ro: false,
          },
          {
            id: 2,
            path: "/mnt/open",
            networks: [],
            hosts: [],
            enabled: true,
            ro: false,
          },
        ];
      case "sharing.smb.query":
        return [{
          id: 1,
          name: "Open",
          path: "/mnt/s",
          hostsallow: [],
          hostsdeny: [],
          enabled: true,
          ro: false,
        }];
      case "interface.ip_in_use":
        return [{ address: "192.0.2.252", netmask: 24 }];
      default:
        return undefined;
    }
  });
  __setTruenasSession(fake.factory);
  try {
    const { context, written } = makeContext();
    await method("exposure_audit").execute({}, context);
    const a = written[0].data;
    assertEquals(written[0].specName, "exposure-audit");
    const flags = a.flags as Record<string, unknown>;
    assertEquals(flags.plaintextLdapPublished, true);
    // 51515 is a custom app's list-form port with empty host IPs; 8080 is bound
    // to one LAN IP only, so it is published but not on every interface.
    assertEquals(flags.portsOnAllInterfaces, [389, 636, 30325, 51515]);
    assertEquals(flags.nonWildcardBindableIps, ["192.0.2.252"]);
    assertEquals(a.unrestrictedNfsShares, ["/mnt/open"]);
    assertEquals(a.unrestrictedSmbShares, ["Open"]);
    assertEquals(
      (a.publishedPorts as Array<Record<string, unknown>>).map((p) => [
        p.source,
        p.portNumber,
      ]),
      [
        ["app:lldap", 389],
        ["app:lldap", 636],
        ["app:lan", 8080],
        ["app:lldap", 30325],
        ["app:kopia", 51515],
      ],
    );
  } finally {
    __setTruenasSession(null);
  }
});

// ─────────────────────────── app_set_port_bind ───────────────────────────

Deno.test("app_set_port_bind: closes a port (published→exposed), sends FULL network, waits job", async () => {
  let updated = false;
  const fake = makeFakeSession((m, params) => {
    if (m === "app.query") {
      // After the update, report ldap_port as exposed.
      const app = structuredClone(LLDAP_APP);
      if (updated) {
        (app.config.network.ldap_port as Record<string, unknown>).bind_mode =
          "exposed";
      }
      return [app];
    }
    if (m === "app.update") {
      updated = true;
      // Assert the patch carries the FULL network (all 3 ports), with ldap exposed.
      const values = (params[1] as {
        values: { network: Record<string, Record<string, unknown>> };
      }).values;
      const net = values.network;
      assert(
        net.http_port && net.ldaps_port && net.ldap_port,
        "must send all sibling ports",
      );
      assertEquals(net.ldap_port.bind_mode, "exposed");
      assertEquals(net.ldaps_port.certificate_id, 1, "ldaps cert must survive");
      return 42; // job id
    }
    if (m === "core.get_jobs") {
      return [{ id: 42, state: "SUCCESS", result: null }];
    }
    return undefined;
  });
  __setTruenasSession(fake.factory);
  try {
    const { context, written } = makeContext();
    await method("app_set_port_bind").execute(
      { app: "lldap", portKey: "ldap_port", bindMode: "exposed" },
      context,
    );
    const r = written[0].data;
    assertEquals(r.action, "updated");
    assertEquals(r.previousBindMode, "published");
    assertEquals(r.bindMode, "exposed");
    assert(find(fake.calls, "app.update"), "app.update must be called");
    assert(find(fake.calls, "core.get_jobs"), "job must be waited on");
  } finally {
    __setTruenasSession(null);
  }
});

Deno.test("app_set_port_bind: handles the config.ports LIST form (e.g. kopia)", async () => {
  const KOPIA = {
    name: "kopia",
    config: {
      ports: [
        {
          bind_mode: "published",
          container_port: 51515,
          host_ips: [],
          port_number: 51515,
          protocol: "tcp",
        },
      ],
    },
  };
  let updated = false;
  let sentPorts: unknown = null;
  const fake = makeFakeSession((m, params) => {
    if (m === "app.query") {
      const app = structuredClone(KOPIA);
      if (updated) app.config.ports[0].bind_mode = "exposed";
      return [app];
    }
    if (m === "app.update") {
      updated = true;
      sentPorts = (params[1] as { values: { ports: unknown } }).values.ports;
      return 7;
    }
    if (m === "core.get_jobs") {
      return [{ id: 7, state: "SUCCESS", result: null }];
    }
    return undefined;
  });
  __setTruenasSession(fake.factory);
  try {
    const { context, written } = makeContext();
    await method("app_set_port_bind").execute(
      { app: "kopia", portNumber: 51515, bindMode: "exposed" },
      context,
    );
    const sp = sentPorts as Array<Record<string, unknown>>;
    assert(
      Array.isArray(sp) && sp[0].bind_mode === "exposed",
      "must send the ports LIST with the entry exposed",
    );
    const r = written[0].data;
    assertEquals(r.action, "updated");
    assertEquals(r.previousBindMode, "published");
    assertEquals(r.bindMode, "exposed");
    assertEquals(r.portNumber, 51515);
  } finally {
    __setTruenasSession(null);
  }
});

Deno.test("app_set_port_bind: selects port by number when portKey omitted", async () => {
  const fake = makeFakeSession((m) => {
    if (m === "app.query") return [LLDAP_APP];
    if (m === "app.update") return 7;
    if (m === "core.get_jobs") return [{ id: 7, state: "SUCCESS" }];
    return undefined;
  });
  __setTruenasSession(fake.factory);
  try {
    const { context, written } = makeContext();
    await method("app_set_port_bind").execute({
      app: "lldap",
      portNumber: 636,
      bindMode: "exposed",
    }, context);
    assertEquals(written[0].data.portKey, "ldaps_port");
  } finally {
    __setTruenasSession(null);
  }
});

Deno.test("app_set_port_bind: no-op when already at desired state (no app.update)", async () => {
  const fake = makeFakeSession((
    m,
  ) => (m === "app.query" ? [LLDAP_APP] : undefined));
  __setTruenasSession(fake.factory);
  try {
    const { context, written } = makeContext();
    await method("app_set_port_bind").execute(
      { app: "lldap", portKey: "ldap_port", bindMode: "published" },
      context,
    );
    assertEquals(written[0].data.action, "unchanged");
    assert(!find(fake.calls, "app.update"), "must NOT update when unchanged");
  } finally {
    __setTruenasSession(null);
  }
});

Deno.test("app_set_port_bind: throws on unknown app (verify-first)", async () => {
  const fake = makeFakeSession((m) => (m === "app.query" ? [] : undefined));
  __setTruenasSession(fake.factory);
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("app_set_port_bind").execute({
          app: "ghost",
          portKey: "x",
          bindMode: "exposed",
        }, context),
      /not found/,
    );
  } finally {
    __setTruenasSession(null);
  }
});

Deno.test("app_set_port_bind: throws on FAILED job", async () => {
  const fake = makeFakeSession((m) => {
    if (m === "app.query") return [LLDAP_APP];
    if (m === "app.update") return 9;
    if (m === "core.get_jobs") {
      return [{ id: 9, state: "FAILED", error: "boom" }];
    }
    return undefined;
  });
  __setTruenasSession(fake.factory);
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("app_set_port_bind").execute({
          app: "lldap",
          portKey: "ldap_port",
          bindMode: "exposed",
        }, context),
      /FAILED|boom/,
    );
  } finally {
    __setTruenasSession(null);
  }
});

// ─────────────────────────── nfs_share_set_access ───────────────────────────

Deno.test("nfs_share_set_access: sets networks, re-reads, records previous", async () => {
  const before = {
    id: 1,
    path: "/mnt/a",
    networks: ["192.0.2.0/24"],
    hosts: [],
    enabled: true,
    ro: false,
  };
  const after = {
    ...before,
    networks: ["192.0.2.161/32", "192.0.2.162/32"],
  };
  let done = false;
  const fake = makeFakeSession((m, params) => {
    if (m === "sharing.nfs.query") return [done ? after : before];
    if (m === "sharing.nfs.update") {
      done = true;
      const body = params[1] as Record<string, unknown>;
      assertEquals(body.networks, ["192.0.2.161/32", "192.0.2.162/32"]);
      return after;
    }
    return undefined;
  });
  __setTruenasSession(fake.factory);
  try {
    const { context, written } = makeContext();
    await method("nfs_share_set_access").execute(
      { id: 1, networks: ["192.0.2.161/32", "192.0.2.162/32"] },
      context,
    );
    const r = written[0].data;
    assertEquals(r.action, "updated");
    assertEquals(r.previousNetworks, ["192.0.2.0/24"]);
    assertEquals(r.networks, ["192.0.2.161/32", "192.0.2.162/32"]);
  } finally {
    __setTruenasSession(null);
  }
});

Deno.test("nfs_share_set_access: ambiguous path is rejected", async () => {
  const fake = makeFakeSession((m) =>
    m === "sharing.nfs.query"
      ? [{ id: 1, path: "/mnt/a" }, { id: 2, path: "/mnt/a" }]
      : undefined
  );
  __setTruenasSession(fake.factory);
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("nfs_share_set_access").execute(
          { path: "/mnt/a", hosts: ["x"] },
          context,
        ),
      /ambiguous/,
    );
  } finally {
    __setTruenasSession(null);
  }
});

// ─────────────────────────── app_set_networks ───────────────────────────

Deno.test("app_set_networks: adds bridges, preserves existing config, sends full list", async () => {
  const before = {
    name: "caddy",
    config: {
      networks: [
        { name: "ix-scrutiny_default", config: { aliases: ["keepme"] } },
      ],
    },
  };
  const after = {
    name: "caddy",
    config: {
      networks: [
        { name: "ix-scrutiny_default", config: { aliases: ["keepme"] } },
        { name: "ix-lldap_default", config: {} },
      ],
    },
  };
  let sent: Array<{ name: string; config: { aliases?: string[] } }> = [];
  let done = false;
  const fake = makeFakeSession((m, params) => {
    if (m === "app.query") return [done ? after : before];
    if (m === "app.update") {
      done = true;
      sent = (params[1] as { values: { networks: typeof sent } }).values
        .networks;
      return 123; // job id
    }
    if (m === "core.get_jobs") {
      return [{ id: 123, state: "SUCCESS", result: null }];
    }
    return undefined;
  });
  __setTruenasSession(fake.factory);
  try {
    const { context, written } = makeContext();
    await method("app_set_networks").execute(
      { app: "caddy", networks: ["ix-scrutiny_default", "ix-lldap_default"] },
      context,
    );
    // full list sent, existing entry's config preserved, new one gets default
    assertEquals(sent.length, 2);
    assertEquals(sent[0].name, "ix-scrutiny_default");
    assertEquals(sent[0].config.aliases, ["keepme"]);
    assertEquals(sent[1].name, "ix-lldap_default");
    const r = written[0].data;
    assertEquals(r.action, "updated");
    assertEquals(r.previousNetworks, ["ix-scrutiny_default"]);
    assertEquals(r.networks, ["ix-scrutiny_default", "ix-lldap_default"]);
  } finally {
    __setTruenasSession(null);
  }
});

Deno.test("app_set_networks: no-op when the set already matches", async () => {
  const app = {
    name: "caddy",
    config: { networks: [{ name: "ix-scrutiny_default", config: {} }] },
  };
  let updateCalled = false;
  const fake = makeFakeSession((m) => {
    if (m === "app.query") return [app];
    if (m === "app.update") {
      updateCalled = true;
      return 1;
    }
    return undefined;
  });
  __setTruenasSession(fake.factory);
  try {
    const { context, written } = makeContext();
    await method("app_set_networks").execute(
      { app: "caddy", networks: ["ix-scrutiny_default"] },
      context,
    );
    assertEquals(updateCalled, false, "must not update when unchanged");
    assertEquals(written[0].data.action, "unchanged");
  } finally {
    __setTruenasSession(null);
  }
});

Deno.test("app_set_networks: refuses a catalog app and sends no update", async () => {
  // Catalog apps keep networks at network.networks with per-container entries.
  const app = {
    name: "lldap",
    custom_app: false,
    config: {
      network: {
        networks: [
          {
            name: "ix-caddy_default",
            containers: [{ name: "lldap", config: {} }],
          },
        ],
      },
    },
  };
  const fake = makeFakeSession((m) => {
    if (m === "app.query") return [app];
    if (m === "app.update") return 1;
    return undefined;
  });
  __setTruenasSession(fake.factory);
  try {
    const { context, written } = makeContext();
    await rejects(
      () =>
        method("app_set_networks").execute(
          { app: "lldap", networks: ["ix-caddy_default"] },
          context,
        ),
      /custom apps only/,
    );
    assertEquals(find(fake.calls, "app.update"), undefined);
    assertEquals(written.length, 0);
  } finally {
    __setTruenasSession(null);
  }
});

// ─────────────────────────── nfs_share_delete ───────────────────────────

Deno.test("nfs_share_delete: removes the export and records its prior config", async () => {
  const share = {
    id: 9,
    path: "/mnt/tank/apps/git",
    networks: ["192.0.2.161/32", "192.0.2.162/32"],
    hosts: [],
    enabled: true,
  };
  let deletedId: unknown = null;
  const fake = makeFakeSession((m, params) => {
    if (m === "sharing.nfs.query") return [share];
    if (m === "sharing.nfs.delete") {
      deletedId = params[0];
      return true;
    }
    return undefined;
  });
  __setTruenasSession(fake.factory);
  try {
    const { context, written } = makeContext();
    await method("nfs_share_delete").execute({ id: 9 }, context);
    assertEquals(deletedId, 9, "must call sharing.nfs.delete with the id");
    const r = written[0].data;
    assertEquals(r.action, "deleted");
    assertEquals(r.path, "/mnt/tank/apps/git");
    assertEquals(r.previousNetworks, [
      "192.0.2.161/32",
      "192.0.2.162/32",
    ]);
    assertEquals(r.networks, []);
  } finally {
    __setTruenasSession(null);
  }
});

Deno.test("nfs_share_delete: refuses when confirmPath mismatches", async () => {
  let deleteCalled = false;
  const fake = makeFakeSession((m) => {
    if (m === "sharing.nfs.query") {
      return [{ id: 9, path: "/mnt/tank/apps/git" }];
    }
    if (m === "sharing.nfs.delete") {
      deleteCalled = true;
      return true;
    }
    return undefined;
  });
  __setTruenasSession(fake.factory);
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("nfs_share_delete").execute(
          { id: 9, confirmPath: "/mnt/tank/apps/WRONG" },
          context,
        ),
      /does not match/,
    );
    assertEquals(
      deleteCalled,
      false,
      "must NOT delete on a confirmPath mismatch",
    );
  } finally {
    __setTruenasSession(null);
  }
});

Deno.test("nfs_share_delete: already-absent share succeeds with action=absent (idempotent)", async () => {
  let deleteCalled = false;
  const fake = makeFakeSession((m) => {
    if (m === "sharing.nfs.query") return []; // nothing matches: already gone
    if (m === "sharing.nfs.delete") {
      deleteCalled = true;
      return true;
    }
    return undefined;
  });
  __setTruenasSession(fake.factory);
  try {
    const { context, written } = makeContext();
    await method("nfs_share_delete").execute({ id: 9 }, context);
    assertEquals(
      deleteCalled,
      false,
      "must NOT call delete when nothing matches",
    );
    const r = written[0].data;
    assertEquals(r.action, "absent");
    assertEquals(r.id, 9);
    assertEquals(
      written[0].name,
      "nfs-share-result:absent:9",
      "by id: not the deleted record's name, so a rerun leaves the removed config as latest",
    );
  } finally {
    __setTruenasSession(null);
  }
});

Deno.test("nfs_share_delete: absent share selected by path gets an escaped, tagged data name", async () => {
  const fake = makeFakeSession((
    m,
  ) => (m === "sharing.nfs.query" ? [] : undefined));
  __setTruenasSession(fake.factory);
  try {
    const { context, written } = makeContext();
    await method("nfs_share_delete").execute(
      { path: "/mnt/tank/old" },
      context,
    );
    assertEquals(
      written[0].name,
      "nfs-share-result:absent:path:%2Fmnt%2Ftank%2Fold",
      "tagged path: so it can never take the name of a share id",
    );
    assertEquals(written[0].data.path, "/mnt/tank/old");
    assertEquals(written[0].data.action, "absent");
    // No share, so no id: null rather than a 0 that reads like a real one.
    assertEquals(written[0].data.id, null);
    assert(
      model.resources["nfs-share-result"].schema.safeParse(written[0].data)
        .success,
      "the absent result must match its schema",
    );
  } finally {
    __setTruenasSession(null);
  }
});

// ─────────────────────────── smb_share_delete ───────────────────────────

Deno.test("smb_share_delete: removes the share and records its prior config", async () => {
  const share = {
    id: 6,
    name: "Music",
    path: "/mnt/tank/Music",
    hostsallow: ["100.64.0.0/10"],
    hostsdeny: [],
    purpose: "NO_PRESET",
    enabled: true,
  };
  let deletedId: unknown = null;
  const fake = makeFakeSession((m, params) => {
    if (m === "sharing.smb.query") return [share];
    if (m === "sharing.smb.delete") {
      deletedId = params[0];
      return true;
    }
    return undefined;
  });
  __setTruenasSession(fake.factory);
  try {
    const { context, written } = makeContext();
    await method("smb_share_delete").execute({ id: 6 }, context);
    assertEquals(deletedId, 6, "must call sharing.smb.delete with the id");
    const r = written[0].data;
    assertEquals(r.action, "deleted");
    assertEquals(r.name, "Music");
    // The share list record expires after an hour; this one must still say
    // where the share pointed, to re-create it.
    assertEquals(r.path, "/mnt/tank/Music");
    assertEquals(r.previousHostsallow, ["100.64.0.0/10"]);
    assertEquals(r.hostsallow, []);
  } finally {
    __setTruenasSession(null);
  }
});

Deno.test("smb_share_delete: refuses when confirmName mismatches", async () => {
  let deleteCalled = false;
  const fake = makeFakeSession((m) => {
    if (m === "sharing.smb.query") {
      return [{ id: 6, name: "Music", path: "/mnt/tank/Music" }];
    }
    if (m === "sharing.smb.delete") {
      deleteCalled = true;
      return true;
    }
    return undefined;
  });
  __setTruenasSession(fake.factory);
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("smb_share_delete").execute(
          { id: 6, confirmName: "WRONG" },
          context,
        ),
      /does not match/,
    );
    assertEquals(
      deleteCalled,
      false,
      "must NOT delete on a confirmName mismatch",
    );
  } finally {
    __setTruenasSession(null);
  }
});

Deno.test("smb_share_delete: already-absent share succeeds with action=absent (idempotent)", async () => {
  let deleteCalled = false;
  const fake = makeFakeSession((m) => {
    if (m === "sharing.smb.query") return []; // nothing matches: already gone
    if (m === "sharing.smb.delete") {
      deleteCalled = true;
      return true;
    }
    return undefined;
  });
  __setTruenasSession(fake.factory);
  try {
    const { context, written } = makeContext();
    await method("smb_share_delete").execute({ name: "Music" }, context);
    assertEquals(
      deleteCalled,
      false,
      "must NOT call delete when nothing matches",
    );
    const r = written[0].data;
    assertEquals(r.action, "absent");
    assertEquals(r.name, "Music");
    assertEquals(r.path, "", "no share, so no path");
  } finally {
    __setTruenasSession(null);
  }
});

Deno.test("smb_share_delete: absent share selected by name gets an escaped, tagged data name", async () => {
  const fake = makeFakeSession((
    m,
  ) => (m === "sharing.smb.query" ? [] : undefined));
  __setTruenasSession(fake.factory);
  try {
    const { context, written } = makeContext();
    await method("smb_share_delete").execute(
      { name: "Old Media/2019" },
      context,
    );
    assertEquals(
      written[0].name,
      "smb-share-result:absent:name:Old Media%2F2019",
    );
    assertEquals(written[0].data.name, "Old Media/2019");
    assertEquals(written[0].data.action, "absent");
    assertEquals(written[0].data.id, null);
    assert(
      model.resources["smb-share-result"].schema.safeParse(written[0].data)
        .success,
      "the absent result must match its schema",
    );

    const byId = makeContext();
    await method("smb_share_delete").execute({ id: 6 }, byId.context);
    assertEquals(
      byId.written[0].name,
      "smb-share-result:absent:6",
      "by id: not the deleted record's name, so a rerun leaves the removed config as latest",
    );
    assertEquals(byId.written[0].data.id, 6, "a selector id is kept");
  } finally {
    __setTruenasSession(null);
  }
});

// ─────────────────────────── smb_share_set_access ───────────────────────────

Deno.test("smb_share_set_access: sends only the access fields (update is a PATCH)", async () => {
  const before = {
    id: 3,
    name: "Media",
    path: "/mnt/m",
    hostsallow: [],
    hostsdeny: [],
    enabled: true,
    ro: false,
  };
  const after = { ...before, hostsallow: ["192.0.2.50"] };
  let done = false;
  const fake = makeFakeSession((m, params) => {
    if (m === "sharing.smb.query") return [done ? after : before];
    if (m === "sharing.smb.update") {
      done = true;
      const body = params[1] as Record<string, unknown>;
      // sharing.smb.update keeps omitted fields, so echoing name/path only
      // risks re-validating values that are not changing.
      assertEquals(body.name, undefined, "must not echo name");
      assertEquals(body.path, undefined, "must not echo path");
      assertEquals(body.purpose, undefined, "must not touch purpose");
      assertEquals(body.hostsallow, ["192.0.2.50"]);
      return after;
    }
    return undefined;
  });
  __setTruenasSession(fake.factory);
  try {
    const { context, written } = makeContext();
    await method("smb_share_set_access").execute({
      id: 3,
      hostsallow: ["192.0.2.50"],
    }, context);
    const r = written[0].data;
    assertEquals(r.action, "updated");
    assertEquals(r.previousHostsallow, []);
    assertEquals(r.hostsallow, ["192.0.2.50"]);
  } finally {
    __setTruenasSession(null);
  }
});

Deno.test("smb_share_set_access: releases a host-locking preset to NO_PRESET", async () => {
  // DEFAULT_SHARE re-applies empty hostsallow on every update, dropping the
  // allowlist; the method must move the share to NO_PRESET in the same update.
  const before = {
    id: 1,
    name: "Projects",
    path: "/mnt/p",
    purpose: "DEFAULT_SHARE",
    hostsallow: [],
    hostsdeny: [],
    enabled: true,
    ro: false,
  };
  const after = {
    ...before,
    purpose: "NO_PRESET",
    hostsallow: ["192.0.2.101"],
  };
  let done = false;
  let sentPurpose: unknown = "UNSET";
  const fake = makeFakeSession((m, params) => {
    if (m === "sharing.smb.query") return [done ? after : before];
    if (m === "sharing.smb.update") {
      done = true;
      sentPurpose = (params[1] as Record<string, unknown>).purpose;
      return after;
    }
    return undefined;
  });
  __setTruenasSession(fake.factory);
  try {
    const { context, written } = makeContext();
    await method("smb_share_set_access").execute({
      id: 1,
      hostsallow: ["192.0.2.101"],
    }, context);
    assertEquals(sentPurpose, "NO_PRESET", "must release the preset lock");
    const r = written[0].data;
    assertEquals(r.previousPurpose, "DEFAULT_SHARE");
    assertEquals(r.purpose, "NO_PRESET");
    assertEquals(r.hostsallow, ["192.0.2.101"]);
    assertEquals(r.path, "/mnt/p");
  } finally {
    __setTruenasSession(null);
  }
});

Deno.test("smb_share_set_access (25.04): refuses a Veeam share", async () => {
  // NO_PRESET drops the Veeam preset's `block size`, which Fast Clone needs
  // (25.04 util_smbconf.py applies preset parameters only off NO_PRESET).
  const share = {
    id: 2,
    name: "Veeam",
    path: "/mnt/v",
    purpose: "VEEAM_REPOSITORY_SHARE",
    hostsallow: [],
    hostsdeny: [],
    enabled: true,
    ro: false,
  };
  const fake = makeFakeSession((m) =>
    m === "sharing.smb.query" ? [share] : undefined
  );
  __setTruenasSession(fake.factory);
  try {
    const { context, written } = makeContext();
    await rejects(
      () =>
        method("smb_share_set_access").execute({
          id: 2,
          hostsallow: ["192.0.2.101"],
        }, context),
      /VEEAM_REPOSITORY_SHARE/,
    );
    assert(!fake.methods().includes("sharing.smb.update"));
    assertEquals(written.length, 0);
  } finally {
    __setTruenasSession(null);
  }
});

Deno.test("smb_share_set_access: leaves a non-locking preset untouched", async () => {
  // MULTI_PROTOCOL_NFS does not lock hostsallow, so the purpose must NOT be changed.
  const before = {
    id: 9,
    name: "stash",
    path: "/mnt/s",
    purpose: "MULTI_PROTOCOL_NFS",
    hostsallow: [],
    hostsdeny: [],
    enabled: true,
    ro: false,
  };
  const after = { ...before, hostsallow: ["192.0.2.101"] };
  let done = false;
  let purposeKeyPresent = true;
  const fake = makeFakeSession((m, params) => {
    if (m === "sharing.smb.query") return [done ? after : before];
    if (m === "sharing.smb.update") {
      done = true;
      purposeKeyPresent = "purpose" in (params[1] as Record<string, unknown>);
      return after;
    }
    return undefined;
  });
  __setTruenasSession(fake.factory);
  try {
    const { context, written } = makeContext();
    await method("smb_share_set_access").execute({
      id: 9,
      hostsallow: ["192.0.2.101"],
    }, context);
    assertEquals(
      purposeKeyPresent,
      false,
      "must not send purpose for a non-locking preset",
    );
    const r = written[0].data;
    assertEquals(r.previousPurpose, "MULTI_PROTOCOL_NFS");
    assertEquals(r.purpose, "MULTI_PROTOCOL_NFS");
  } finally {
    __setTruenasSession(null);
  }
});

// 25.10 rows carry the host lists under `options`; the shapes follow upstream
// `api/v25_10_0/smb.py` (LegacyOpt, DefaultOpt) and `v25_10_1/smb.py`.

Deno.test("smb_share_list (25.10): reads host lists from options and readonly", async () => {
  const fake = makeFakeSession((m) =>
    m === "sharing.smb.query"
      ? [
        {
          id: 1,
          name: "Legacy",
          path: "/mnt/l",
          enabled: true,
          readonly: true,
          purpose: "LEGACY_SHARE",
          options: {
            recyclebin: false,
            hostsallow: ["100.64.0.0/10"],
            hostsdeny: ["ALL"],
          },
        },
        {
          id: 2,
          name: "Default",
          path: "/mnt/d",
          enabled: true,
          readonly: false,
          purpose: "DEFAULT_SHARE",
          options: { aapl_name_mangling: false },
        },
      ]
      : undefined
  );
  __setTruenasSession(fake.factory);
  try {
    const { context, written } = makeContext();
    await method("smb_share_list").execute({}, context);
    const [legacy, def] = written.map((w) => w.data);
    assertEquals(
      [legacy.ro, legacy.hostsallow, legacy.hostsdeny, legacy.unrestricted],
      [true, ["100.64.0.0/10"], ["ALL"], false],
    );
    // A purpose without host lists admits every host.
    assertEquals([def.ro, def.hostsallow, def.unrestricted], [false, [], true]);
  } finally {
    __setTruenasSession(null);
  }
});

Deno.test("smb_share_set_access (25.10): merges the new lists into the existing options", async () => {
  // The update replaces the whole options object and defaults unsent fields, so
  // every existing option must be sent back alongside the purpose.
  const options = {
    recyclebin: true,
    auxsmbconf: "veto files = /.DS_Store/",
    hostsallow: ["100.64.0.0/10"],
    hostsdeny: [],
  };
  const before = {
    id: 4,
    name: "Assets",
    path: "/mnt/a",
    enabled: true,
    readonly: false,
    purpose: "LEGACY_SHARE",
    options,
  };
  const after = {
    ...before,
    options: { ...options, hostsallow: ["192.0.2.0/24"] },
  };
  let done = false;
  let sent: Record<string, unknown> = {};
  const fake = makeFakeSession((m, params) => {
    if (m === "sharing.smb.query") return [done ? after : before];
    if (m === "sharing.smb.update") {
      done = true;
      sent = params[1] as Record<string, unknown>;
      return after;
    }
    return undefined;
  });
  __setTruenasSession(fake.factory);
  try {
    const { context, written } = makeContext();
    await method("smb_share_set_access").execute({
      id: 4,
      hostsallow: ["192.0.2.0/24"],
    }, context);
    assertEquals(sent, {
      purpose: "LEGACY_SHARE",
      options: {
        recyclebin: true,
        auxsmbconf: "veto files = /.DS_Store/",
        hostsallow: ["192.0.2.0/24"],
        hostsdeny: [],
      },
    });
    const r = written[0].data;
    assertEquals(
      [r.action, r.previousHostsallow, r.hostsallow, r.purpose],
      ["updated", ["100.64.0.0/10"], ["192.0.2.0/24"], "LEGACY_SHARE"],
    );
  } finally {
    __setTruenasSession(null);
  }
});

Deno.test("smb_share_set_access (25.10.0): moves a DEFAULT_SHARE to LEGACY_SHARE", async () => {
  // On 25.10.0 DEFAULT_SHARE has no host lists; LEGACY_SHARE replaces NO_PRESET.
  const before = {
    id: 5,
    name: "Books",
    path: "/mnt/b",
    enabled: true,
    readonly: false,
    purpose: "DEFAULT_SHARE",
    options: { aapl_name_mangling: true },
  };
  const after = {
    ...before,
    purpose: "LEGACY_SHARE",
    options: { aapl_name_mangling: true, hostsallow: ["192.0.2.7"] },
  };
  let done = false;
  let sent: Record<string, unknown> = {};
  const fake = makeFakeSession((m, params) => {
    if (m === "sharing.smb.query") return [done ? after : before];
    if (m === "sharing.smb.update") {
      done = true;
      sent = params[1] as Record<string, unknown>;
      return after;
    }
    return undefined;
  });
  __setTruenasSession(fake.factory);
  try {
    const { context, written } = makeContext();
    await method("smb_share_set_access").execute({
      id: 5,
      hostsallow: ["192.0.2.7"],
    }, context);
    assertEquals(sent, {
      purpose: "LEGACY_SHARE",
      options: {
        aapl_name_mangling: true,
        hostsallow: ["192.0.2.7"],
        hostsdeny: [],
      },
    });
    const r = written[0].data;
    assertEquals(
      [r.previousPurpose, r.purpose, r.hostsallow],
      ["DEFAULT_SHARE", "LEGACY_SHARE", ["192.0.2.7"]],
    );
  } finally {
    __setTruenasSession(null);
  }
});

Deno.test("smb_share_set_access (25.10): refuses a purpose that holds no host lists", async () => {
  // Moving a Time Machine share to LEGACY_SHARE would drop Time Machine.
  const share = {
    id: 6,
    name: "TM",
    path: "/mnt/tm",
    enabled: true,
    readonly: false,
    purpose: "TIMEMACHINE_SHARE",
    options: { timemachine_quota: 0, auto_snapshot: false },
  };
  const fake = makeFakeSession((m) =>
    m === "sharing.smb.query" ? [share] : undefined
  );
  __setTruenasSession(fake.factory);
  try {
    const { context, written } = makeContext();
    let error = "";
    try {
      await method("smb_share_set_access").execute({
        id: 6,
        hostsallow: ["192.0.2.7"],
      }, context);
    } catch (e) {
      error = (e as Error).message;
    }
    assert(error.includes("TIMEMACHINE_SHARE"), `unexpected error: ${error}`);
    assert(
      !fake.methods().includes("sharing.smb.update"),
      "must not send an update",
    );
    assertEquals(written.length, 0);
  } finally {
    __setTruenasSession(null);
  }
});

Deno.test("smb_share_set_access (25.10): unchanged lists send nothing", async () => {
  const share = {
    id: 7,
    name: "Photos",
    path: "/mnt/ph",
    enabled: true,
    readonly: false,
    purpose: "LEGACY_SHARE",
    options: { hostsallow: ["100.64.0.0/10"], hostsdeny: [] },
  };
  const fake = makeFakeSession((m) =>
    m === "sharing.smb.query" ? [share] : undefined
  );
  __setTruenasSession(fake.factory);
  try {
    const { context, written } = makeContext();
    await method("smb_share_set_access").execute({
      id: 7,
      hostsallow: ["100.64.0.0/10"],
    }, context);
    assert(!fake.methods().includes("sharing.smb.update"));
    assertEquals(written[0].data.action, "unchanged");
  } finally {
    __setTruenasSession(null);
  }
});

// ─────────────────────────── secret non-leakage ───────────────────────────

Deno.test("no method logs the API key", async () => {
  const fake = makeFakeSession((
    m,
  ) => (m === "app.query" ? [LLDAP_APP] : undefined));
  __setTruenasSession(fake.factory);
  try {
    const { context, logs } = makeContext();
    await method("app_list").execute({}, context);
    const blob = JSON.stringify(logs);
    assert(!blob.includes(GLOBALS.apiKey), "API key must never appear in logs");
  } finally {
    __setTruenasSession(null);
  }
});

// ─────────────────────────── reachable check ───────────────────────────

type CheckDef = {
  execute: (
    context: { globalArgs: Record<string, unknown> },
  ) => Promise<{ pass: boolean; errors?: string[] }>;
};
const check = (name: string): CheckDef =>
  (model.checks as unknown as Record<string, CheckDef>)[name];

// A check receives globalArgs without the schema's defaults, so the fixture
// omits every defaulted setting to prove the check applies them itself.
Deno.test("reachable check applies the schema defaults to globalArgs", async () => {
  let seen: Record<string, unknown> | undefined;
  const fake = makeFakeSession((m) => (m === "system.info" ? {} : undefined));
  __setTruenasSession((g) => {
    seen = g;
    return fake.factory(g);
  });
  try {
    const r = await check("reachable").execute({
      globalArgs: { endpoint: GLOBALS.endpoint, apiKey: GLOBALS.apiKey },
    });
    assertEquals(r.pass, true);
    assertEquals(seen?.timeoutMs, 30000);
    assert(fake.isClosed(), "the probe session must be closed");
  } finally {
    __setTruenasSession(null);
  }
});

Deno.test("reachable check fails, not throws, when endpoint is omitted", async () => {
  let opened = false;
  __setTruenasSession((g) => {
    opened = true;
    return makeFakeSession(() => ({})).factory(g);
  });
  try {
    const r = await check("reachable").execute({
      globalArgs: { apiKey: GLOBALS.apiKey },
    });
    assertEquals(r.pass, false);
    assert(/endpoint/.test((r.errors ?? []).join(" ")), "must name the field");
    assertEquals(opened, false, "must not open a session without an endpoint");
  } finally {
    __setTruenasSession(null);
  }
});

// swamp names data per model, not per spec, and TrueNAS numbers NFS and SMB
// shares separately, so share 1 of each must not share a name.
Deno.test("nfs and smb shares with the same id get different data names", async () => {
  const fake = makeFakeSession((m) =>
    m === "sharing.nfs.query"
      ? [{ id: 1, path: "/mnt/a" }]
      : m === "sharing.smb.query"
      ? [{ id: 1, name: "a", path: "/mnt/a" }]
      : []
  );
  __setTruenasSession(fake.factory);
  try {
    const nfs = makeContext();
    await method("nfs_share_list").execute({}, nfs.context);
    const smb = makeContext();
    await method("smb_share_list").execute({}, smb.context);
    assertEquals([nfs.written[0].name, smb.written[0].name], [
      "nfs-share:1",
      "smb-share:1",
    ]);
  } finally {
    __setTruenasSession(null);
  }
});

Deno.test("app_set_port_bind: a job id core.get_jobs does not know fails at once", async () => {
  const fake = makeFakeSession((m) => {
    if (m === "app.query") return [structuredClone(LLDAP_APP)];
    if (m === "app.update") return 42;
    if (m === "core.get_jobs") return [];
    return undefined;
  });
  __setTruenasSession(fake.factory);
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("app_set_port_bind").execute(
          { app: "lldap", portKey: "ldap_port", bindMode: "exposed" },
          context,
        ),
      /job 42 not found/,
    );
    assertEquals(fake.methods().filter((m) => m === "core.get_jobs").length, 1);
  } finally {
    __setTruenasSession(null);
  }
});

Deno.test("network_info: each bindable IP names the interface that holds it", async () => {
  const fake = makeFakeSession((m) => {
    if (m === "interface.ip_in_use") {
      return [{ address: "192.0.2.5", netmask: 24 }];
    }
    if (m === "interface.query") {
      return [{ name: "eno1", state: { aliases: [{ address: "192.0.2.5" }] } }];
    }
    if (m === "system.general.config") return { ui_address: ["0.0.0.0"] };
    return undefined;
  });
  __setTruenasSession(fake.factory);
  try {
    const { context, written } = makeContext();
    await method("network_info").execute({}, context);
    const ips = written[0].data.bindableIps as Array<Record<string, unknown>>;
    assertEquals(ips[0].interface, "eno1");
  } finally {
    __setTruenasSession(null);
  }
});

// system_info, network_info and exposure_audit each write one record per model.
// They used to share the name `main`, so the last one run replaced the others.
Deno.test("single-record specs get their own data names", async () => {
  const fake = makeFakeSession((m) => {
    if (m === "system.info") return { hostname: "nas", version: "25.04.2.6" };
    if (m === "system.general.config") return { ui_address: ["0.0.0.0"] };
    return [];
  });
  __setTruenasSession(fake.factory);
  try {
    const { context, written } = makeContext();
    await method("system_info").execute({}, context);
    await method("network_info").execute({}, context);
    await method("exposure_audit").execute({}, context);
    assertEquals(written.map((w) => w.name), [
      "system-info",
      "network-info",
      "exposure-audit",
    ]);
  } finally {
    __setTruenasSession(null);
  }
});

// A path can hold any character but NUL, so the escape must keep paths that a
// lossy slug would merge apart, and a path listed twice must be written once.
Deno.test("filesystem_list: data names stay distinct for awkward paths", async () => {
  const fake = makeFakeSession((
    m,
  ) => (m === "filesystem.listdir" ? [] : undefined));
  __setTruenasSession(fake.factory);
  try {
    const { context, written } = makeContext();
    await method("filesystem_list").execute(
      {
        path: ["/a/b", "/a%2Fb", "/a:b", "/a-b", "/a.b", "/a/../b", "/a/b"],
        maxEntries: 500,
      },
      context,
    );
    assertEquals(written.map((w) => w.name), [
      "dir-listing:%2Fa%2Fb",
      "dir-listing:%2Fa%252Fb",
      "dir-listing:%2Fa:b",
      "dir-listing:%2Fa-b",
      "dir-listing:%2Fa.b",
      "dir-listing:%2Fa%2F.%2E%2Fb",
    ]);
  } finally {
    __setTruenasSession(null);
  }
});

// ─────────────────────────── stage 3: job errors (L1, L2) ───────────────────────────

Deno.test("a FAILED job reports its reason, not only the exception type", async () => {
  const fake = makeFakeSession((m) => {
    if (m === "app.query") return [structuredClone(LLDAP_APP)];
    if (m === "app.update") return 9;
    if (m === "core.get_jobs") {
      return [{
        id: 9,
        state: "FAILED",
        error: "[EINVAL] values.network.ldap_port.host_ips.0: Invalid IP",
        exc_info: { type: "VALIDATION", repr: "ValidationErrors(...)" },
      }];
    }
    return undefined;
  });
  __setTruenasSession(fake.factory);
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("app_set_port_bind").execute(
          { app: "lldap", portKey: "ldap_port", hostIps: ["bogus"] },
          context,
        ),
      /job 9 FAILED: VALIDATION: \[EINVAL\] values\.network\.ldap_port\.host_ips\.0: Invalid IP/,
    );
  } finally {
    __setTruenasSession(null);
  }
});

Deno.test("a job that outlives timeoutMs says it may still apply", async () => {
  const fake = makeFakeSession((m) => {
    if (m === "app.query") return [structuredClone(LLDAP_APP)];
    if (m === "app.update") return 11;
    if (m === "core.get_jobs") return [{ id: 11, state: "RUNNING" }];
    return undefined;
  });
  __setTruenasSession(fake.factory);
  try {
    const { context } = makeContext();
    context.globalArgs = { ...GLOBALS, timeoutMs: 1 };
    await rejects(
      () =>
        method("app_set_port_bind").execute(
          { app: "lldap", portKey: "ldap_port", bindMode: "exposed" },
          context,
        ),
      /job 11 did not finish.*still running on TrueNAS.*may yet apply/,
    );
  } finally {
    __setTruenasSession(null);
  }
});

Deno.test("a status poll that fails says the job may still apply", async () => {
  // The job was submitted, so losing the poll (a call timeout or a dropped
  // socket) leaves its outcome unknown, the same as a job timeout.
  const fake = makeFakeSession((m) => {
    if (m === "app.query") return [structuredClone(LLDAP_APP)];
    if (m === "app.update") return 12;
    if (m === "core.get_jobs") {
      throw new Error("TrueNAS core.get_jobs timed out after 30000ms");
    }
    return undefined;
  });
  __setTruenasSession(fake.factory);
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("app_set_port_bind").execute(
          { app: "lldap", portKey: "ldap_port", bindMode: "exposed" },
          context,
        ),
      /job 12.*core\.get_jobs timed out.*may yet apply/,
    );
  } finally {
    __setTruenasSession(null);
  }
});

// A change call that times out or loses its socket may still have landed; one
// TrueNAS answers with a JSON-RPC error did not.
const NFS_SHARE = {
  id: 2,
  path: "/mnt/tank/stash",
  networks: ["192.0.2.0/24"],
  hosts: [],
  enabled: true,
};
const SMB_SHARE = {
  id: 4,
  name: "Assets",
  path: "/mnt/tank/assets",
  purpose: "NO_PRESET",
  hostsallow: ["192.0.2.0/24"],
  hostsdeny: [],
  enabled: true,
  ro: false,
};
const changeCases: Array<{
  call: string;
  method: string;
  args: Record<string, unknown>;
  query: [string, unknown];
}> = [
  {
    call: "app.update",
    method: "app_set_port_bind",
    args: { app: "lldap", portKey: "ldap_port", bindMode: "exposed" },
    query: ["app.query", LLDAP_APP],
  },
  {
    call: "sharing.nfs.update",
    method: "nfs_share_set_access",
    args: { id: 2, networks: ["192.0.2.7/32"] },
    query: ["sharing.nfs.query", NFS_SHARE],
  },
  {
    call: "sharing.nfs.delete",
    method: "nfs_share_delete",
    args: { id: 2 },
    query: ["sharing.nfs.query", NFS_SHARE],
  },
  {
    call: "sharing.smb.update",
    method: "smb_share_set_access",
    args: { id: 4, hostsdeny: ["192.0.2.7"] },
    query: ["sharing.smb.query", SMB_SHARE],
  },
  {
    call: "sharing.smb.delete",
    method: "smb_share_delete",
    args: { id: 4 },
    query: ["sharing.smb.query", SMB_SHARE],
  },
];

for (const c of changeCases) {
  Deno.test(`${c.call}: a timeout says the change may still apply`, async () => {
    const fake = makeFakeSession((m) => {
      if (m === c.query[0]) return [structuredClone(c.query[1])];
      if (m === c.call) {
        throw new Error(`TrueNAS call timed out after 30000ms`);
      }
      return undefined;
    });
    __setTruenasSession(fake.factory);
    try {
      const { context } = makeContext();
      await rejects(
        () => method(c.method).execute(c.args, context),
        /timed out.*may yet apply/,
      );
    } finally {
      __setTruenasSession(null);
    }
  });

  Deno.test(`${c.call}: a JSON-RPC error is reported as a refusal`, async () => {
    const fake = makeFakeSession((m) => {
      if (m === c.query[0]) return [structuredClone(c.query[1])];
      if (m === c.call) {
        throw new Error("TrueNAS JSON-RPC error: [EINVAL] refused");
      }
      return undefined;
    });
    __setTruenasSession(fake.factory);
    try {
      const { context } = makeContext();
      let message = "";
      try {
        await method(c.method).execute(c.args, context);
      } catch (e) {
        message = (e as Error).message;
      }
      assert(message.includes("[EINVAL] refused"), `got: ${message}`);
      assert(!message.includes("may yet apply"), `got: ${message}`);
    } finally {
      __setTruenasSession(null);
    }
  });
}

// ─────────────────────────── stage 3: exposure_audit host network (L3) ───────────────────────────

Deno.test("exposure_audit: lists host-network apps, which have no port objects", async () => {
  const hostNet = {
    name: "scrypted",
    custom_app: false,
    config: { network: { host_network: true } },
  };
  const fake = makeFakeSession((m) => {
    if (m === "system.info") return { hostname: "nas", version: "25.04" };
    if (m === "app.query") return [LLDAP_APP, hostNet];
    if (m.endsWith(".query") || m === "interface.ip_in_use") return [];
    return undefined;
  });
  __setTruenasSession(fake.factory);
  try {
    const { context, written } = makeContext();
    await method("exposure_audit").execute({}, context);
    assertEquals(written[0].data.hostNetworkApps, ["scrypted"]);
  } finally {
    __setTruenasSession(null);
  }
});

// ─────────────────────────── stage 3: compose apps refused (L10) ───────────────────────────

const COMPOSE_APP = {
  name: "whoami",
  custom_app: true,
  // A compose app's config is its compose file.
  config: {
    services: { whoami: { image: "traefik/whoami", ports: ["8080:80"] } },
    networks: { default: {} },
  },
};

for (
  const [name, args] of [
    ["app_set_port_bind", {
      app: "whoami",
      portNumber: 8080,
      bindMode: "exposed",
    }],
    ["app_set_networks", { app: "whoami", networks: ["ix-caddy_default"] }],
  ] as const
) {
  Deno.test(`${name}: refuses an app installed from compose YAML`, async () => {
    const fake = makeFakeSession((m) => {
      if (m === "app.query") return [COMPOSE_APP];
      if (m === "app.update") throw new Error("must not be called");
      return undefined;
    });
    __setTruenasSession(fake.factory);
    try {
      const { context, written } = makeContext();
      await rejects(
        () => method(name).execute(args, context),
        /installed from compose YAML.*Nothing was changed/,
      );
      assertEquals(fake.methods(), ["app.query"]);
      assertEquals(written.length, 0);
    } finally {
      __setTruenasSession(null);
    }
  });
}

// ─────────────────────────── stage 3: port selection (N2) ───────────────────────────

Deno.test("app_set_port_bind: refuses a number two list-form ports share", async () => {
  const app = {
    name: "dns",
    custom_app: false,
    config: {
      ports: [
        { bind_mode: "published", port_number: 53, protocol: "tcp" },
        { bind_mode: "published", port_number: 53, protocol: "udp" },
      ],
    },
  };
  const fake = makeFakeSession((m) => (m === "app.query" ? [app] : undefined));
  __setTruenasSession(fake.factory);
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("app_set_port_bind").execute(
          { app: "dns", portNumber: 53, bindMode: "exposed" },
          context,
        ),
      /portNumber 53 matches 2 entries.*ambiguous/,
    );
    assertEquals(fake.methods(), ["app.query"]);
  } finally {
    __setTruenasSession(null);
  }
});

Deno.test("app_set_port_bind: refuses a number two keyed ports share", async () => {
  const app = structuredClone(LLDAP_APP);
  app.config.network.ldaps_port.port_number = 389;
  const fake = makeFakeSession((m) => (m === "app.query" ? [app] : undefined));
  __setTruenasSession(fake.factory);
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("app_set_port_bind").execute(
          { app: "lldap", portNumber: 389, bindMode: "exposed" },
          context,
        ),
      /portNumber 389 matches 2 ports on lldap \(ldap_port, ldaps_port\)/,
    );
    assertEquals(fake.methods(), ["app.query"]);
  } finally {
    __setTruenasSession(null);
  }
});

Deno.test("app_set_port_bind: refuses a portKey that matches nothing on a list-form app", async () => {
  const fake = makeFakeSession((
    m,
  ) => (m === "app.query" ? [structuredClone(CUSTOM_APP)] : undefined));
  __setTruenasSession(fake.factory);
  try {
    const { context } = makeContext();
    await rejects(
      () =>
        method("app_set_port_bind").execute(
          {
            app: "kopia",
            portKey: "web_port",
            portNumber: 51515,
            bindMode: "exposed",
          },
          context,
        ),
      /portKey "web_port" is not a key of config\.network/,
    );
    assertEquals(fake.methods(), ["app.query"]);
  } finally {
    __setTruenasSession(null);
  }
});

Deno.test("app_set_port_bind: a hostIps-only edit keeps the bind mode", async () => {
  let sent: Record<string, Record<string, unknown>> = {};
  let done = false;
  const fake = makeFakeSession((m, params) => {
    if (m === "app.query") {
      const app = structuredClone(LLDAP_APP);
      if (done) app.config.network.http_port.host_ips = ["192.0.2.252"];
      return [app];
    }
    if (m === "app.update") {
      done = true;
      sent = (params[1] as { values: { network: typeof sent } }).values.network;
      return 5;
    }
    if (m === "core.get_jobs") return [{ id: 5, state: "SUCCESS" }];
    return undefined;
  });
  __setTruenasSession(fake.factory);
  try {
    const { context, written } = makeContext();
    await method("app_set_port_bind").execute(
      { app: "lldap", portKey: "http_port", hostIps: ["192.0.2.252"] },
      context,
    );
    assertEquals(sent.http_port.bind_mode, "published");
    assertEquals(sent.http_port.host_ips, ["192.0.2.252"]);
    const r = written[0].data;
    assertEquals(r.action, "updated");
    assertEquals(r.bindMode, "published");
    assertEquals(r.previousHostIps, ["0.0.0.0"]);
    assertEquals(r.hostIps, ["192.0.2.252"]);
  } finally {
    __setTruenasSession(null);
  }
});

// ─────────────────────────── stage 3: argument bounds (N1) ───────────────────────────

Deno.test("global arguments refuse an empty apiKey and a non-positive timeoutMs", () => {
  const base = { endpoint: "nas.test", apiKey: "k" };
  assert(model.globalArguments.safeParse(base).success, "base must parse");
  assert(!model.globalArguments.safeParse({ ...base, apiKey: "" }).success);
  assert(!model.globalArguments.safeParse({ ...base, timeoutMs: 0 }).success);
  assert(!model.globalArguments.safeParse({ ...base, timeoutMs: -5 }).success);
});

Deno.test("filesystem_list refuses a negative maxEntries; 0 records existence only", async () => {
  const args = model.methods.filesystem_list.arguments;
  assert(!args.safeParse({ path: "/mnt", maxEntries: -1 }).success);
  assert(args.safeParse({ path: "/mnt", maxEntries: 0 }).success);

  const fake = makeFakeSession((m) =>
    m === "filesystem.listdir" ? [{ name: "a", type: "FILE" }] : undefined
  );
  __setTruenasSession(fake.factory);
  try {
    const { context, written } = makeContext();
    await method("filesystem_list").execute(
      { path: "/mnt", maxEntries: 0 },
      context,
    );
    const d = written[0].data;
    assertEquals([d.exists, d.entryCount, d.truncated], [true, 0, true]);
  } finally {
    __setTruenasSession(null);
  }
});

// ─────────────────────────── stage 3: list shaping (N4, L12) ───────────────────────────

Deno.test("nfs_share_list: a wildcard network or host is unrestricted", async () => {
  const share = (id: number, networks: string[], hosts: string[]) => ({
    id,
    path: `/mnt/${id}`,
    networks,
    hosts,
    enabled: true,
    ro: false,
  });
  const fake = makeFakeSession((m) =>
    m === "sharing.nfs.query"
      ? [
        share(1, ["0.0.0.0/0"], []),
        share(2, ["::/0"], []),
        share(3, [], ["*"]),
        share(4, ["192.0.2.0/24"], ["*.example.com"]),
        share(5, [], []),
      ]
      : undefined
  );
  __setTruenasSession(fake.factory);
  try {
    const { context, written } = makeContext();
    await method("nfs_share_list").execute({}, context);
    assertEquals(
      written.map((w) => [w.data.id, w.data.unrestricted]),
      [[1, true], [2, true], [3, true], [4, false], [5, true]],
    );
  } finally {
    __setTruenasSession(null);
  }
});

Deno.test("smb_share_list: shapes fields and flags an empty hostsallow", async () => {
  const fake = makeFakeSession((m) =>
    m === "sharing.smb.query"
      ? [
        {
          id: 1,
          name: "Open",
          path: "/mnt/o",
          comment: "c",
          enabled: true,
          ro: true,
          hostsallow: [],
          hostsdeny: ["192.0.2.9"],
          purpose: "DEFAULT_SHARE",
        },
        {
          id: 2,
          name: "Shut",
          path: "/mnt/s",
          enabled: false,
          ro: false,
          hostsallow: ["192.0.2.0/24"],
          hostsdeny: ["ALL"],
          purpose: "NO_PRESET",
        },
      ]
      : undefined
  );
  __setTruenasSession(fake.factory);
  try {
    const { context, written } = makeContext();
    await method("smb_share_list").execute({}, context);
    assertEquals(written.map((w) => w.name), ["smb-share:1", "smb-share:2"]);
    const [open, shut] = written.map((w) => w.data);
    assertEquals(
      [open.comment, open.ro, open.hostsdeny, open.purpose, open.unrestricted],
      ["c", true, ["192.0.2.9"], "DEFAULT_SHARE", true],
    );
    assertEquals([shut.enabled, shut.unrestricted], [false, false]);
  } finally {
    __setTruenasSession(null);
  }
});

Deno.test("system_info and service_list shape their records", async () => {
  const fake = makeFakeSession((m) => {
    if (m === "system.info") {
      return {
        hostname: "nas",
        version: "25.04.2.6",
        uptime_seconds: 120.5,
        loadavg: [0.1, 0.2, 0.3],
        physmem: 1024,
        model: "Xeon",
        cores: 8,
      };
    }
    if (m === "service.query") {
      return [
        { service: "ssh", state: "RUNNING", enable: true },
        { service: "ftp", state: "STOPPED", enable: false },
        { state: "RUNNING" }, // no name: skipped
      ];
    }
    return undefined;
  });
  __setTruenasSession(fake.factory);
  try {
    const { context, written } = makeContext();
    await method("system_info").execute({}, context);
    await method("service_list").execute({}, context);
    const info = written[0].data;
    assertEquals(
      [info.hostname, info.uptimeSeconds, info.loadAvg, info.cores],
      ["nas", 120.5, [0.1, 0.2, 0.3], 8],
    );
    assertEquals(written.slice(1).map((w) => [w.name, w.data.running]), [
      ["service:ssh", true],
      ["service:ftp", false],
    ]);
  } finally {
    __setTruenasSession(null);
  }
});

// ─────────────────────────── stage 3: no-op paths and logs (L12, L13) ───────────────────────────

Deno.test("nfs_share_set_access: no update when the lists already match, and says so", async () => {
  const share = {
    id: 4,
    path: "/mnt/x",
    networks: ["192.0.2.0/24"],
    hosts: ["a"],
    enabled: true,
  };
  const fake = makeFakeSession((m) => {
    if (m === "sharing.nfs.query") return [share];
    if (m === "sharing.nfs.update") throw new Error("must not be called");
    return undefined;
  });
  __setTruenasSession(fake.factory);
  try {
    const { context, written, logs } = makeContext();
    await method("nfs_share_set_access").execute(
      { id: 4, networks: ["192.0.2.0/24"], hosts: ["a"] },
      context,
    );
    assertEquals(written[0].data.action, "unchanged");
    assert(
      logs.some((l) => /NFS share access already at desired state/.test(l.msg)),
      "the no-op path must log",
    );
  } finally {
    __setTruenasSession(null);
  }
});

Deno.test("smb_share_set_access: no update when the lists already match", async () => {
  const share = {
    id: 3,
    name: "M",
    path: "/mnt/m",
    hostsallow: ["192.0.2.50"],
    hostsdeny: ["ALL"],
    purpose: "NO_PRESET",
  };
  const fake = makeFakeSession((m) => {
    if (m === "sharing.smb.query") return [share];
    if (m === "sharing.smb.update") throw new Error("must not be called");
    return undefined;
  });
  __setTruenasSession(fake.factory);
  try {
    const { context, written, logs } = makeContext();
    await method("smb_share_set_access").execute(
      { id: 3, hostsallow: ["192.0.2.50"] },
      context,
    );
    assertEquals(written[0].data.action, "unchanged");
    assert(
      logs.some((l) => /SMB share access already at desired state/.test(l.msg)),
      "the no-op path must log",
    );
  } finally {
    __setTruenasSession(null);
  }
});

Deno.test("list methods log a completion line with the count", async () => {
  const fake = makeFakeSession((
    m,
  ) => (m === "app.query" ? [LLDAP_APP] : undefined));
  __setTruenasSession(fake.factory);
  try {
    const { context, logs } = makeContext();
    await method("app_list").execute({}, context);
    const done = logs.find((l) => l.msg === "Recorded apps");
    assertEquals(done?.props, { count: 1 });
  } finally {
    __setTruenasSession(null);
  }
});

// ─────────────────────────── stage 3: the real transport (L12, N5) ───────────────────────────

type Frame = { id: number; method: string; params: unknown[] };

/**
 * A stand-in for the global WebSocket, so the real session factory runs without a
 * network. `opens` decides what happens after construction; `reply` answers each
 * frame (`undefined` = never answer). Events fire on microtasks, not timers, so no
 * timer outlives a test.
 */
function installFakeWebSocket(
  opens: "open" | "close" | "never",
  reply: (f: Frame) => { result?: unknown; error?: unknown } | undefined,
) {
  const urls: string[] = [];
  const frames: Frame[] = [];
  class FakeWebSocket {
    onopen: (() => void) | null = null;
    onerror: (() => void) | null = null;
    onclose: (() => void) | null = null;
    onmessage: ((ev: { data: string }) => void) | null = null;
    #open = false;
    constructor(url: string) {
      urls.push(url);
      queueMicrotask(() => {
        if (opens === "open") {
          this.#open = true;
          this.onopen?.();
        } else if (opens === "close") {
          this.onclose?.();
        }
      });
    }
    send(data: string) {
      // The key must never be sent before the TLS socket is open.
      if (!this.#open) throw new Error("send before open");
      const f = JSON.parse(data) as Frame;
      frames.push(f);
      const r = reply(f);
      if (r === undefined) return;
      queueMicrotask(() =>
        this.onmessage?.({ data: JSON.stringify({ id: f.id, ...r }) })
      );
    }
    close() {
      this.onclose?.();
    }
  }
  const real = globalThis.WebSocket;
  globalThis.WebSocket = FakeWebSocket as unknown as typeof WebSocket;
  return {
    urls,
    frames,
    restore: () => {
      globalThis.WebSocket = real;
    },
  };
}

function transportContext(timeoutMs: number) {
  const c = makeContext();
  c.context.globalArgs = {
    endpoint: "nas.test",
    apiKey: "s3cret-key",
    timeoutMs,
  };
  return c;
}

Deno.test("transport: logs in over wss, then calls", async () => {
  const ws = installFakeWebSocket(
    "open",
    (f) =>
      f.method === "auth.login_with_api_key"
        ? { result: true }
        : { result: { hostname: "nas", version: "25.04" } },
  );
  try {
    const { context, written } = transportContext(1000);
    await method("system_info").execute({}, context);
    assertEquals(ws.urls, ["wss://nas.test/api/current"]);
    assertEquals(ws.frames.map((f) => f.method), [
      "auth.login_with_api_key",
      "system.info",
    ]);
    assertEquals(written[0].data.hostname, "nas");
  } finally {
    ws.restore();
  }
});

Deno.test("transport: a rejected login fails", async () => {
  const ws = installFakeWebSocket("open", () => ({ result: false }));
  try {
    const { context } = transportContext(1000);
    await rejects(
      () => method("system_info").execute({}, context),
      /api-key login rejected/,
    );
    assertEquals(ws.frames.length, 1);
  } finally {
    ws.restore();
  }
});

Deno.test("transport: an RPC error that echoes the key is redacted", async () => {
  const ws = installFakeWebSocket(
    "open",
    (f) =>
      f.method === "auth.login_with_api_key"
        ? { result: true }
        : { error: { message: "bad token s3cret-key" } },
  );
  try {
    const { context } = transportContext(1000);
    let message = "";
    try {
      await method("system_info").execute({}, context);
    } catch (e) {
      message = (e as Error).message;
    }
    assert(/JSON-RPC error/.test(message), `unexpected error: ${message}`);
    assert(!message.includes("s3cret-key"), "the key must be redacted");
    assert(message.includes("***"), "the key must be replaced, not dropped");
  } finally {
    ws.restore();
  }
});

Deno.test("transport: a call with no reply times out", async () => {
  const ws = installFakeWebSocket(
    "open",
    (f) =>
      f.method === "auth.login_with_api_key" ? { result: true } : undefined,
  );
  try {
    const { context } = transportContext(20);
    await rejects(
      () => method("system_info").execute({}, context),
      /call system\.info timed out after 20ms/,
    );
  } finally {
    ws.restore();
  }
});

Deno.test("transport: a socket that never opens times out", async () => {
  const ws = installFakeWebSocket("never", () => undefined);
  try {
    const { context } = transportContext(20);
    await rejects(
      () => method("system_info").execute({}, context),
      /connection timed out after 20ms/,
    );
    assertEquals(ws.frames.length, 0);
  } finally {
    ws.restore();
  }
});

Deno.test("transport: a close before open fails at once and points at the certificate", async () => {
  const ws = installFakeWebSocket("close", () => undefined);
  try {
    // A long timeout: without the fix the close is ignored and this waits it out.
    const { context } = transportContext(10_000);
    const started = Date.now();
    await rejects(
      () => method("system_info").execute({}, context),
      /connection failed.*certificate/,
    );
    assert(Date.now() - started < 1000, "must not wait for the timeout");
    assertEquals(ws.frames.length, 0);
  } finally {
    ws.restore();
  }
});

// ─────────────────────────── stage 3: observation lifetime (L9) ───────────────────────────

Deno.test("app and share observations expire after an hour, like services", () => {
  // Nothing deletes the record of an app or share that has gone, so an
  // "infinite" lifetime would report it as live for ever.
  for (const spec of ["app", "nfs-share", "smb-share", "service"] as const) {
    assertEquals(model.resources[spec].lifetime, "1h", spec);
  }
});

// ─────────────────────────── upgrade to 2026.10.11.1 ───────────────────────────

Deno.test("upgrade 2026.10.11.1: drops insecureSkipTlsVerify and a non-positive timeoutMs", () => {
  const up = model.upgrades[0].upgradeAttributes;
  assertEquals(
    up({
      endpoint: "nas",
      apiKey: "k",
      insecureSkipTlsVerify: true,
      timeoutMs: 0,
    }),
    { endpoint: "nas", apiKey: "k" },
  );
  assertEquals(
    up({ endpoint: "nas", timeoutMs: 5000 }),
    { endpoint: "nas", timeoutMs: 5000 },
  );
  assertEquals(up({ endpoint: "nas" }), { endpoint: "nas" });
});
