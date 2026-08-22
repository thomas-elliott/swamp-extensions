/**
 * Unit tests for the load-bearing logic of `@thomas/truenas` — the bits where a
 * silent bug would be costly: the wss-only transport guard (the API-key-revoke
 * footgun), port-binding shaping, verify-first resolution, the app.update full-network
 * patch + job-wait, share-access update bodies, the exposure roll-up flags, and the
 * no-op fast paths. No live host — the JSON-RPC transport is faked via the
 * __setTruenasSession seam.
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
  insecureSkipTlsVerify: true,
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

Deno.test("websocketUrl: https is upgraded to wss", () => {
  assertEquals(
    websocketUrl("https://nas.example.com"),
    "wss://nas.example.com/api/current",
  );
});

Deno.test("websocketUrl: keeps an explicit wss path", () => {
  assertEquals(
    websocketUrl("wss://nas.example.com/api/current"),
    "wss://nas.example.com/api/current",
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
    assertEquals(written[0].name, "lldap");
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

// ─────────────────────────── filesystem_list ───────────────────────────

Deno.test("filesystem_list: shapes entries, sorts them, flags truncation", async () => {
  const fake = makeFakeSession((m) =>
    m === "filesystem.listdir" ? [
      { name: "offsite", type: "DIRECTORY", size: 4096, is_mountpoint: true },
      { name: "app-config", type: "DIRECTORY", size: 4096 },
    ] : undefined
  );
  __setTruenasSession(fake.factory);
  try {
    const { context, written } = makeContext();
    await method("filesystem_list").execute(
      { path: "/mnt/Primary/backup", maxEntries: 1 },
      context,
    );
    assertEquals(written[0].specName, "dir-listing");
    assertEquals(written[0].name, "mnt-Primary-backup");
    const l = written[0].data;
    assertEquals(l.exists, true);
    assertEquals(l.truncated, true, "maxEntries=1 of 2 entries");
    assertEquals(
      (l.entries as Array<Record<string, unknown>>).map((e) => e.name),
      ["app-config"],
      "entries sort by name",
    );
    assertEquals(find(fake.calls, "filesystem.listdir")!.params, [
      "/mnt/Primary/backup",
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
  const fake = makeFakeSession((m) => (m === "filesystem.listdir" ? [] : undefined));
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
    m === "app.query" ? [{
      name: "kopia",
      config: {
        storage: {
          config: {
            type: "host_path",
            mount_path: "/app/config",
            host_path_config: { path: "/mnt/Primary/apps/kopia" },
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
    }] : undefined
  );
  __setTruenasSession(fake.factory);
  try {
    const { context, written } = makeContext();
    await method("app_storage").execute({ app: "kopia" }, context);
    assertEquals(written[0].specName, "app-storage");
    assertEquals(
      written[0].name,
      "kopia-storage",
      "a bare app name would clobber app_list's `app` instance",
    );
    assertEquals(written[0].data.mountCount, 2, "ix_volume is not a host path");
    const mounts = written[0].data.mounts as Array<Record<string, unknown>>;
    assertEquals(mounts.map((m) => m.mountPath), ["/app/config", "/data/backup"]);
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
    m === "replication.query" ? [{
      id: 3,
      name: "Apps - Backup",
      direction: "PUSH",
      transport: "LOCAL",
      enabled: true,
      auto: true,
      recursive: true,
      source_datasets: ["Primary/apps"],
      target_dataset: "Backup/apps",
      readonly: "SET",
      properties: true,
      state: { state: "FINISHED", datetime: { $date: 1785585769000 } },
    }] : undefined
  );
  __setTruenasSession(fake.factory);
  try {
    const { context, written } = makeContext();
    await method("replication_list").execute({}, context);
    assertEquals(written[0].specName, "replication-task");
    assertEquals(written[0].name, "repl-3", "a bare id would clobber nfs-share 3");
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
      "mnt-Backup-apps",
      "mnt-Backup-nope",
    ]);
    assertEquals(written[0].data.exists, true);
    assertEquals(written[1].data.exists, false, "ENOENT doesn't abort the fan-out");
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

Deno.test("exposure_audit: flags plaintext LDAP + 0.0.0.0 ports + unrestricted shares", async () => {
  const fake = makeFakeSession((m) => {
    switch (m) {
      case "system.info":
        return { hostname: "truenas", version: "25.04.2.6" };
      case "app.query":
        return [LLDAP_APP];
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
    assertEquals(flags.portsOnAllInterfaces, [389, 636, 30325]);
    assertEquals(flags.nonWildcardBindableIps, ["192.0.2.252"]);
    assertEquals(a.unrestrictedNfsShares, ["/mnt/open"]);
    assertEquals(a.unrestrictedSmbShares, ["Open"]);
    assertEquals((a.publishedPorts as unknown[]).length, 3);
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
    if (m === "core.get_jobs") return [{ id: 7, state: "SUCCESS", result: null }];
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
  let sent: any = null;
  let done = false;
  const fake = makeFakeSession((m, params) => {
    if (m === "app.query") return [done ? after : before];
    if (m === "app.update") {
      done = true;
      sent = (params[1] as any).values.networks;
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

// ─────────────────────────── nfs_share_delete ───────────────────────────

Deno.test("nfs_share_delete: removes the export and records its prior config", async () => {
  const share = {
    id: 9,
    path: "/mnt/Primary/apps/git",
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
    assertEquals(r.path, "/mnt/Primary/apps/git");
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
    if (m === "sharing.nfs.query") return [{ id: 9, path: "/mnt/Primary/apps/git" }];
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
          { id: 9, confirmPath: "/mnt/Primary/apps/WRONG" },
          context,
        ),
      /does not match/,
    );
    assertEquals(deleteCalled, false, "must NOT delete on a confirmPath mismatch");
  } finally {
    __setTruenasSession(null);
  }
});

Deno.test("nfs_share_delete: already-absent share succeeds with action=absent (idempotent)", async () => {
  let deleteCalled = false;
  const fake = makeFakeSession((m) => {
    if (m === "sharing.nfs.query") return []; // nothing matches — already gone
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
    assertEquals(deleteCalled, false, "must NOT call delete when nothing matches");
    const r = written[0].data;
    assertEquals(r.action, "absent");
    assertEquals(r.id, 9);
  } finally {
    __setTruenasSession(null);
  }
});

// ─────────────────────────── smb_share_delete ───────────────────────────

Deno.test("smb_share_delete: removes the share and records its prior config", async () => {
  const share = {
    id: 6,
    name: "Music",
    path: "/mnt/Primary/Music",
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
    assertEquals(r.previousHostsallow, ["100.64.0.0/10"]);
    assertEquals(r.hostsallow, []);
  } finally {
    __setTruenasSession(null);
  }
});

Deno.test("smb_share_delete: refuses when confirmName mismatches", async () => {
  let deleteCalled = false;
  const fake = makeFakeSession((m) => {
    if (m === "sharing.smb.query") return [{ id: 6, name: "Music", path: "/mnt/Primary/Music" }];
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
    assertEquals(deleteCalled, false, "must NOT delete on a confirmName mismatch");
  } finally {
    __setTruenasSession(null);
  }
});

Deno.test("smb_share_delete: already-absent share succeeds with action=absent (idempotent)", async () => {
  let deleteCalled = false;
  const fake = makeFakeSession((m) => {
    if (m === "sharing.smb.query") return []; // nothing matches — already gone
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
    assertEquals(deleteCalled, false, "must NOT call delete when nothing matches");
    const r = written[0].data;
    assertEquals(r.action, "absent");
    assertEquals(r.name, "Music");
  } finally {
    __setTruenasSession(null);
  }
});

// ─────────────────────────── smb_share_set_access ───────────────────────────

Deno.test("smb_share_set_access: echoes name+path and sets hostsallow", async () => {
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
      assertEquals(body.name, "Media", "must echo name (schema-required)");
      assertEquals(body.path, "/mnt/m", "must echo path");
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
  // DEFAULT_SHARE re-applies empty hostsallow on every update, silently dropping the
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
    assertEquals(purposeKeyPresent, false, "must not send purpose for a non-locking preset");
    const r = written[0].data;
    assertEquals(r.previousPurpose, "MULTI_PROTOCOL_NFS");
    assertEquals(r.purpose, "MULTI_PROTOCOL_NFS");
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
