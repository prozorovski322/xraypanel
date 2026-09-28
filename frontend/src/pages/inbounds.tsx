import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, Trash2 } from "lucide-react";
import { useState, type FormEvent } from "react";

import { api, unwrap, type Schemas } from "@/api/client";
import { useAuth } from "@/auth";
import { PageHeader } from "@/components/layout";
import { useToast } from "@/components/toast";
import {
  Badge,
  Button,
  Card,
  CardHeader,
  Dialog,
  Empty,
  ErrorNote,
  Field,
  Input,
  Select,
  Spinner,
  Table,
  Td,
  Textarea,
  Th,
} from "@/components/ui";
import { formatDate } from "@/lib/utils";

type InboundCreate = Schemas["InboundCreate"];

export function InboundsPage() {
  const { can } = useAuth();
  const toast = useToast();
  const queryClient = useQueryClient();
  const [creating, setCreating] = useState(false);

  const inbounds = useQuery({ queryKey: ["inbounds"], queryFn: async () => unwrap(await api.GET("/inbounds")) });

  const remove = useMutation({
    mutationFn: async (id: number) => {
      const result = await api.DELETE("/inbounds/{id}", { params: { path: { id } } });
      if (!result.response.ok) unwrap(result);
    },
    onSuccess: () => {
      toast.ok("Inbound deleted");
      void queryClient.invalidateQueries({ queryKey: ["inbounds"] });
    },
    onError: toast.error,
  });

  const writable = can("inbounds:write");

  return (
    <>
      <PageHeader
        title="Inbounds"
        description="Listeners a node runs. Users reach them through groups; nodes run the ones attached to them."
        actions={
          writable && (
            <Button variant="primary" onClick={() => setCreating(true)}>
              <Plus className="size-4" /> New inbound
            </Button>
          )
        }
      />
      <Card>
        {inbounds.isPending ? (
          <Spinner />
        ) : inbounds.isError ? (
          <ErrorNote error={inbounds.error} />
        ) : inbounds.data.length === 0 ? (
          <Empty>No inbounds yet.</Empty>
        ) : (
          <Table>
            <thead>
              <tr>
                <Th>Tag</Th>
                <Th>Protocol</Th>
                <Th>Listen</Th>
                <Th>Flow</Th>
                <Th>State</Th>
                <Th />
              </tr>
            </thead>
            <tbody>
              {inbounds.data.map((inbound) => (
                <tr key={inbound.id}>
                  <Td className="font-medium">{inbound.tag}</Td>
                  <Td className="text-muted">
                    {inbound.protocol} · {inbound.transport} · {inbound.security}
                  </Td>
                  <Td className="num">
                    {inbound.listen_address}:{inbound.listen_port}
                  </Td>
                  <Td className="text-muted">{inbound.flow || "—"}</Td>
                  <Td>{inbound.enabled ? <Badge tone="ok">enabled</Badge> : <Badge>disabled</Badge>}</Td>
                  <Td className="text-right">
                    {writable && inbound.id !== undefined && (
                      <Button
                        size="sm"
                        variant="ghost"
                        aria-label={`Delete ${inbound.tag}`}
                        loading={remove.isPending && remove.variables === inbound.id}
                        onClick={() => {
                          if (window.confirm(`Delete ${inbound.tag}? Every node running it stops serving it.`)) {
                            remove.mutate(inbound.id!);
                          }
                        }}
                      >
                        <Trash2 className="size-4" />
                      </Button>
                    )}
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>

      <RealityKeys writable={writable} />
      <CreateInboundDialog open={creating} onOpenChange={setCreating} />
    </>
  );
}

const ssMethods = ["2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"];

function parseObject(label: string, text: string): Record<string, unknown> | undefined {
  if (text.trim() === "") return undefined;
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    throw new Error(`${label} is not valid JSON.`);
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${label} must be a JSON object.`);
  }
  return value as Record<string, unknown>;
}

function CreateInboundDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const toast = useToast();
  const queryClient = useQueryClient();

  const [tag, setTag] = useState("");
  const [protocol, setProtocol] = useState<InboundCreate["protocol"]>("vless");
  const [transport, setTransport] = useState<InboundCreate["transport"]>("tcp");
  const [security, setSecurity] = useState<InboundCreate["security"]>("reality");
  const [port, setPort] = useState("443");
  const [listen, setListen] = useState("0.0.0.0");
  const [vision, setVision] = useState(true);
  const [ssMethod, setSsMethod] = useState(ssMethods[0]!);
  const [realityKey, setRealityKey] = useState("");
  const [network, setNetwork] = useState("");
  const [tls, setTls] = useState("");
  const [error, setError] = useState<string | null>(null);

  const keys = useQuery({
    queryKey: ["reality-keys"],
    queryFn: async () => unwrap(await api.GET("/reality-keys")),
    enabled: open,
  });

  // The same rule the database and the generator enforce (ADR-010), applied before submit so
  // the form never offers a combination the panel will refuse.
  const visionAllowed = protocol === "vless" && transport === "tcp" && (security === "tls" || security === "reality");

  const create = useMutation({
    mutationFn: async () => {
      const listenPort = Number(port);
      if (!Number.isInteger(listenPort) || listenPort < 1 || listenPort > 65535) {
        throw new Error("Port must be between 1 and 65535.");
      }
      const body: InboundCreate = {
        tag: tag.trim(),
        protocol,
        transport,
        security,
        listen_port: listenPort,
        listen_address: listen.trim() || "0.0.0.0",
        enabled: true,
        flow: visionAllowed && vision ? "xtls-rprx-vision" : undefined,
        ss_method: protocol === "shadowsocks" ? ssMethod : undefined,
        reality_key_id: security === "reality" && realityKey ? Number(realityKey) : undefined,
        network_settings: parseObject("Transport settings", network),
        tls_settings: security === "tls" ? parseObject("TLS settings", tls) : undefined,
      };
      if (security === "reality" && !body.reality_key_id) throw new Error("Choose a Reality key.");
      return unwrap(await api.POST("/inbounds", { body }));
    },
    onSuccess: (inbound) => {
      toast.ok(`Created ${inbound.tag}`);
      onOpenChange(false);
      setTag("");
      setError(null);
      void queryClient.invalidateQueries({ queryKey: ["inbounds"] });
    },
    onError: (err) => setError(err instanceof Error ? err.message : String(err)),
  });

  function submit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    create.mutate();
  }

  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      wide
      title="New inbound"
      description="Validated against the same rules as the node's configuration, so a combination Xray would refuse is refused here."
      footer={
        <>
          <Button onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button variant="primary" type="submit" form="create-inbound" loading={create.isPending}>
            Create
          </Button>
        </>
      }
    >
      <form id="create-inbound" className="grid grid-cols-1 gap-4 sm:grid-cols-2" onSubmit={submit}>
        <Field label="Tag" htmlFor="in-tag" hint="Unique name in the node's config.">
          <Input id="in-tag" value={tag} onChange={(e) => setTag(e.target.value)} required autoFocus />
        </Field>
        <Field label="Protocol" htmlFor="in-protocol">
          <Select id="in-protocol" value={protocol} onChange={(e) => setProtocol(e.target.value as InboundCreate["protocol"])}>
            <option value="vless">VLESS</option>
            <option value="trojan">Trojan</option>
            <option value="shadowsocks">Shadowsocks 2022</option>
          </Select>
        </Field>
        <Field label="Transport" htmlFor="in-transport">
          <Select
            id="in-transport"
            value={transport}
            onChange={(e) => setTransport(e.target.value as InboundCreate["transport"])}
          >
            <option value="tcp">TCP</option>
            <option value="ws">WebSocket</option>
            <option value="grpc">gRPC</option>
            <option value="httpupgrade">HTTPUpgrade</option>
            <option value="xhttp">XHTTP</option>
          </Select>
        </Field>
        <Field label="Security" htmlFor="in-security">
          <Select
            id="in-security"
            value={security}
            onChange={(e) => setSecurity(e.target.value as InboundCreate["security"])}
          >
            <option value="reality">Reality</option>
            <option value="tls">TLS</option>
            <option value="none">None</option>
          </Select>
        </Field>
        <Field label="Port" htmlFor="in-port">
          <Input id="in-port" inputMode="numeric" value={port} onChange={(e) => setPort(e.target.value)} required />
        </Field>
        <Field label="Listen address" htmlFor="in-listen">
          <Input id="in-listen" value={listen} onChange={(e) => setListen(e.target.value)} />
        </Field>

        {security === "reality" && (
          <Field label="Reality key" htmlFor="in-reality" hint="Create one below if the list is empty.">
            <Select id="in-reality" value={realityKey} onChange={(e) => setRealityKey(e.target.value)} required>
              <option value="">Choose…</option>
              {(keys.data ?? []).map((key) => (
                <option key={key.id} value={key.id}>
                  {key.name} ({key.dest})
                </option>
              ))}
            </Select>
          </Field>
        )}

        {protocol === "shadowsocks" && (
          <Field label="Method" htmlFor="in-ss" hint="The server key is generated by the panel.">
            <Select id="in-ss" value={ssMethod} onChange={(e) => setSsMethod(e.target.value)}>
              {ssMethods.map((method) => (
                <option key={method}>{method}</option>
              ))}
            </Select>
          </Field>
        )}

        {visionAllowed && (
          <label className="flex items-center gap-2 self-end pb-2 text-sm">
            <input type="checkbox" checked={vision} onChange={(e) => setVision(e.target.checked)} />
            XTLS Vision flow
          </label>
        )}

        {transport !== "tcp" && (
          <div className="sm:col-span-2">
            <Field
              label="Transport settings (JSON)"
              htmlFor="in-network"
              hint={transport === "grpc" ? 'For example {"serviceName":"api"}' : 'For example {"path":"/ws"}'}
            >
              <Textarea id="in-network" value={network} onChange={(e) => setNetwork(e.target.value)} />
            </Field>
          </div>
        )}

        {security === "tls" && (
          <div className="sm:col-span-2">
            <Field
              label="TLS settings (JSON)"
              htmlFor="in-tls"
              hint='Paths are on the node, for example {"certificates":[{"certificateFile":"/etc/ssl/fullchain.pem","keyFile":"/etc/ssl/key.pem"}]}'
            >
              <Textarea id="in-tls" value={tls} onChange={(e) => setTls(e.target.value)} required />
            </Field>
          </div>
        )}

        {error && (
          <p className="text-sm text-bad sm:col-span-2" role="alert">
            {error}
          </p>
        )}
      </form>
    </Dialog>
  );
}

function RealityKeys({ writable }: { writable: boolean }) {
  const toast = useToast();
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [dest, setDest] = useState("www.cloudflare.com:443");
  const [names, setNames] = useState("www.cloudflare.com");

  const keys = useQuery({ queryKey: ["reality-keys"], queryFn: async () => unwrap(await api.GET("/reality-keys")) });

  const create = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.POST("/reality-keys", {
          body: {
            name: name.trim(),
            dest: dest.trim(),
            server_names: names
              .split(",")
              .map((s) => s.trim())
              .filter(Boolean),
          },
        }),
      ),
    onSuccess: () => {
      toast.ok("Reality key created");
      setOpen(false);
      setName("");
      void queryClient.invalidateQueries({ queryKey: ["reality-keys"] });
    },
    onError: toast.error,
  });

  const remove = useMutation({
    mutationFn: async (id: number) => {
      const result = await api.DELETE("/reality-keys/{id}", { params: { path: { id } } });
      if (!result.response.ok) unwrap(result);
    },
    onSuccess: () => {
      toast.ok("Reality key deleted");
      void queryClient.invalidateQueries({ queryKey: ["reality-keys"] });
    },
    onError: toast.error,
  });

  return (
    <Card className="mt-4">
      <CardHeader
        title="Reality keys"
        description="Key pairs generated by the panel. The private half never leaves it except to the nodes that need it."
        actions={
          writable && (
            <Button size="sm" onClick={() => setOpen(true)}>
              <Plus className="size-4" /> New key
            </Button>
          )
        }
      />
      {keys.isPending ? (
        <Spinner />
      ) : keys.isError ? (
        <ErrorNote error={keys.error} />
      ) : keys.data.length === 0 ? (
        <Empty>No Reality keys.</Empty>
      ) : (
        <Table>
          <thead>
            <tr>
              <Th>Name</Th>
              <Th>Destination</Th>
              <Th>Public key</Th>
              <Th>Created</Th>
              <Th />
            </tr>
          </thead>
          <tbody>
            {keys.data.map((key) => (
              <tr key={key.id}>
                <Td className="font-medium">{key.name}</Td>
                <Td className="text-muted">{key.dest}</Td>
                <Td>
                  <code className="text-xs">{key.public_key}</code>
                </Td>
                <Td className="text-muted">{formatDate(key.created_at)}</Td>
                <Td className="text-right">
                  {writable && key.id !== undefined && (
                    <Button
                      size="sm"
                      variant="ghost"
                      aria-label={`Delete ${key.name}`}
                      onClick={() => window.confirm(`Delete ${key.name}?`) && remove.mutate(key.id!)}
                    >
                      <Trash2 className="size-4" />
                    </Button>
                  )}
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}

      <Dialog
        open={open}
        onOpenChange={setOpen}
        title="New Reality key"
        footer={
          <>
            <Button onClick={() => setOpen(false)}>Cancel</Button>
            <Button variant="primary" loading={create.isPending} onClick={() => create.mutate()}>
              Create
            </Button>
          </>
        }
      >
        <div className="flex flex-col gap-4">
          <Field label="Name" htmlFor="rk-name">
            <Input id="rk-name" value={name} onChange={(e) => setName(e.target.value)} required />
          </Field>
          <Field label="Destination" htmlFor="rk-dest" hint="host:port of a real TLS site the handshake imitates.">
            <Input id="rk-dest" value={dest} onChange={(e) => setDest(e.target.value)} />
          </Field>
          <Field label="Server names" htmlFor="rk-names" hint="Comma-separated; must be names the destination serves.">
            <Input id="rk-names" value={names} onChange={(e) => setNames(e.target.value)} />
          </Field>
        </div>
      </Dialog>
    </Card>
  );
}
