import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, Check, Copy, KeyRound, Trash2 } from "lucide-react";
import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router";

import { api, unwrap, type Schemas } from "@/api/client";
import { useAuth } from "@/auth";
import { PageHeader } from "@/components/layout";
import { NodeStatusBadge } from "@/components/status";
import { useToast } from "@/components/toast";
import { TrafficChart } from "@/components/traffic-chart";
import { Badge, Button, Card, CardHeader, Dialog, Empty, ErrorNote, Spinner, Table, Td, Th } from "@/components/ui";
import { useCopy } from "@/lib/hooks";
import { formatBytes, formatDateTime, formatRelative } from "@/lib/utils";

export function NodeDetailPage() {
  const params = useParams();
  const id = Number(params["id"]);
  const { can } = useAuth();
  const toast = useToast();
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const [enrollment, setEnrollment] = useState<Schemas["Enrollment"] | null>(null);
  const [deleting, setDeleting] = useState(false);

  const node = useQuery({
    queryKey: ["nodes", id],
    queryFn: async () => unwrap(await api.GET("/nodes/{id}", { params: { path: { id } } })),
    refetchInterval: 5_000,
    enabled: Number.isFinite(id),
  });

  const connection = useQuery({
    queryKey: ["nodes", id, "connection"],
    queryFn: async () => unwrap(await api.GET("/nodes/{id}/connection", { params: { path: { id } } })),
    refetchInterval: 5_000,
    enabled: Number.isFinite(id),
  });

  const toggle = useMutation({
    mutationFn: async (enabled: boolean) =>
      unwrap(await api.PATCH("/nodes/{id}", { params: { path: { id } }, body: { enabled } })),
    onSuccess: (n) => {
      toast.ok(n.enabled ? "Node enabled" : "Node disabled");
      void queryClient.invalidateQueries({ queryKey: ["nodes"] });
    },
    onError: toast.error,
  });

  const mint = useMutation({
    mutationFn: async () =>
      unwrap(await api.POST("/nodes/{id}/enrollment-tokens", { params: { path: { id } } })),
    onSuccess: (e) => {
      setEnrollment(e);
      void queryClient.invalidateQueries({ queryKey: ["nodes", id, "tokens"] });
    },
    onError: toast.error,
  });

  const remove = useMutation({
    mutationFn: async () => {
      const result = await api.DELETE("/nodes/{id}", { params: { path: { id } } });
      if (!result.response.ok) unwrap(result);
    },
    onSuccess: () => {
      toast.ok("Node deleted");
      navigate("/nodes", { replace: true });
      // As for users: only the list is refreshed, never the deleted node's own queries.
      void queryClient.invalidateQueries({ queryKey: ["nodes"], exact: true });
    },
    onError: toast.error,
  });

  if (!Number.isFinite(id)) return <ErrorNote error={new Error("That is not a node id.")} />;
  if (node.isPending) return <Spinner />;
  if (node.isError) return <ErrorNote error={node.error} />;

  const n = node.data;
  const writable = can("nodes:write");
  const behind = (n.applied_version ?? 0) < (n.config_version ?? 0);

  return (
    <>
      <Link to="/nodes" className="mb-3 inline-flex items-center gap-1 text-sm text-muted hover:text-text">
        <ArrowLeft className="size-4" /> Nodes
      </Link>
      <PageHeader
        title={n.name ?? "Node"}
        description={n.address}
        actions={
          writable && (
            <>
              <Button onClick={() => mint.mutate()} loading={mint.isPending}>
                <KeyRound className="size-4" /> Enrollment token
              </Button>
              <Button onClick={() => toggle.mutate(!n.enabled)} loading={toggle.isPending}>
                {n.enabled ? "Disable" : "Enable"}
              </Button>
              <Button variant="danger" onClick={() => setDeleting(true)}>
                <Trash2 className="size-4" /> Delete
              </Button>
            </>
          )
        }
      />

      <div className="grid gap-4 lg:grid-cols-2">
        <Card className="p-4">
          <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2.5 text-sm">
            <dt className="text-muted">Status</dt>
            <dd>
              <NodeStatusBadge status={n.status} enabled={n.enabled} />
            </dd>
            <dt className="text-muted">Config</dt>
            <dd className="num">
              applied {n.applied_version ?? 0} of {n.config_version ?? 0}
              {behind && (
                <Badge tone="warn" className="ml-2">
                  behind
                </Badge>
              )}
            </dd>
            {n.last_error && (
              <>
                <dt className="text-muted">Last error</dt>
                <dd className="break-words text-bad">{n.last_error}</dd>
              </>
            )}
            <dt className="text-muted">Xray</dt>
            <dd className="num">{n.xray_version || "—"}</dd>
            <dt className="text-muted">Agent</dt>
            <dd className="num">{n.agent_version || "—"}</dd>
            <dt className="text-muted">Traffic</dt>
            <dd className="num">{formatBytes(n.traffic_used)}</dd>
            <dt className="text-muted">Last seen</dt>
            <dd>{formatRelative(n.last_seen_at)}</dd>
          </dl>
        </Card>

        <Card>
          <CardHeader
            title="Live connection"
            description="What this panel process holds right now, which is not always what the stored status says."
          />
          {connection.isPending ? (
            <Spinner />
          ) : connection.isError ? (
            <ErrorNote error={connection.error} />
          ) : connection.data.connected ? (
            <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2.5 p-4 text-sm">
              <dt className="text-muted">Stream</dt>
              <dd>
                <Badge tone="ok">open</Badge>
              </dd>
              <dt className="text-muted">From</dt>
              <dd className="num">{connection.data.remote_addr}</dd>
              <dt className="text-muted">Connected</dt>
              <dd>{formatDateTime(connection.data.connected_at)}</dd>
              <dt className="text-muted">Heartbeat</dt>
              <dd>{formatRelative(connection.data.last_heartbeat)}</dd>
              <dt className="text-muted">Xray running</dt>
              <dd>
                {connection.data.xray_running ? <Badge tone="ok">yes</Badge> : <Badge tone="bad">no</Badge>}
              </dd>
            </dl>
          ) : (
            <Empty>No open stream. The agent is not running, cannot reach the panel, or is not enrolled yet.</Empty>
          )}
        </Card>
      </div>

      <NodeInbounds nodeId={id} writable={can("nodes:write")} />
      <NodeTraffic nodeId={id} />

      <EnrollmentDialog enrollment={enrollment} onClose={() => setEnrollment(null)} />

      <Dialog
        open={deleting}
        onOpenChange={setDeleting}
        title={`Delete ${n.name}?`}
        description="The node's certificate stops being accepted and its agent is disconnected. Users on it lose access."
        footer={
          <>
            <Button onClick={() => setDeleting(false)}>Cancel</Button>
            <Button variant="danger" loading={remove.isPending} onClick={() => remove.mutate()}>
              Delete node
            </Button>
          </>
        }
      >
        <p className="text-sm text-muted">To take a node out of service for a while, disable it instead.</p>
      </Dialog>
    </>
  );
}

function NodeInbounds({ nodeId, writable }: { nodeId: number; writable: boolean }) {
  const toast = useToast();
  const queryClient = useQueryClient();

  const attached = useQuery({
    queryKey: ["nodes", nodeId, "inbounds"],
    queryFn: async () => unwrap(await api.GET("/nodes/{id}/inbounds", { params: { path: { id: nodeId } } })),
  });
  const all = useQuery({
    queryKey: ["inbounds"],
    queryFn: async () => unwrap(await api.GET("/inbounds")),
  });

  const change = useMutation({
    mutationFn: async ({ inboundId, attach }: { inboundId: number; attach: boolean }) => {
      const options = { params: { path: { id: nodeId, inboundID: inboundId } } };
      const result = attach
        ? await api.PUT("/nodes/{id}/inbounds/{inboundID}", options)
        : await api.DELETE("/nodes/{id}/inbounds/{inboundID}", options);
      if (!result.response.ok) unwrap(result);
    },
    onSuccess: (_, { attach }) => {
      toast.ok(attach ? "Inbound attached; the node picks it up on its next heartbeat" : "Inbound detached");
      void queryClient.invalidateQueries({ queryKey: ["nodes", nodeId] });
    },
    onError: toast.error,
  });

  const attachedIds = new Set((attached.data ?? []).map((inbound) => inbound.id));

  return (
    <Card className="mt-4">
      <CardHeader
        title="Inbounds on this node"
        description="Detaching is applied without restarting the core; attaching a new one restarts it."
      />
      {attached.isPending || all.isPending ? (
        <Spinner />
      ) : attached.isError ? (
        <ErrorNote error={attached.error} />
      ) : all.isError ? (
        <ErrorNote error={all.error} />
      ) : (all.data ?? []).length === 0 ? (
        <Empty>
          No inbounds exist yet. <Link to="/inbounds" className="underline">Create one</Link> first.
        </Empty>
      ) : (
        <Table>
          <thead>
            <tr>
              <Th>Inbound</Th>
              <Th>Protocol</Th>
              <Th>Port</Th>
              <Th className="text-right">On this node</Th>
            </tr>
          </thead>
          <tbody>
            {(all.data ?? []).map((inbound) => {
              const on = attachedIds.has(inbound.id);
              return (
                <tr key={inbound.id}>
                  <Td className="font-medium">{inbound.tag}</Td>
                  <Td className="text-muted">
                    {inbound.protocol} · {inbound.transport} · {inbound.security}
                  </Td>
                  <Td className="num">{inbound.listen_port}</Td>
                  <Td className="text-right">
                    {writable ? (
                      <Button
                        size="sm"
                        variant={on ? "secondary" : "ghost"}
                        loading={change.isPending && change.variables?.inboundId === inbound.id}
                        onClick={() => inbound.id && change.mutate({ inboundId: inbound.id, attach: !on })}
                      >
                        {on ? "Detach" : "Attach"}
                      </Button>
                    ) : on ? (
                      <Badge tone="ok">attached</Badge>
                    ) : (
                      <span className="text-muted">—</span>
                    )}
                  </Td>
                </tr>
              );
            })}
          </tbody>
        </Table>
      )}
    </Card>
  );
}

function NodeTraffic({ nodeId }: { nodeId: number }) {
  const to = new Date().toISOString().slice(0, 10);
  const from = new Date(Date.now() - 29 * 86_400_000).toISOString().slice(0, 10);

  const traffic = useQuery({
    queryKey: ["nodes", nodeId, "traffic", from, to],
    queryFn: async () =>
      unwrap(await api.GET("/nodes/{id}/traffic", { params: { path: { id: nodeId }, query: { from, to } } })),
  });

  return (
    <Card className="mt-4">
      <CardHeader title="Traffic, last 30 days" description="All users on this node. Days are UTC." />
      {traffic.isPending ? (
        <Spinner />
      ) : traffic.isError ? (
        <ErrorNote error={traffic.error} />
      ) : (
        <TrafficChart
          from={from}
          to={to}
          days={(traffic.data.days ?? []).map((d) => ({ day: d.day, uplink: d.uplink, downlink: d.downlink }))}
        />
      )}
    </Card>
  );
}

/**
 * EnrollmentDialog shows a freshly minted token exactly once, with everything the node's
 * operator has to paste. The panel's node address is not known here — the panel does not
 * know which of its names nodes should dial — so that one line is left for them to fill in.
 */
function EnrollmentDialog({ enrollment, onClose }: { enrollment: Schemas["Enrollment"] | null; onClose: () => void }) {
  const [copied, copy] = useCopy();

  const env = enrollment
    ? [
        "NODE_PANEL_ADDR=panel.example.com:8443",
        `NODE_CA_PIN=${enrollment.ca_pin ?? ""}`,
        `NODE_ENROLLMENT_TOKEN=${enrollment.token ?? ""}`,
      ].join("\n")
    : "";

  return (
    <Dialog
      open={enrollment !== null}
      onOpenChange={(open) => !open && onClose()}
      wide
      title="Enrollment token"
      description={`Single use, valid until ${formatDateTime(enrollment?.expires_at)}. It is shown once and cannot be read back.`}
      footer={<Button onClick={onClose}>Done</Button>}
    >
      <div className="flex flex-col gap-3">
        <p className="text-sm text-muted">
          Put these in the node's environment (see <code>deploy/node.env.example</code>) and replace the address with the
          host and node port nodes should dial.
        </p>
        <pre className="overflow-x-auto rounded-md bg-surface-2 p-3 text-xs">{env}</pre>
        <div>
          <Button size="sm" onClick={() => void copy("env", env)}>
            {copied === "env" ? <Check className="size-4" /> : <Copy className="size-4" />}
            {copied === "env" ? "Copied" : "Copy"}
          </Button>
        </div>
        <p className="text-xs text-muted">
          The pin is what lets the node verify this panel before it sends the token. Without it the token would go to
          whoever answers at that address.
        </p>
      </div>
    </Dialog>
  );
}
