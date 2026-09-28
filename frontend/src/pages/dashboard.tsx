import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router";

import { api, unwrap } from "@/api/client";
import { useAuth } from "@/auth";
import { PageHeader } from "@/components/layout";
import { NodeStatusBadge, UserStatusBadge } from "@/components/status";
import { Card, CardHeader, Empty, ErrorNote, Spinner, Table, Td, Th, UsageMeter } from "@/components/ui";
import { formatBytes, formatRelative, usageRatio } from "@/lib/utils";

/**
 * The dashboard answers three questions an operator arrives with: is everything up, who is
 * using the most, and how much is moving. It polls, because "is everything up" is the one
 * that goes stale fastest; the figures are a handful of aggregates and cheap to recompute.
 */
export function DashboardPage() {
  const { can } = useAuth();

  const summary = useQuery({
    queryKey: ["stats", "summary"],
    queryFn: async () => unwrap(await api.GET("/stats/summary")),
    refetchInterval: 10_000,
  });

  return (
    <>
      <PageHeader title="Dashboard" description="Refreshes every few seconds." />

      {summary.isPending ? (
        <Spinner />
      ) : summary.isError ? (
        <ErrorNote error={summary.error} />
      ) : (
        <div className="mb-6 grid grid-cols-2 gap-3 lg:grid-cols-4">
          <Stat
            label="Active users"
            value={String(summary.data.users?.["active"] ?? 0)}
            detail={`${summary.data.users?.["limited"] ?? 0} limited · ${summary.data.users?.["expired"] ?? 0} expired`}
          />
          <Stat
            label="Online now"
            value={String(summary.data.online_users ?? 0)}
            detail={`moved traffic in the last ${Math.round((summary.data.online_window_seconds ?? 300) / 60)} min`}
          />
          <Stat
            label="Traffic today"
            value={formatBytes((summary.data.traffic_today?.uplink ?? 0) + (summary.data.traffic_today?.downlink ?? 0))}
            detail={`this month ${formatBytes(
              (summary.data.traffic_month?.uplink ?? 0) + (summary.data.traffic_month?.downlink ?? 0),
            )}`}
          />
          <Stat
            label="Nodes connected"
            value={`${summary.data.nodes?.["connected"] ?? 0} / ${Object.values(summary.data.nodes ?? {}).reduce(
              (a, b) => a + b,
              0,
            )}`}
            detail={
              (summary.data.nodes?.["error"] ?? 0) > 0
                ? `${summary.data.nodes?.["error"]} in error`
                : `${summary.data.nodes?.["disconnected"] ?? 0} disconnected`
            }
            alarm={(summary.data.nodes?.["error"] ?? 0) > 0}
          />
        </div>
      )}

      <div className="grid gap-4 lg:grid-cols-2">
        {can("users:read") && <TopConsumers />}
        {can("nodes:read") && <NodesAtAGlance />}
      </div>
    </>
  );
}

/**
 * Stat is a headline number. Not a chart: one figure, stated plainly, with what it means
 * underneath.
 */
function Stat({ label, value, detail, alarm }: { label: string; value: string; detail?: string; alarm?: boolean }) {
  return (
    <Card className="p-4">
      <div className="text-xs font-medium text-muted">{label}</div>
      <div className="num mt-1 text-2xl font-semibold">{value}</div>
      {detail && <div className={alarm ? "mt-1 text-xs font-medium text-bad" : "mt-1 text-xs text-muted"}>{detail}</div>}
    </Card>
  );
}

function TopConsumers() {
  const users = useQuery({
    queryKey: ["users", "top"],
    queryFn: async () =>
      unwrap(await api.GET("/users", { params: { query: { sort: "traffic_used", order: "desc", limit: 10 } } })),
    refetchInterval: 30_000,
  });

  return (
    <Card>
      <CardHeader title="Top consumers" description="Traffic used in the current period." />
      {users.isPending ? (
        <Spinner />
      ) : users.isError ? (
        <ErrorNote error={users.error} />
      ) : (users.data.items ?? []).length === 0 ? (
        <Empty>No users yet.</Empty>
      ) : (
        <Table>
          <tbody>
            {(users.data.items ?? []).map((user) => (
              <tr key={user.id}>
                <Td>
                  <Link to={`/users/${user.id}`} className="font-medium hover:underline">
                    {user.username}
                  </Link>
                </Td>
                <Td>
                  <UserStatusBadge status={user.status} />
                </Td>
                <Td className="w-48">
                  <UsageMeter
                    ratio={usageRatio(user.traffic_used, user.traffic_limit)}
                    label={
                      user.traffic_limit
                        ? `${formatBytes(user.traffic_used)} of ${formatBytes(user.traffic_limit)}`
                        : `${formatBytes(user.traffic_used)} · no limit`
                    }
                  />
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
    </Card>
  );
}

function NodesAtAGlance() {
  const nodes = useQuery({
    queryKey: ["nodes"],
    queryFn: async () => unwrap(await api.GET("/nodes")),
    refetchInterval: 5_000,
  });

  const items = nodes.data ?? [];

  return (
    <Card>
      <CardHeader title="Nodes" description="Live status, refreshed every five seconds." />
      {nodes.isPending ? (
        <Spinner />
      ) : nodes.isError ? (
        <ErrorNote error={nodes.error} />
      ) : items.length === 0 ? (
        <Empty>No nodes yet.</Empty>
      ) : (
        <Table>
          <thead>
            <tr>
              <Th>Node</Th>
              <Th>Status</Th>
              <Th>Last seen</Th>
              <Th className="text-right">Config</Th>
            </tr>
          </thead>
          <tbody>
            {items.map((node) => {
              const behind = (node.applied_version ?? 0) < (node.config_version ?? 0);
              return (
                <tr key={node.id}>
                  <Td>
                    <Link to={`/nodes/${node.id}`} className="font-medium hover:underline">
                      {node.name}
                    </Link>
                  </Td>
                  <Td>
                    <NodeStatusBadge status={node.status} enabled={node.enabled} />
                  </Td>
                  <Td className="text-muted">{formatRelative(node.last_seen_at)}</Td>
                  <Td className={behind ? "num text-right text-warn" : "num text-right text-muted"}>
                    {node.applied_version ?? 0}/{node.config_version ?? 0}
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
