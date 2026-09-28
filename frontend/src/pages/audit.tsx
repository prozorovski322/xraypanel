import { useInfiniteQuery } from "@tanstack/react-query";
import { Fragment, useState } from "react";

import { api, unwrap } from "@/api/client";
import { PageHeader } from "@/components/layout";
import { Badge, Button, Card, Empty, ErrorNote, Input, Select, Spinner, Table, Td, Th } from "@/components/ui";
import { useDebounced } from "@/lib/hooks";
import { formatDateTime } from "@/lib/utils";

type ActorType = "admin" | "api_key" | "system" | "node";

/**
 * The audit log, newest first, paged by entry id so that entries written while somebody is
 * reading do not shift the pages under them. "Load more" rather than numbered pages, because
 * the log only grows and there is no meaningful page 7.
 */
export function AuditPage() {
  const [entityType, setEntityType] = useState("");
  const [entityId, setEntityId] = useState("");
  const [action, setAction] = useState("");
  const [actorType, setActorType] = useState<ActorType | "">("");
  const [expanded, setExpanded] = useState<number | null>(null);

  const filters = useDebounced({ entityType, entityId: entityId.trim(), action: action.trim(), actorType });

  const log = useInfiniteQuery({
    queryKey: ["audit", filters],
    initialPageParam: undefined as number | undefined,
    queryFn: async ({ pageParam }) =>
      unwrap(
        await api.GET("/audit", {
          params: {
            query: {
              before: pageParam,
              entity_type: filters.entityType || undefined,
              entity_id: filters.entityId || undefined,
              action: filters.action || undefined,
              actor_type: filters.actorType || undefined,
              limit: 50,
            },
          },
        }),
      ),
    getNextPageParam: (last) => last.next_before ?? undefined,
  });

  const entries = log.data?.pages.flatMap((page) => page.items) ?? [];

  return (
    <>
      <PageHeader title="Audit log" description="Every change, who made it, and what it was before." />
      <Card>
        <div className="flex flex-wrap gap-2 border-b border-border p-3">
          <Select aria-label="Entity" className="w-40" value={entityType} onChange={(e) => setEntityType(e.target.value)}>
            <option value="">All entities</option>
            <option value="user">Users</option>
            <option value="node">Nodes</option>
            <option value="inbound">Inbounds</option>
            <option value="group">Groups</option>
            <option value="host">Hosts</option>
            <option value="admin">Administrators</option>
            <option value="api_key">API keys</option>
            <option value="webhook_endpoint">Webhooks</option>
          </Select>
          <Input
            aria-label="Entity id"
            placeholder="Entity id"
            className="w-32"
            value={entityId}
            onChange={(e) => setEntityId(e.target.value)}
          />
          <Input
            aria-label="Action"
            placeholder="Action, e.g. user.limited"
            className="w-56"
            value={action}
            onChange={(e) => setAction(e.target.value)}
          />
          <Select
            aria-label="Actor"
            className="w-36"
            value={actorType}
            onChange={(e) => setActorType(e.target.value as ActorType | "")}
          >
            <option value="">Any actor</option>
            <option value="admin">Administrator</option>
            <option value="api_key">API key</option>
            <option value="system">System</option>
            <option value="node">Node</option>
          </Select>
        </div>

        {log.isPending ? (
          <Spinner />
        ) : log.isError ? (
          <ErrorNote error={log.error} />
        ) : entries.length === 0 ? (
          <Empty>Nothing matches.</Empty>
        ) : (
          <Table>
            <thead>
              <tr>
                <Th>When</Th>
                <Th>Actor</Th>
                <Th>Action</Th>
                <Th>Entity</Th>
                <Th>From</Th>
              </tr>
            </thead>
            <tbody>
              {entries.map((entry) => (
                <Fragment key={entry.id}>
                  <tr
                    className="cursor-pointer hover:bg-surface-2"
                    onClick={() => setExpanded(expanded === entry.id ? null : entry.id)}
                    aria-expanded={expanded === entry.id}
                  >
                    <Td className="whitespace-nowrap text-muted">{formatDateTime(entry.at)}</Td>
                    <Td>
                      <Badge>{entry.actor_type}</Badge> {entry.actor_label}
                    </Td>
                    <Td>
                      <code className="text-xs">{entry.action}</code>
                    </Td>
                    <Td className="text-muted">
                      {entry.entity_type}
                      {entry.entity_id ? ` #${entry.entity_id}` : ""}
                    </Td>
                    <Td className="num text-muted">{entry.ip || "—"}</Td>
                  </tr>
                  {expanded === entry.id && (
                    <tr>
                      <Td colSpan={5} className="bg-surface-2">
                        {entry.diff ? (
                          <pre className="overflow-x-auto text-xs">{JSON.stringify(entry.diff, null, 2)}</pre>
                        ) : (
                          <span className="text-sm text-muted">No recorded change.</span>
                        )}
                      </Td>
                    </tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </Table>
        )}

        {log.hasNextPage && (
          <div className="border-t border-border p-3 text-center">
            <Button onClick={() => void log.fetchNextPage()} loading={log.isFetchingNextPage}>
              Load older entries
            </Button>
          </div>
        )}
      </Card>
    </>
  );
}
