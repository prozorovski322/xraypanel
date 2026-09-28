import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ChevronLeft, ChevronRight, Plus, Search } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router";

import { api, idempotencyKey, unwrap, type Schemas } from "@/api/client";
import { useAuth } from "@/auth";
import { PageHeader } from "@/components/layout";
import { UserStatusBadge } from "@/components/status";
import { useToast } from "@/components/toast";
import {
  Button,
  Card,
  Dialog,
  Empty,
  ErrorNote,
  Field,
  Input,
  Select,
  Spinner,
  Table,
  Td,
  Th,
  UsageMeter,
} from "@/components/ui";
import { useDebounced } from "@/lib/hooks";
import { formatBytes, formatDate, formatRelative, parseBytes, usageRatio } from "@/lib/utils";

type UserStatus = Schemas["UserStatus"];
type SortKey = "username" | "traffic_used" | "expires_at" | "created_at" | "online_at";

const pageSize = 50;

export function UsersPage() {
  const { can } = useAuth();
  const [search, setSearch] = useState("");
  const [status, setStatus] = useState<UserStatus | "">("");
  const [sort, setSort] = useState<SortKey>("created_at");
  const [offset, setOffset] = useState(0);
  const [creating, setCreating] = useState(false);

  const query = useDebounced(search.trim());

  const users = useQuery({
    queryKey: ["users", "list", { query, status, sort, offset }],
    queryFn: async () =>
      unwrap(
        await api.GET("/users", {
          params: {
            query: {
              search: query || undefined,
              status: status ? [status] : undefined,
              sort,
              order: sort === "username" ? "asc" : "desc",
              limit: pageSize,
              offset,
            },
          },
        }),
      ),
    // The previous page stays on screen while the next loads, so paging does not flash empty.
    placeholderData: keepPreviousData,
  });

  const total = users.data?.total ?? 0;
  const items = users.data?.items ?? [];

  return (
    <>
      <PageHeader
        title="Users"
        description={users.data ? `${total} ${total === 1 ? "user" : "users"}` : undefined}
        actions={
          can("users:write") && (
            <Button variant="primary" onClick={() => setCreating(true)}>
              <Plus className="size-4" />
              New user
            </Button>
          )
        }
      />

      <Card>
        <div className="flex flex-wrap items-center gap-2 border-b border-border p-3">
          <div className="relative min-w-56 flex-1">
            <Search className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted" />
            <Input
              aria-label="Search users"
              placeholder="Search by username or note"
              className="pl-8"
              value={search}
              onChange={(e) => {
                setSearch(e.target.value);
                setOffset(0);
              }}
            />
          </div>
          <Select
            aria-label="Status"
            className="w-40"
            value={status}
            onChange={(e) => {
              setStatus(e.target.value as UserStatus | "");
              setOffset(0);
            }}
          >
            <option value="">All statuses</option>
            <option value="active">Active</option>
            <option value="limited">Limited</option>
            <option value="expired">Expired</option>
            <option value="disabled">Disabled</option>
          </Select>
          <Select aria-label="Sort" className="w-44" value={sort} onChange={(e) => setSort(e.target.value as SortKey)}>
            <option value="created_at">Newest first</option>
            <option value="username">Username</option>
            <option value="traffic_used">Most traffic</option>
            <option value="expires_at">Expiry</option>
            <option value="online_at">Last online</option>
          </Select>
        </div>

        {users.isPending ? (
          <Spinner />
        ) : users.isError ? (
          <ErrorNote error={users.error} />
        ) : items.length === 0 ? (
          <Empty>{query || status ? "No users match." : "No users yet."}</Empty>
        ) : (
          <Table>
            <thead>
              <tr>
                <Th>Username</Th>
                <Th>Status</Th>
                <Th>Traffic</Th>
                <Th>Expires</Th>
                <Th>Last online</Th>
              </tr>
            </thead>
            <tbody>
              {items.map((user) => (
                <tr key={user.id} className="hover:bg-surface-2">
                  <Td>
                    <Link to={`/users/${user.id}`} className="font-medium hover:underline">
                      {user.username}
                    </Link>
                    {user.note && <div className="max-w-64 truncate text-xs text-muted">{user.note}</div>}
                  </Td>
                  <Td>
                    <UserStatusBadge status={user.status} />
                  </Td>
                  <Td className="w-56">
                    <UsageMeter
                      ratio={usageRatio(user.traffic_used, user.traffic_limit)}
                      label={
                        user.traffic_limit
                          ? `${formatBytes(user.traffic_used)} of ${formatBytes(user.traffic_limit)}`
                          : `${formatBytes(user.traffic_used)} · no limit`
                      }
                    />
                  </Td>
                  <Td className="text-muted">{user.expires_at ? formatDate(user.expires_at) : "never"}</Td>
                  <Td className="text-muted">{formatRelative(user.online_at)}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}

        {total > pageSize && (
          <div className="flex items-center justify-between border-t border-border px-4 py-2 text-sm text-muted">
            <span className="num">
              {offset + 1}–{Math.min(offset + pageSize, total)} of {total}
            </span>
            <div className="flex gap-1">
              <Button
                size="sm"
                variant="ghost"
                disabled={offset === 0}
                onClick={() => setOffset(Math.max(0, offset - pageSize))}
                aria-label="Previous page"
              >
                <ChevronLeft className="size-4" />
              </Button>
              <Button
                size="sm"
                variant="ghost"
                disabled={offset + pageSize >= total}
                onClick={() => setOffset(offset + pageSize)}
                aria-label="Next page"
              >
                <ChevronRight className="size-4" />
              </Button>
            </div>
          </div>
        )}
      </Card>

      <CreateUserDialog open={creating} onOpenChange={setCreating} />
    </>
  );
}

function CreateUserDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const toast = useToast();
  const queryClient = useQueryClient();
  const navigate = useNavigate();

  const [username, setUsername] = useState("");
  const [limit, setLimit] = useState("");
  const [strategy, setStrategy] = useState<Schemas["ResetStrategy"]>("monthly");
  const [days, setDays] = useState("30");
  const [note, setNote] = useState("");
  const [error, setError] = useState<string | null>(null);
  // One key per dialog opening: a double-click or a retried submit creates one user.
  const [key, setKey] = useState(idempotencyKey);

  const create = useMutation({
    mutationFn: async () => {
      const trafficLimit = limit.trim() === "" ? 0 : parseBytes(limit);
      if (trafficLimit === null) throw new Error('Traffic limit must be a size such as "100 GiB", or empty for none.');

      const expiresIn = days.trim() === "" ? null : Number(days);
      if (expiresIn !== null && (!Number.isFinite(expiresIn) || expiresIn <= 0)) {
        throw new Error("Days must be a positive number, or empty for no expiry.");
      }

      return unwrap(
        await api.POST("/users", {
          params: { header: { "Idempotency-Key": key } },
          body: {
            username: username.trim(),
            traffic_limit: trafficLimit,
            reset_strategy: strategy,
            expires_at: expiresIn === null ? null : new Date(Date.now() + expiresIn * 86_400_000).toISOString(),
            note: note.trim() || undefined,
          },
        }),
      );
    },
    onSuccess: (user) => {
      toast.ok(`Created ${user.username}`);
      void queryClient.invalidateQueries({ queryKey: ["users"] });
      onOpenChange(false);
      setUsername("");
      setLimit("");
      setNote("");
      setKey(idempotencyKey());
      if (user.id) navigate(`/users/${user.id}`);
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
      title="New user"
      description="The user gets the default groups, and with them every inbound those groups include."
      footer={
        <>
          <Button onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button variant="primary" type="submit" form="create-user" loading={create.isPending}>
            Create
          </Button>
        </>
      }
    >
      <form id="create-user" className="flex flex-col gap-4" onSubmit={submit}>
        <Field label="Username" htmlFor="new-username" hint="Letters, digits, dot, dash and underscore.">
          <Input id="new-username" value={username} onChange={(e) => setUsername(e.target.value)} required autoFocus />
        </Field>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Traffic limit" htmlFor="new-limit" hint="Empty for no limit.">
            <Input id="new-limit" placeholder="100 GiB" value={limit} onChange={(e) => setLimit(e.target.value)} />
          </Field>
          <Field label="Resets" htmlFor="new-strategy">
            <Select
              id="new-strategy"
              value={strategy}
              onChange={(e) => setStrategy(e.target.value as Schemas["ResetStrategy"])}
            >
              <option value="never">Never</option>
              <option value="daily">Daily</option>
              <option value="weekly">Weekly</option>
              <option value="monthly">Monthly</option>
            </Select>
          </Field>
        </div>
        <Field label="Expires in (days)" htmlFor="new-days" hint="Empty for no expiry.">
          <Input id="new-days" inputMode="numeric" value={days} onChange={(e) => setDays(e.target.value)} />
        </Field>
        <Field label="Note" htmlFor="new-note">
          <Input id="new-note" value={note} onChange={(e) => setNote(e.target.value)} />
        </Field>
        {error && (
          <p className="text-sm text-bad" role="alert">
            {error}
          </p>
        )}
      </form>
    </Dialog>
  );
}
