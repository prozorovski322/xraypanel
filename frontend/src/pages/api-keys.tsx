import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, Copy, Plus } from "lucide-react";
import { useState, type FormEvent } from "react";

import { api, unwrap, type Schemas } from "@/api/client";
import { useAuth } from "@/auth";
import { PageHeader } from "@/components/layout";
import { useToast } from "@/components/toast";
import { Badge, Button, Card, Dialog, Empty, ErrorNote, Field, Input, Spinner, Table, Td, Th } from "@/components/ui";
import { useCopy } from "@/lib/hooks";
import { formatDate, formatRelative } from "@/lib/utils";

type Scope = Schemas["Scope"];

// Grouped by resource, write after read, so a scope's neighbour is its obvious alternative.
const scopes: { scope: Scope; hint: string }[] = [
  { scope: "users:read", hint: "list and read users, their subscriptions and traffic" },
  { scope: "users:write", hint: "create, change, renew and delete users" },
  { scope: "nodes:read", hint: "list nodes and their status" },
  { scope: "nodes:write", hint: "change nodes, issue enrollment tokens" },
  { scope: "inbounds:read", hint: "list inbounds, hosts, groups and Reality keys" },
  { scope: "inbounds:write", hint: "change them" },
  { scope: "stats:read", hint: "dashboard figures" },
  { scope: "admins:read", hint: "list API keys" },
  { scope: "admins:write", hint: "create and revoke API keys" },
  { scope: "audit:read", hint: "read the audit log" },
  { scope: "webhooks:read", hint: "list webhook endpoints" },
  { scope: "webhooks:write", hint: "register and change webhook endpoints" },
];

export function ApiKeysPage() {
  const { can } = useAuth();
  const toast = useToast();
  const queryClient = useQueryClient();
  const [creating, setCreating] = useState(false);
  const [created, setCreated] = useState<string | null>(null);
  const [copied, copy] = useCopy();

  const keys = useQuery({ queryKey: ["api-keys"], queryFn: async () => unwrap(await api.GET("/api-keys")) });

  const revoke = useMutation({
    mutationFn: async (id: number) => {
      const result = await api.DELETE("/api-keys/{id}", { params: { path: { id } } });
      if (!result.response.ok) unwrap(result);
    },
    onSuccess: () => {
      toast.ok("Key revoked");
      void queryClient.invalidateQueries({ queryKey: ["api-keys"] });
    },
    onError: toast.error,
  });

  const writable = can("admins:write");

  return (
    <>
      <PageHeader
        title="API keys"
        description="For bots, billing systems and scripts. A key carries only the scopes it was given."
        actions={
          writable && (
            <Button variant="primary" onClick={() => setCreating(true)}>
              <Plus className="size-4" /> New key
            </Button>
          )
        }
      />
      <Card>
        {keys.isPending ? (
          <Spinner />
        ) : keys.isError ? (
          <ErrorNote error={keys.error} />
        ) : keys.data.length === 0 ? (
          <Empty>No API keys.</Empty>
        ) : (
          <Table>
            <thead>
              <tr>
                <Th>Name</Th>
                <Th>Key</Th>
                <Th>Scopes</Th>
                <Th>Last used</Th>
                <Th>Expires</Th>
                <Th />
              </tr>
            </thead>
            <tbody>
              {keys.data.map((key) => (
                <tr key={key.id} className={key.revoked_at ? "opacity-60" : undefined}>
                  <Td className="font-medium">{key.name}</Td>
                  <Td>
                    <code className="text-xs">{key.prefix}…</code>
                  </Td>
                  <Td>
                    <div className="flex max-w-80 flex-wrap gap-1">
                      {(key.scopes ?? []).map((scope) => (
                        <Badge key={scope}>{scope}</Badge>
                      ))}
                    </div>
                  </Td>
                  <Td className="text-muted">{formatRelative(key.last_used_at)}</Td>
                  <Td className="text-muted">{key.expires_at ? formatDate(key.expires_at) : "never"}</Td>
                  <Td className="text-right">
                    {key.revoked_at ? (
                      <Badge tone="bad">revoked</Badge>
                    ) : (
                      writable &&
                      key.id !== undefined && (
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() =>
                            window.confirm(`Revoke ${key.name}? Anything using it stops working at once.`) &&
                            revoke.mutate(key.id!)
                          }
                        >
                          Revoke
                        </Button>
                      )
                    )}
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>

      <CreateKeyDialog
        open={creating}
        onOpenChange={setCreating}
        onCreated={(key) => {
          setCreating(false);
          setCreated(key);
        }}
      />

      <Dialog
        open={created !== null}
        onOpenChange={(open) => !open && setCreated(null)}
        title="Key created"
        description="Copy it now. Only its hash is stored, so it cannot be shown again."
        footer={<Button onClick={() => setCreated(null)}>Done</Button>}
      >
        <div className="flex items-center gap-2">
          <Input readOnly value={created ?? ""} className="font-mono text-xs" aria-label="API key" />
          <Button size="sm" onClick={() => created && void copy("key", created)}>
            {copied === "key" ? <Check className="size-4" /> : <Copy className="size-4" />}
            {copied === "key" ? "Copied" : "Copy"}
          </Button>
        </div>
      </Dialog>
    </>
  );
}

function CreateKeyDialog({
  open,
  onOpenChange,
  onCreated,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onCreated: (key: string) => void;
}) {
  const toast = useToast();
  const queryClient = useQueryClient();
  const [name, setName] = useState("");
  const [selected, setSelected] = useState<Set<Scope>>(new Set(["users:read"]));
  const [days, setDays] = useState("");

  const create = useMutation({
    mutationFn: async () => {
      const n = days.trim() === "" ? null : Number(days);
      if (n !== null && (!Number.isFinite(n) || n <= 0)) throw new Error("Days must be a positive number.");
      return unwrap(
        await api.POST("/api-keys", {
          body: {
            name: name.trim(),
            scopes: [...selected],
            expires_at: n === null ? null : new Date(Date.now() + n * 86_400_000).toISOString(),
          },
        }),
      );
    },
    onSuccess: (result) => {
      void queryClient.invalidateQueries({ queryKey: ["api-keys"] });
      setName("");
      const key = result.key;
      if (key) onCreated(key);
      else toast.error("The panel created the key but did not return it.");
    },
    onError: toast.error,
  });

  function submit(event: FormEvent) {
    event.preventDefault();
    create.mutate();
  }

  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      wide
      title="New API key"
      description="Give it the fewest scopes that do the job: a key that leaks can do exactly what it was allowed to."
      footer={
        <>
          <Button onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button variant="primary" type="submit" form="key-form" loading={create.isPending}>
            Create
          </Button>
        </>
      }
    >
      <form id="key-form" className="flex flex-col gap-4" onSubmit={submit}>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <Field label="Name" htmlFor="k-name" hint="What uses it, e.g. telegram-bot.">
            <Input id="k-name" value={name} onChange={(e) => setName(e.target.value)} required autoFocus />
          </Field>
          <Field label="Expires in (days)" htmlFor="k-days" hint="Empty for no expiry.">
            <Input id="k-days" inputMode="numeric" value={days} onChange={(e) => setDays(e.target.value)} />
          </Field>
        </div>
        <fieldset className="grid grid-cols-1 gap-1.5 sm:grid-cols-2">
          <legend className="mb-1 text-sm font-medium">Scopes</legend>
          {scopes.map(({ scope, hint }) => (
            <label key={scope} className="flex items-start gap-2 text-sm">
              <input
                type="checkbox"
                className="mt-1"
                checked={selected.has(scope)}
                onChange={() =>
                  setSelected((current) => {
                    const next = new Set(current);
                    if (next.has(scope)) next.delete(scope);
                    else next.add(scope);
                    return next;
                  })
                }
              />
              <span>
                <code className="text-xs">{scope}</code>
                <span className="block text-xs text-muted">{hint}</span>
              </span>
            </label>
          ))}
        </fieldset>
      </form>
    </Dialog>
  );
}
