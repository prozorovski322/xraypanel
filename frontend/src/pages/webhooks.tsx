import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, Copy, Plus, Trash2 } from "lucide-react";
import { useState, type FormEvent } from "react";

import { api, unwrap, type Schemas } from "@/api/client";
import { useAuth } from "@/auth";
import { PageHeader } from "@/components/layout";
import { useToast } from "@/components/toast";
import { Badge, Button, Card, Dialog, Empty, ErrorNote, Field, Input, Spinner, Table, Td, Th } from "@/components/ui";
import { useCopy } from "@/lib/hooks";
import { formatDate } from "@/lib/utils";

type WebhookEvent = Schemas["WebhookEvent"];

const events: { event: WebhookEvent; hint: string }[] = [
  { event: "user.created", hint: "a subscriber was added" },
  { event: "user.limited", hint: "they used up their traffic" },
  { event: "user.expired", hint: "their subscription ended" },
  { event: "user.renewed", hint: "their subscription was extended" },
];

export function WebhooksPage() {
  const { can } = useAuth();
  const toast = useToast();
  const queryClient = useQueryClient();
  const [creating, setCreating] = useState(false);
  const [secret, setSecret] = useState<string | null>(null);
  const [copied, copy] = useCopy();

  const hooks = useQuery({ queryKey: ["webhooks"], queryFn: async () => unwrap(await api.GET("/webhooks")) });

  const toggle = useMutation({
    mutationFn: async ({ id, enabled }: { id: number; enabled: boolean }) =>
      unwrap(await api.PATCH("/webhooks/{id}", { params: { path: { id } }, body: { enabled } })),
    onSuccess: (hook) => {
      toast.ok(hook.enabled ? "Endpoint enabled" : "Endpoint disabled");
      void queryClient.invalidateQueries({ queryKey: ["webhooks"] });
    },
    onError: toast.error,
  });

  const remove = useMutation({
    mutationFn: async (id: number) => {
      const result = await api.DELETE("/webhooks/{id}", { params: { path: { id } } });
      if (!result.response.ok) unwrap(result);
    },
    onSuccess: () => {
      toast.ok("Endpoint removed");
      void queryClient.invalidateQueries({ queryKey: ["webhooks"] });
    },
    onError: toast.error,
  });

  const writable = can("webhooks:write");
  const items = hooks.data?.items ?? [];

  return (
    <>
      <PageHeader
        title="Webhooks"
        description="The panel POSTs signed events here. See docs/enforcement.md for how a receiver verifies them."
        actions={
          writable && (
            <Button variant="primary" onClick={() => setCreating(true)}>
              <Plus className="size-4" /> New endpoint
            </Button>
          )
        }
      />
      <Card>
        {hooks.isPending ? (
          <Spinner />
        ) : hooks.isError ? (
          <ErrorNote error={hooks.error} />
        ) : items.length === 0 ? (
          <Empty>No endpoints. Events are only queued for endpoints that exist when they happen.</Empty>
        ) : (
          <Table>
            <thead>
              <tr>
                <Th>URL</Th>
                <Th>Events</Th>
                <Th>Created</Th>
                <Th>State</Th>
                <Th />
              </tr>
            </thead>
            <tbody>
              {items.map((hook) => (
                <tr key={hook.id}>
                  <Td className="max-w-80 truncate font-medium" title={hook.url}>
                    {hook.url}
                  </Td>
                  <Td>
                    <div className="flex flex-wrap gap-1">
                      {hook.events.map((event) => (
                        <Badge key={event}>{event}</Badge>
                      ))}
                    </div>
                  </Td>
                  <Td className="text-muted">{formatDate(hook.created_at)}</Td>
                  <Td>{hook.enabled ? <Badge tone="ok">enabled</Badge> : <Badge>disabled</Badge>}</Td>
                  <Td className="text-right whitespace-nowrap">
                    {writable && (
                      <>
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => toggle.mutate({ id: hook.id, enabled: !hook.enabled })}
                        >
                          {hook.enabled ? "Disable" : "Enable"}
                        </Button>
                        <Button
                          size="sm"
                          variant="ghost"
                          aria-label="Remove"
                          onClick={() =>
                            window.confirm(`Remove ${hook.url}? Its undelivered events are dropped with it.`) &&
                            remove.mutate(hook.id)
                          }
                        >
                          <Trash2 className="size-4" />
                        </Button>
                      </>
                    )}
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>

      <CreateWebhookDialog
        open={creating}
        onOpenChange={setCreating}
        onCreated={(value) => {
          setCreating(false);
          setSecret(value);
        }}
      />

      <Dialog
        open={secret !== null}
        onOpenChange={(open) => !open && setSecret(null)}
        title="Signing secret"
        description="Give this to the receiver now. It is stored encrypted and cannot be shown again."
        footer={<Button onClick={() => setSecret(null)}>Done</Button>}
      >
        <div className="flex items-center gap-2">
          <Input readOnly value={secret ?? ""} className="font-mono text-xs" aria-label="Signing secret" />
          <Button size="sm" onClick={() => secret && void copy("secret", secret)}>
            {copied === "secret" ? <Check className="size-4" /> : <Copy className="size-4" />}
            {copied === "secret" ? "Copied" : "Copy"}
          </Button>
        </div>
      </Dialog>
    </>
  );
}

function CreateWebhookDialog({
  open,
  onOpenChange,
  onCreated,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onCreated: (secret: string) => void;
}) {
  const toast = useToast();
  const queryClient = useQueryClient();
  const [url, setUrl] = useState("");
  const [selected, setSelected] = useState<Set<WebhookEvent>>(new Set(["user.limited", "user.expired"]));

  const create = useMutation({
    mutationFn: async () => {
      if (selected.size === 0) throw new Error("Choose at least one event.");
      return unwrap(await api.POST("/webhooks", { body: { url: url.trim(), events: [...selected], enabled: true } }));
    },
    onSuccess: (hook) => {
      void queryClient.invalidateQueries({ queryKey: ["webhooks"] });
      setUrl("");
      if (hook.secret) onCreated(hook.secret);
      else toast.ok("Endpoint registered");
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
      title="New webhook endpoint"
      description="The panel generates the signing secret and shows it once."
      footer={
        <>
          <Button onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button variant="primary" type="submit" form="hook-form" loading={create.isPending}>
            Register
          </Button>
        </>
      }
    >
      <form id="hook-form" className="flex flex-col gap-4" onSubmit={submit}>
        <Field label="URL" htmlFor="w-url" hint="Redirects are not followed.">
          <Input
            id="w-url"
            type="url"
            placeholder="https://billing.example.com/hooks/panel"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            required
            autoFocus
          />
        </Field>
        <fieldset className="flex flex-col gap-1.5">
          <legend className="mb-1 text-sm font-medium">Events</legend>
          {events.map(({ event, hint }) => (
            <label key={event} className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={selected.has(event)}
                onChange={() =>
                  setSelected((current) => {
                    const next = new Set(current);
                    if (next.has(event)) next.delete(event);
                    else next.add(event);
                    return next;
                  })
                }
              />
              <code className="text-xs">{event}</code>
              <span className="text-muted">{hint}</span>
            </label>
          ))}
        </fieldset>
      </form>
    </Dialog>
  );
}
