import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Pencil, Plus, Trash2 } from "lucide-react";
import { useState, type FormEvent } from "react";

import { api, unwrap, type Schemas } from "@/api/client";
import { useAuth } from "@/auth";
import { PageHeader } from "@/components/layout";
import { useToast } from "@/components/toast";
import { Badge, Button, Card, Dialog, Empty, ErrorNote, Field, Input, Select, Spinner, Table, Td, Th } from "@/components/ui";

type HostWrite = Schemas["HostWrite"];
type Host = HostWrite & { id?: number };

const fingerprints: NonNullable<HostWrite["fingerprint"]>[] = [
  "chrome",
  "firefox",
  "safari",
  "ios",
  "android",
  "edge",
  "360",
  "qq",
  "random",
  "randomized",
];

/**
 * Hosts are what a subscription link points at. An inbound is where a node listens; a host is
 * what a client is told to dial — the node's own address, a CDN domain in front of it, a
 * different port. One inbound can have several, which becomes several links.
 */
export function HostsPage() {
  const { can } = useAuth();
  const toast = useToast();
  const queryClient = useQueryClient();
  const [editing, setEditing] = useState<Host | null>(null);

  const hosts = useQuery({ queryKey: ["hosts"], queryFn: async () => unwrap(await api.GET("/hosts")) as Host[] });
  const inbounds = useQuery({ queryKey: ["inbounds"], queryFn: async () => unwrap(await api.GET("/inbounds")) });

  const tagOf = new Map((inbounds.data ?? []).map((inbound) => [inbound.id, inbound.tag]));

  const remove = useMutation({
    mutationFn: async (id: number) => {
      const result = await api.DELETE("/hosts/{id}", { params: { path: { id } } });
      if (!result.response.ok) unwrap(result);
    },
    onSuccess: () => {
      toast.ok("Host deleted");
      void queryClient.invalidateQueries({ queryKey: ["hosts"] });
    },
    onError: toast.error,
  });

  const writable = can("inbounds:write");

  return (
    <>
      <PageHeader
        title="Hosts"
        description="What subscription links point at. Templates {USERNAME}, {NODE} and {COUNTRY} are filled in per user."
        actions={
          writable && (
            <Button variant="primary" onClick={() => setEditing({ enabled: true, sort_order: 0 })}>
              <Plus className="size-4" /> New host
            </Button>
          )
        }
      />
      <Card>
        {hosts.isPending ? (
          <Spinner />
        ) : hosts.isError ? (
          <ErrorNote error={hosts.error} />
        ) : hosts.data.length === 0 ? (
          <Empty>No hosts. Without one, an inbound is reachable only at the node's own address.</Empty>
        ) : (
          <Table>
            <thead>
              <tr>
                <Th>Remark</Th>
                <Th>Inbound</Th>
                <Th>Address</Th>
                <Th>SNI</Th>
                <Th>State</Th>
                <Th />
              </tr>
            </thead>
            <tbody>
              {hosts.data.map((host) => (
                <tr key={host.id}>
                  <Td className="font-medium">{host.remark}</Td>
                  <Td className="text-muted">{tagOf.get(host.inbound_id) ?? host.inbound_id}</Td>
                  <Td className="num">
                    {host.address}
                    {host.port ? `:${host.port}` : ""}
                  </Td>
                  <Td className="text-muted">{host.sni || "—"}</Td>
                  <Td>{host.enabled ? <Badge tone="ok">enabled</Badge> : <Badge>disabled</Badge>}</Td>
                  <Td className="text-right whitespace-nowrap">
                    {writable && host.id !== undefined && (
                      <>
                        <Button size="sm" variant="ghost" aria-label="Edit" onClick={() => setEditing(host)}>
                          <Pencil className="size-4" />
                        </Button>
                        <Button
                          size="sm"
                          variant="ghost"
                          aria-label="Delete"
                          onClick={() => window.confirm(`Delete host ${host.remark}?`) && remove.mutate(host.id!)}
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

      {editing && (
        <HostDialog
          key={editing.id ?? "new"}
          host={editing}
          inbounds={inbounds.data ?? []}
          onClose={() => setEditing(null)}
        />
      )}
    </>
  );
}

function HostDialog({ host, inbounds, onClose }: { host: Host; inbounds: Schemas["Inbound"][]; onClose: () => void }) {
  const toast = useToast();
  const queryClient = useQueryClient();
  const [form, setForm] = useState<Host>({ ...host });
  const set = <K extends keyof Host>(key: K, value: Host[K]) => setForm((current) => ({ ...current, [key]: value }));

  const save = useMutation({
    mutationFn: async () => {
      const body: HostWrite = {
        inbound_id: form.inbound_id,
        remark: form.remark?.trim(),
        address: form.address?.trim(),
        port: form.port ?? null,
        sni: form.sni?.trim() || undefined,
        host_header: form.host_header?.trim() || undefined,
        path: form.path?.trim() || undefined,
        fingerprint: form.fingerprint || undefined,
        alpn: form.alpn?.trim() || undefined,
        allow_insecure: form.allow_insecure ?? false,
        sort_order: form.sort_order ?? 0,
        enabled: form.enabled ?? true,
      };
      return host.id !== undefined
        ? unwrap(await api.PATCH("/hosts/{id}", { params: { path: { id: host.id } }, body }))
        : unwrap(await api.POST("/hosts", { body }));
    },
    onSuccess: () => {
      toast.ok(host.id !== undefined ? "Host saved" : "Host created");
      void queryClient.invalidateQueries({ queryKey: ["hosts"] });
      onClose();
    },
    onError: toast.error,
  });

  function submit(event: FormEvent) {
    event.preventDefault();
    save.mutate();
  }

  return (
    <Dialog
      open
      onOpenChange={(open) => !open && onClose()}
      wide
      title={host.id !== undefined ? "Edit host" : "New host"}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" type="submit" form="host-form" loading={save.isPending}>
            Save
          </Button>
        </>
      }
    >
      <form id="host-form" className="grid grid-cols-1 gap-4 sm:grid-cols-2" onSubmit={submit}>
        <Field label="Inbound" htmlFor="h-inbound">
          <Select
            id="h-inbound"
            value={form.inbound_id ?? ""}
            onChange={(e) => set("inbound_id", e.target.value ? Number(e.target.value) : undefined)}
            required
          >
            <option value="">Choose…</option>
            {inbounds.map((inbound) => (
              <option key={inbound.id} value={inbound.id}>
                {inbound.tag}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="Remark" htmlFor="h-remark" hint="The name a client shows, e.g. {COUNTRY} {NODE}.">
          <Input id="h-remark" value={form.remark ?? ""} onChange={(e) => set("remark", e.target.value)} required />
        </Field>
        <Field label="Address" htmlFor="h-address" hint="Domain or IP a client dials.">
          <Input id="h-address" value={form.address ?? ""} onChange={(e) => set("address", e.target.value)} required />
        </Field>
        <Field label="Port" htmlFor="h-port" hint="Empty uses the inbound's port.">
          <Input
            id="h-port"
            inputMode="numeric"
            value={form.port ?? ""}
            onChange={(e) => set("port", e.target.value ? Number(e.target.value) : null)}
          />
        </Field>
        <Field label="SNI" htmlFor="h-sni">
          <Input id="h-sni" value={form.sni ?? ""} onChange={(e) => set("sni", e.target.value)} />
        </Field>
        <Field label="Host header" htmlFor="h-hostheader">
          <Input id="h-hostheader" value={form.host_header ?? ""} onChange={(e) => set("host_header", e.target.value)} />
        </Field>
        <Field label="Path" htmlFor="h-path">
          <Input id="h-path" value={form.path ?? ""} onChange={(e) => set("path", e.target.value)} />
        </Field>
        <Field label="Fingerprint" htmlFor="h-fp">
          <Select
            id="h-fp"
            value={form.fingerprint ?? ""}
            onChange={(e) => set("fingerprint", (e.target.value || undefined) as HostWrite["fingerprint"])}
          >
            <option value="">Default</option>
            {fingerprints.map((fp) => (
              <option key={fp}>{fp}</option>
            ))}
          </Select>
        </Field>
        <Field label="ALPN" htmlFor="h-alpn" hint="Comma-separated, e.g. h2,http/1.1">
          <Input id="h-alpn" value={form.alpn ?? ""} onChange={(e) => set("alpn", e.target.value)} />
        </Field>
        <Field label="Order" htmlFor="h-order" hint="Lower comes first in the subscription.">
          <Input
            id="h-order"
            inputMode="numeric"
            value={form.sort_order ?? 0}
            onChange={(e) => set("sort_order", Number(e.target.value) || 0)}
          />
        </Field>
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={form.enabled ?? true} onChange={(e) => set("enabled", e.target.checked)} />
          Enabled
        </label>
        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={form.allow_insecure ?? false}
            onChange={(e) => set("allow_insecure", e.target.checked)}
          />
          Allow insecure (skips certificate checks on the client)
        </label>
      </form>
    </Dialog>
  );
}
