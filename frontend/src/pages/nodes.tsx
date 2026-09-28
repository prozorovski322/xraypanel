import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router";

import { api, unwrap } from "@/api/client";
import { useAuth } from "@/auth";
import { PageHeader } from "@/components/layout";
import { NodeStatusBadge } from "@/components/status";
import { useToast } from "@/components/toast";
import { Button, Card, Dialog, Empty, ErrorNote, Field, Input, Spinner, Table, Td, Th } from "@/components/ui";
import { formatBytes, formatRelative } from "@/lib/utils";

export function NodesPage() {
  const { can } = useAuth();
  const [creating, setCreating] = useState(false);

  // Polled: whether a node is up is the thing on this page most likely to change while it is
  // open, and the list is one small query.
  const nodes = useQuery({
    queryKey: ["nodes"],
    queryFn: async () => unwrap(await api.GET("/nodes")),
    refetchInterval: 5_000,
  });

  return (
    <>
      <PageHeader
        title="Nodes"
        description="Exit servers. Each runs the agent, which dials the panel; nodes need no inbound management port."
        actions={
          can("nodes:write") && (
            <Button variant="primary" onClick={() => setCreating(true)}>
              <Plus className="size-4" /> New node
            </Button>
          )
        }
      />
      <Card>
        {nodes.isPending ? (
          <Spinner />
        ) : nodes.isError ? (
          <ErrorNote error={nodes.error} />
        ) : nodes.data.length === 0 ? (
          <Empty>No nodes yet. Create one, then enrol its agent with a token from the node's page.</Empty>
        ) : (
          <Table>
            <thead>
              <tr>
                <Th>Node</Th>
                <Th>Status</Th>
                <Th>Last seen</Th>
                <Th>Xray</Th>
                <Th className="text-right">Config applied</Th>
                <Th className="text-right">Traffic</Th>
              </tr>
            </thead>
            <tbody>
              {nodes.data.map((node) => {
                const behind = (node.applied_version ?? 0) < (node.config_version ?? 0);
                return (
                  <tr key={node.id} className="hover:bg-surface-2">
                    <Td>
                      <Link to={`/nodes/${node.id}`} className="font-medium hover:underline">
                        {node.name}
                      </Link>
                      <div className="text-xs text-muted">
                        {node.address}
                        {node.country_code ? ` · ${node.country_code}` : ""}
                      </div>
                    </Td>
                    <Td>
                      <NodeStatusBadge status={node.status} enabled={node.enabled} />
                      {node.last_error && (
                        <div className="mt-1 max-w-64 truncate text-xs text-bad" title={node.last_error}>
                          {node.last_error}
                        </div>
                      )}
                    </Td>
                    <Td className="text-muted">{formatRelative(node.last_seen_at)}</Td>
                    <Td className="num text-muted">{node.xray_version || "—"}</Td>
                    <Td className={behind ? "num text-right text-warn" : "num text-right text-muted"}>
                      {node.applied_version ?? 0} / {node.config_version ?? 0}
                    </Td>
                    <Td className="num text-right">{formatBytes(node.traffic_used)}</Td>
                  </tr>
                );
              })}
            </tbody>
          </Table>
        )}
      </Card>
      <CreateNodeDialog open={creating} onOpenChange={setCreating} />
    </>
  );
}

function CreateNodeDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const toast = useToast();
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const [name, setName] = useState("");
  const [address, setAddress] = useState("");
  const [country, setCountry] = useState("");

  const create = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.POST("/nodes", {
          body: {
            name: name.trim(),
            address: address.trim(),
            country_code: country.trim().toUpperCase() || undefined,
            enabled: true,
          },
        }),
      ),
    onSuccess: (node) => {
      toast.ok(`Created ${node.name}`);
      onOpenChange(false);
      setName("");
      setAddress("");
      setCountry("");
      void queryClient.invalidateQueries({ queryKey: ["nodes"] });
      if (node.id) navigate(`/nodes/${node.id}`);
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
      title="New node"
      description="Registers the node. It starts serving once its agent enrols and inbounds are attached."
      footer={
        <>
          <Button onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button variant="primary" type="submit" form="create-node" loading={create.isPending}>
            Create
          </Button>
        </>
      }
    >
      <form id="create-node" className="flex flex-col gap-4" onSubmit={submit}>
        <Field label="Name" htmlFor="node-name">
          <Input id="node-name" value={name} onChange={(e) => setName(e.target.value)} required autoFocus />
        </Field>
        <Field label="Address" htmlFor="node-address" hint="What clients connect to: a hostname or an IP address.">
          <Input id="node-address" value={address} onChange={(e) => setAddress(e.target.value)} required />
        </Field>
        <Field label="Country code" htmlFor="node-country" hint="Two letters, used in link names. Optional.">
          <Input id="node-country" maxLength={2} value={country} onChange={(e) => setCountry(e.target.value)} />
        </Field>
      </form>
    </Dialog>
  );
}
