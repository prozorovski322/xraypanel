import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Pencil, Plus, Trash2 } from "lucide-react";
import { useState, type FormEvent } from "react";

import { api, unwrap, type Schemas } from "@/api/client";
import { useAuth } from "@/auth";
import { PageHeader } from "@/components/layout";
import { useToast } from "@/components/toast";
import { Badge, Button, Card, Dialog, Empty, ErrorNote, Field, Input, Spinner, Table, Td, Th } from "@/components/ui";

type Group = Schemas["Group"];

/**
 * Groups are the only way a user gets access to an inbound. No per-user exceptions: the rule
 * for who can use what stays one join, which is what keeps it testable.
 */
export function GroupsPage() {
  const { can } = useAuth();
  const toast = useToast();
  const queryClient = useQueryClient();
  const [editing, setEditing] = useState<Group | null>(null);

  const groups = useQuery({ queryKey: ["groups"], queryFn: async () => unwrap(await api.GET("/groups")) });

  const remove = useMutation({
    mutationFn: async (id: number) => {
      const result = await api.DELETE("/groups/{id}", { params: { path: { id } } });
      if (!result.response.ok) unwrap(result);
    },
    onSuccess: () => {
      toast.ok("Group deleted");
      void queryClient.invalidateQueries({ queryKey: ["groups"] });
    },
    onError: toast.error,
  });

  const writable = can("inbounds:write");

  return (
    <>
      <PageHeader
        title="Groups"
        description="Bundles of inbounds. A user can use exactly the inbounds of the groups they are in."
        actions={
          writable && (
            <Button variant="primary" onClick={() => setEditing({ is_default: false, inbound_ids: [] })}>
              <Plus className="size-4" /> New group
            </Button>
          )
        }
      />
      <Card>
        {groups.isPending ? (
          <Spinner />
        ) : groups.isError ? (
          <ErrorNote error={groups.error} />
        ) : groups.data.length === 0 ? (
          <Empty>No groups. New users get the default groups, so create at least one and mark it default.</Empty>
        ) : (
          <Table>
            <thead>
              <tr>
                <Th>Name</Th>
                <Th>Inbounds</Th>
                <Th>Default</Th>
                <Th />
              </tr>
            </thead>
            <tbody>
              {groups.data.map((group) => (
                <tr key={group.id}>
                  <Td>
                    <div className="font-medium">{group.name}</div>
                    {group.description && <div className="text-xs text-muted">{group.description}</div>}
                  </Td>
                  <Td>
                    <div className="flex flex-wrap gap-1">
                      {(group.inbound_tags ?? []).length === 0 ? (
                        <span className="text-muted">none</span>
                      ) : (
                        (group.inbound_tags ?? []).map((tag) => <Badge key={tag}>{tag}</Badge>)
                      )}
                    </div>
                  </Td>
                  <Td>{group.is_default ? <Badge tone="accent">default</Badge> : <span className="text-muted">—</span>}</Td>
                  <Td className="text-right whitespace-nowrap">
                    {writable && group.id !== undefined && (
                      <>
                        <Button size="sm" variant="ghost" aria-label="Edit" onClick={() => setEditing(group)}>
                          <Pencil className="size-4" />
                        </Button>
                        <Button
                          size="sm"
                          variant="ghost"
                          aria-label="Delete"
                          onClick={() =>
                            window.confirm(`Delete ${group.name}? Its members lose the inbounds it granted.`) &&
                            remove.mutate(group.id!)
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

      {editing && <GroupDialog key={editing.id ?? "new"} group={editing} onClose={() => setEditing(null)} />}
    </>
  );
}

function GroupDialog({ group, onClose }: { group: Group; onClose: () => void }) {
  const toast = useToast();
  const queryClient = useQueryClient();
  const [name, setName] = useState(group.name ?? "");
  const [description, setDescription] = useState(group.description ?? "");
  const [isDefault, setIsDefault] = useState(group.is_default ?? false);
  const [inboundIds, setInboundIds] = useState<Set<number>>(new Set(group.inbound_ids ?? []));

  const inbounds = useQuery({ queryKey: ["inbounds"], queryFn: async () => unwrap(await api.GET("/inbounds")) });

  const save = useMutation({
    mutationFn: async () => {
      const body = {
        name: name.trim(),
        description: description.trim(),
        is_default: isDefault,
        inbound_ids: [...inboundIds],
      };
      return group.id !== undefined
        ? unwrap(await api.PATCH("/groups/{id}", { params: { path: { id: group.id } }, body }))
        : unwrap(await api.POST("/groups", { body }));
    },
    onSuccess: () => {
      toast.ok(group.id !== undefined ? "Group saved" : "Group created");
      void queryClient.invalidateQueries({ queryKey: ["groups"] });
      onClose();
    },
    onError: toast.error,
  });

  function toggle(id: number) {
    setInboundIds((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function submit(event: FormEvent) {
    event.preventDefault();
    save.mutate();
  }

  return (
    <Dialog
      open
      onOpenChange={(open) => !open && onClose()}
      title={group.id !== undefined ? `Edit ${group.name}` : "New group"}
      description="Changing a group's inbounds changes what every member can use, on every node, at once."
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" type="submit" form="group-form" loading={save.isPending}>
            Save
          </Button>
        </>
      }
    >
      <form id="group-form" className="flex flex-col gap-4" onSubmit={submit}>
        <Field label="Name" htmlFor="g-name">
          <Input id="g-name" value={name} onChange={(e) => setName(e.target.value)} required autoFocus />
        </Field>
        <Field label="Description" htmlFor="g-desc">
          <Input id="g-desc" value={description} onChange={(e) => setDescription(e.target.value)} />
        </Field>
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={isDefault} onChange={(e) => setIsDefault(e.target.checked)} />
          Default — granted to every new user
        </label>
        <fieldset className="flex flex-col gap-1.5">
          <legend className="mb-1 text-sm font-medium">Inbounds</legend>
          {inbounds.isPending ? (
            <Spinner />
          ) : (inbounds.data ?? []).length === 0 ? (
            <p className="text-sm text-muted">No inbounds exist yet.</p>
          ) : (
            (inbounds.data ?? []).map((inbound) =>
              inbound.id === undefined ? null : (
                <label key={inbound.id} className="flex items-center gap-2 text-sm">
                  <input type="checkbox" checked={inboundIds.has(inbound.id)} onChange={() => toggle(inbound.id!)} />
                  <span className="font-medium">{inbound.tag}</span>
                  <span className="text-muted">
                    {inbound.protocol} · {inbound.transport} · {inbound.security} · :{inbound.listen_port}
                  </span>
                </label>
              ),
            )
          )}
        </fieldset>
      </form>
    </Dialog>
  );
}
