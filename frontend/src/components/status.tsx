import { CircleCheck, CircleDashed, CircleOff, CircleX, Clock, Gauge } from "lucide-react";

import { Badge, type Tone } from "@/components/ui";

/**
 * Status badges. Each carries an icon and a word as well as a colour, because a status that is
 * only a colour is invisible to a colour-blind operator and to anybody reading a screenshot
 * in a ticket.
 */

const userStatuses: Record<string, { tone: Tone; label: string; icon: typeof CircleCheck }> = {
  active: { tone: "ok", label: "Active", icon: CircleCheck },
  limited: { tone: "warn", label: "Limited", icon: Gauge },
  expired: { tone: "bad", label: "Expired", icon: Clock },
  disabled: { tone: "idle", label: "Disabled", icon: CircleOff },
};

export function UserStatusBadge({ status }: { status: string | undefined }) {
  const meta = userStatuses[status ?? ""] ?? { tone: "idle" as Tone, label: status ?? "unknown", icon: CircleDashed };
  const Icon = meta.icon;
  return (
    <Badge tone={meta.tone}>
      <Icon className="size-3" aria-hidden />
      {meta.label}
    </Badge>
  );
}

const nodeStatuses: Record<string, { tone: Tone; label: string; icon: typeof CircleCheck }> = {
  connected: { tone: "ok", label: "Connected", icon: CircleCheck },
  disconnected: { tone: "idle", label: "Disconnected", icon: CircleDashed },
  error: { tone: "bad", label: "Error", icon: CircleX },
  disabled: { tone: "idle", label: "Disabled", icon: CircleOff },
};

export function NodeStatusBadge({ status, enabled }: { status: string | undefined; enabled?: boolean }) {
  const key = enabled === false ? "disabled" : (status ?? "");
  const meta = nodeStatuses[key] ?? { tone: "idle" as Tone, label: key || "unknown", icon: CircleDashed };
  const Icon = meta.icon;
  return (
    <Badge tone={meta.tone}>
      <Icon className="size-3" aria-hidden />
      {meta.label}
    </Badge>
  );
}
