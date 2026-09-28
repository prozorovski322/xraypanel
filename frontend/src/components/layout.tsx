import {
  Activity,
  FileClock,
  Gauge,
  KeyRound,
  Layers,
  LogOut,
  Network,
  Server,
  Settings,
  Share2,
  Users,
  Webhook,
} from "lucide-react";
import type { ReactNode } from "react";
import { Navigate, NavLink, Outlet, useLocation } from "react-router";

import { useAuth } from "@/auth";
import { Button, Spinner } from "@/components/ui";
import { cn } from "@/lib/utils";

interface NavItem {
  to: string;
  label: string;
  icon: ReactNode;
  scope: string;
}

const nav: NavItem[] = [
  { to: "/", label: "Dashboard", icon: <Gauge className="size-4" />, scope: "stats:read" },
  { to: "/users", label: "Users", icon: <Users className="size-4" />, scope: "users:read" },
  { to: "/nodes", label: "Nodes", icon: <Server className="size-4" />, scope: "nodes:read" },
  { to: "/inbounds", label: "Inbounds", icon: <Network className="size-4" />, scope: "inbounds:read" },
  { to: "/hosts", label: "Hosts", icon: <Share2 className="size-4" />, scope: "inbounds:read" },
  { to: "/groups", label: "Groups", icon: <Layers className="size-4" />, scope: "inbounds:read" },
  { to: "/api-keys", label: "API keys", icon: <KeyRound className="size-4" />, scope: "admins:read" },
  { to: "/webhooks", label: "Webhooks", icon: <Webhook className="size-4" />, scope: "webhooks:read" },
  { to: "/audit", label: "Audit log", icon: <FileClock className="size-4" />, scope: "audit:read" },
];

/** RequireAuth holds a route until the session is restored, and sends a visitor to login. */
export function RequireAuth({ children }: { children: ReactNode }) {
  const { status } = useAuth();
  const location = useLocation();

  if (status === "restoring") return <Spinner label="Restoring the session" />;
  if (status === "anonymous") return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  return <>{children}</>;
}

export function Layout() {
  const { me, logout, can } = useAuth();

  return (
    <div className="flex min-h-full">
      <aside className="sticky top-0 hidden h-screen w-56 shrink-0 flex-col border-r border-border bg-surface md:flex">
        <div className="flex items-center gap-2 px-4 py-4">
          <Activity className="size-5 text-accent" aria-hidden />
          <span className="font-semibold">xraypanel</span>
        </div>
        <nav className="flex flex-1 flex-col gap-0.5 px-2" aria-label="Main">
          {nav
            .filter((item) => can(item.scope))
            .map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.to === "/"}
                className={({ isActive }) =>
                  cn(
                    "flex items-center gap-2.5 rounded-md px-3 py-2 text-sm",
                    isActive ? "bg-surface-2 font-medium text-text" : "text-muted hover:bg-surface-2 hover:text-text",
                  )
                }
              >
                {item.icon}
                {item.label}
              </NavLink>
            ))}
        </nav>
        <div className="border-t border-border p-3">
          <NavLink
            to="/settings"
            className="flex items-center gap-2 rounded-md px-2 py-1.5 text-sm text-muted hover:bg-surface-2 hover:text-text"
          >
            <Settings className="size-4" />
            <span className="truncate">{me?.username ?? "Account"}</span>
            <span className="ml-auto text-xs">{me?.role}</span>
          </NavLink>
          <Button variant="ghost" size="sm" className="mt-1 w-full justify-start" onClick={() => void logout()}>
            <LogOut className="size-4" />
            Sign out
          </Button>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        {/* A narrow screen gets the same destinations as a horizontal strip. */}
        <nav className="flex gap-1 overflow-x-auto border-b border-border bg-surface px-2 py-2 md:hidden" aria-label="Main">
          {nav
            .filter((item) => can(item.scope))
            .map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.to === "/"}
                className={({ isActive }) =>
                  cn("rounded-md px-3 py-1.5 text-sm whitespace-nowrap", isActive ? "bg-surface-2 font-medium" : "text-muted")
                }
              >
                {item.label}
              </NavLink>
            ))}
          <NavLink to="/settings" className="rounded-md px-3 py-1.5 text-sm whitespace-nowrap text-muted">
            Account
          </NavLink>
        </nav>
        <main className="mx-auto w-full max-w-7xl flex-1 p-4 md:p-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
}

/** PageHeader is a screen's title and its main actions. */
export function PageHeader({ title, description, actions }: { title: string; description?: string; actions?: ReactNode }) {
  return (
    <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
      <div>
        <h1 className="text-xl font-semibold">{title}</h1>
        {description && <p className="mt-1 text-sm text-muted">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}
