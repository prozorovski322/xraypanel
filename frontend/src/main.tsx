import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { createBrowserRouter, RouterProvider } from "react-router";

import { ApiError } from "@/api/client";
import { AuthProvider } from "@/auth";
import { Layout, RequireAuth } from "@/components/layout";
import { ToastProvider } from "@/components/toast";
import { ApiKeysPage } from "@/pages/api-keys";
import { AuditPage } from "@/pages/audit";
import { DashboardPage } from "@/pages/dashboard";
import { GroupsPage } from "@/pages/groups";
import { HostsPage } from "@/pages/hosts";
import { InboundsPage } from "@/pages/inbounds";
import { LoginPage } from "@/pages/login";
import { NodeDetailPage } from "@/pages/node-detail";
import { NodesPage } from "@/pages/nodes";
import { NotFoundPage } from "@/pages/not-found";
import { SettingsPage } from "@/pages/settings";
import { UserDetailPage } from "@/pages/user-detail";
import { UsersPage } from "@/pages/users";
import { WebhooksPage } from "@/pages/webhooks";

import "./index.css";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // A 4xx is an answer, not a flake: retrying a 403 or a 404 three times only delays the
      // message the operator needs to see.
      retry: (failures, error) => !(error instanceof ApiError && error.status < 500) && failures < 2,
      staleTime: 5_000,
      refetchOnWindowFocus: true,
    },
  },
});

const router = createBrowserRouter([
  { path: "/login", element: <LoginPage /> },
  {
    path: "/",
    element: (
      <RequireAuth>
        <Layout />
      </RequireAuth>
    ),
    children: [
      { index: true, element: <DashboardPage /> },
      { path: "users", element: <UsersPage /> },
      { path: "users/:id", element: <UserDetailPage /> },
      { path: "nodes", element: <NodesPage /> },
      { path: "nodes/:id", element: <NodeDetailPage /> },
      { path: "inbounds", element: <InboundsPage /> },
      { path: "hosts", element: <HostsPage /> },
      { path: "groups", element: <GroupsPage /> },
      { path: "api-keys", element: <ApiKeysPage /> },
      { path: "webhooks", element: <WebhooksPage /> },
      { path: "audit", element: <AuditPage /> },
      { path: "settings", element: <SettingsPage /> },
      { path: "*", element: <NotFoundPage /> },
    ],
  },
]);

const root = document.getElementById("root");
if (!root) throw new Error("index.html has no #root element");

createRoot(root).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <ToastProvider>
        <AuthProvider>
          <RouterProvider router={router} />
        </AuthProvider>
      </ToastProvider>
    </QueryClientProvider>
  </StrictMode>,
);
