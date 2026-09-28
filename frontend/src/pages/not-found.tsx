import { Link } from "react-router";

import { Card } from "@/components/ui";

export function NotFoundPage() {
  return (
    <Card className="mx-auto mt-10 max-w-md p-6 text-center">
      <h1 className="text-lg font-semibold">Nothing here</h1>
      <p className="mt-2 text-sm text-muted">This page does not exist, or it moved.</p>
      <Link to="/" className="mt-4 inline-block text-sm text-accent hover:underline">
        Back to the dashboard
      </Link>
    </Card>
  );
}
