import { Suspense } from "react";
import { PipelineTable } from "@/components/PipelineTable";
import { MetricsOverview } from "@/components/MetricsOverview";

export default function DashboardPage() {
  return (
    <main className="container mx-auto p-8">
      <h1 className="text-2xl font-bold mb-6">Data Platform Dashboard</h1>
      <p className="text-sm text-gray-500 mb-8">
        ⚠️ This dashboard is deprecated. Please use{" "}
        <a href="https://datacorp.grafana.net" className="text-blue-500 underline">
          Grafana
        </a>{" "}
        instead.
      </p>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
        <Suspense fallback={<div>Loading metrics...</div>}>
          <MetricsOverview />
        </Suspense>
      </div>

      <section>
        <h2 className="text-xl font-semibold mb-4">Pipeline Status</h2>
        <Suspense fallback={<div>Loading pipelines...</div>}>
          <PipelineTable />
        </Suspense>
      </section>
    </main>
  );
}
