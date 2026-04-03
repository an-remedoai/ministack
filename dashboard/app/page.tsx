import { fetchStateSummary } from "@/lib/ministack-client";
import { ServiceCard } from "@/components/service-card";
import { HealthStatus } from "@/components/health-status";

export default async function Overview() {
  let data;
  let connected = true;

  try {
    data = await fetchStateSummary();
  } catch {
    connected = false;
  }

  if (!connected || !data) {
    return (
      <div>
        <HealthStatus
          totalServices={0}
          totalResources={0}
          connected={false}
        />
        <div className="rounded-lg border border-[var(--red)]/30 bg-[var(--red)]/5 p-6 text-center">
          <p className="text-[var(--red)] font-semibold mb-2">
            Cannot connect to MiniStack
          </p>
          <p className="text-sm text-[var(--text-muted)]">
            Make sure MiniStack is running on{" "}
            {process.env.MINISTACK_URL || "http://localhost:4566"}
          </p>
        </div>
      </div>
    );
  }

  const sorted = Object.entries(data.services).sort(([a], [b]) =>
    a.localeCompare(b)
  );

  return (
    <div>
      <HealthStatus
        totalServices={data.totals.services}
        totalResources={data.totals.total_resources}
        connected={true}
      />
      <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 xl:grid-cols-6 gap-3">
        {sorted.map(([name, state]) => (
          <ServiceCard key={name} name={name} state={state} />
        ))}
      </div>
    </div>
  );
}
