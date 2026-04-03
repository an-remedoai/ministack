import { fetchServiceDetail } from "@/lib/ministack-client";
import { ResourceTable } from "@/components/resource-table";

export default async function ServiceDetailPage({
  params,
}: {
  params: Promise<{ service: string }>;
}) {
  const { service } = await params;

  let detail;
  let error: string | null = null;

  try {
    detail = await fetchServiceDetail(service);
  } catch (e) {
    error = e instanceof Error ? e.message : "Failed to fetch service detail";
  }

  return (
    <div>
      <div className="mb-6">
        <a
          href="/"
          className="text-sm text-[var(--text-muted)] hover:text-white transition-colors"
        >
          &larr; Back to Overview
        </a>
      </div>

      <h1 className="text-xl font-bold mb-4">{service}</h1>

      {error && (
        <div className="rounded-lg border border-[var(--red)]/30 bg-[var(--red)]/5 p-4">
          <p className="text-[var(--red)] text-sm">{error}</p>
        </div>
      )}

      {detail && (
        <div className="space-y-6">
          {Object.entries(detail.resources).map(([resourceType, items]) => (
            <div key={resourceType}>
              <h2 className="text-sm font-semibold text-[var(--text-muted)] uppercase tracking-wide mb-2">
                {resourceType}{" "}
                <span className="text-[var(--text-muted)]/60">
                  ({Array.isArray(items) ? items.length : 0})
                </span>
              </h2>
              {Array.isArray(items) ? (
                <ResourceTable
                  items={items as Record<string, unknown>[]}
                />
              ) : (
                <pre className="text-xs bg-[var(--card)] rounded p-3 overflow-x-auto">
                  {JSON.stringify(items, null, 2)}
                </pre>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
