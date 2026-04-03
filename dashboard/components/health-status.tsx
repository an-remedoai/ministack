export function HealthStatus({
  totalServices,
  totalResources,
  connected,
}: {
  totalServices: number;
  totalResources: number;
  connected: boolean;
}) {
  return (
    <div className="flex items-center gap-6 mb-6">
      <div className="flex items-center gap-2">
        <span
          className={`w-3 h-3 rounded-full ${
            connected ? "bg-[var(--green)]" : "bg-[var(--red)]"
          }`}
        />
        <span className="text-sm">
          {connected ? "Connected" : "Disconnected"}
        </span>
      </div>
      <div className="text-sm text-[var(--text-muted)]">
        {totalServices} services
      </div>
      <div className="text-sm text-[var(--text-muted)]">
        {totalResources} resources
      </div>
    </div>
  );
}
