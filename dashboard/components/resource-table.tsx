export function ResourceTable({
  items,
}: {
  items: Record<string, unknown>[];
}) {
  if (!items || items.length === 0) {
    return (
      <p className="text-sm text-[var(--text-muted)]">No resources found.</p>
    );
  }

  const columns = Object.keys(items[0]);

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm border-collapse">
        <thead>
          <tr className="border-b border-[var(--border)]">
            {columns.map((col) => (
              <th
                key={col}
                className="text-left py-2 px-3 text-[var(--text-muted)] font-medium"
              >
                {col}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {items.map((item, i) => (
            <tr
              key={i}
              className="border-b border-[var(--border)]/50 hover:bg-white/5"
            >
              {columns.map((col) => (
                <td key={col} className="py-2 px-3 font-mono text-xs">
                  {typeof item[col] === "object"
                    ? JSON.stringify(item[col])
                    : String(item[col] ?? "")}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
