export function StatTile({
  label,
  value,
  sub,
}: {
  label: string;
  value: string;
  sub?: string;
}) {
  return (
    <div className="card">
      <p className="stat-tile-label">{label}</p>
      <p className="stat-tile-value tabular">{value}</p>
      {sub ? <p className="stat-tile-sub">{sub}</p> : null}
    </div>
  );
}
