import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";

// Exposure by zone: how many OPEN findings are visible from each zone, by
// severity. Presented as what the data IS — a zone-derived count — and NOT as a
// reachability judgement: internet_reachable is not written yet, so the UI shows
// no such verdict (constraint 3). Counts are per zone and are NOT summable: one
// finding seen from three zones counts once in each (ADR-010).
export function Exposure() {
  const { data, isLoading, error } = useQuery({
    queryKey: ["exposure"],
    queryFn: () => api.exposure(),
  });

  return (
    <section>
      <h1>Exposure by zone</h1>
      <p className="muted">
        Open findings visible from each zone. A finding seen from several zones is counted once in
        each — these columns are not a total. This reflects which vantage points observed a
        finding, not whether it is reachable from the internet (not yet assessed).
      </p>
      {isLoading && <p>Loading…</p>}
      {error && <p className="error">Could not load exposure.</p>}
      {data && (
        <table>
          <thead>
            <tr><th>Zone</th><th>Type</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Info</th><th>Findings</th></tr>
          </thead>
          <tbody>
            {data.zones.map((z) => (
              <tr key={z.zone_id}>
                <td>{z.zone_name || z.zone_id}</td>
                <td>{z.zone_type}</td>
                <td>{z.critical}</td><td>{z.high}</td><td>{z.medium}</td><td>{z.low}</td><td>{z.info}</td>
                <td>{z.total}</td>
              </tr>
            ))}
            {data.zones.length === 0 && <tr><td colSpan={8} className="muted">No exposed findings.</td></tr>}
          </tbody>
        </table>
      )}
    </section>
  );
}
