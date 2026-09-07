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
      <p className="note">
        Open findings visible from each zone. A finding seen from several zones is counted once in
        each — these columns are not a total. This reflects which vantage points observed a
        finding, not whether it is reachable from the internet (not yet assessed).
      </p>
      {isLoading && <p>Loading…</p>}
      {error && <p className="error">Could not load exposure.</p>}
      {data && (
        <table>
          <thead>
            <tr>
              <th>Zone</th><th>Type</th>
              <th className="num">Critical</th><th className="num">High</th><th className="num">Medium</th>
              <th className="num">Low</th><th className="num">Info</th><th className="num">Findings</th>
            </tr>
          </thead>
          <tbody>
            {data.zones.map((z) => (
              <tr key={z.zone_id}>
                <td>{z.zone_name || z.zone_id}</td>
                <td className="muted">{z.zone_type}</td>
                <td className="num sev-critical">{z.critical || <span className="faint">0</span>}</td>
                <td className="num sev-high">{z.high || <span className="faint">0</span>}</td>
                <td className="num sev-medium">{z.medium || <span className="faint">0</span>}</td>
                <td className="num sev-low">{z.low || <span className="faint">0</span>}</td>
                <td className="num muted">{z.info || <span className="faint">0</span>}</td>
                <td className="num">{z.total}</td>
              </tr>
            ))}
            {data.zones.length === 0 && <tr className="empty"><td colSpan={8}>No exposed findings.</td></tr>}
          </tbody>
        </table>
      )}
    </section>
  );
}
