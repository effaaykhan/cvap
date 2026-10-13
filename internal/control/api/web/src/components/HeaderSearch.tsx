import { useEffect, useState, type FormEvent } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { CategoryIcon } from "./CategoryIcon";

// The console's search, in the top header so it is there on every page. It
// opens the dashboard search (/dashboard/search): assets matched by Core on a
// hostname or current address, findings and vulnerabilities by rule, CVE,
// category or asset. On the results page the box keeps the query it shows.
export const SEARCH_PATH = "/dashboard/search";

export function HeaderSearch() {
  const navigate = useNavigate();
  const { pathname, search } = useLocation();
  const shown = pathname === SEARCH_PATH ? new URLSearchParams(search).get("q") ?? "" : "";
  const [q, setQ] = useState(shown);
  useEffect(() => setQ(shown), [shown]);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    const v = q.trim();
    if (v) navigate(`${SEARCH_PATH}?${new URLSearchParams({ q: v })}`);
  };
  return (
    <form className="header-search" role="search" onSubmit={submit}>
      <CategoryIcon name="search" size={16} />
      <input type="search" value={q} onChange={(e) => setQ(e.target.value)}
             placeholder="Search assets, vulnerabilities, findings..." aria-label="Search assets, vulnerabilities, findings" />
    </form>
  );
}
