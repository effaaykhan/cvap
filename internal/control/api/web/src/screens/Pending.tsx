import { PageHead } from "../components/PageHead";

// A navigation destination whose screen is not built yet. It says so and
// nothing more: no placeholder figures, because a number the scanner did not
// establish reads exactly like one it did.
//
// `data` separates the two honest states. "none" — nothing in Core collects
// this today. "partial" — Core holds related data, but no view of it is built
// here yet, so claiming "no data" would be as wrong as inventing some.
export function Pending({ title, data }: { title: string; data: "none" | "partial" }) {
  return (
    <>
      <PageHead title={title} sub="This view is awaiting backend and data implementation." />
      <div className="card">
        <p className="empty">
          {data === "none"
            ? "No current backend data available."
            : "Not built yet. Related data exists in Core, but this view does not present it."}
        </p>
      </div>
    </>
  );
}
