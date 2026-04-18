import { useEffect, useState } from "react";
import SurfaceGraph from "../components/graph/SurfaceGraph";
import { fetchDashboardData } from "../services/api";

function SurfaceMapPage() {
  const [data, setData] = useState(null);

  useEffect(() => {
    fetchDashboardData().then(setData);
  }, []);

  if (!data) {
    return <section className="page">Rendering map...</section>;
  }

  return (
    <section className="page">
      <SurfaceGraph graph={data.graph} details={data.nodeDetails} />
    </section>
  );
}

export default SurfaceMapPage;
