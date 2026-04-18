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
      <section className="hero-card page-intro">
        <div>
          <p className="eyebrow">Graph intelligence</p>
          <h2>Inspect how internet exposure fans out across the environment.</h2>
          <p>
            This view helps non-technical stakeholders understand why one exposed admin panel or
            storage bucket matters beyond the single asset itself.
          </p>
        </div>
      </section>
      <SurfaceGraph graph={data.graph} details={data.nodeDetails} assetsById={data.assetsById || {}} />
    </section>
  );
}

export default SurfaceMapPage;
