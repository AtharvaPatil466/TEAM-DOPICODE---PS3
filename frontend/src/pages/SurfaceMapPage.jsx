import { useEffect, useState } from "react";
import SurfaceGraph from "../components/graph/SurfaceGraph";
import { fetchSurfaceGraphData } from "../services/api";

function SurfaceMapPage() {
  const [data, setData] = useState(null);
  const [status, setStatus] = useState("Rendering map...");
  const [error, setError] = useState(null);

  useEffect(() => {
    let cancelled = false;

    async function loadGraph() {
      setStatus("Rendering map...");
      setError(null);

      try {
        const graphData = await fetchSurfaceGraphData();
        if (cancelled) {
          return;
        }
        setData(graphData);
        setStatus(null);
      } catch (loadError) {
        if (cancelled) {
          return;
        }
        setError(loadError);
        setStatus("Unable to render map.");
      }
    }

    loadGraph();

    return () => {
      cancelled = true;
    };
  }, []);

  if (status && !data) {
    return (
      <section className="page">
        <section className="panel">
          <h2>{status}</h2>
          {error ? <p>{error.message}</p> : null}
        </section>
      </section>
    );
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
      <SurfaceGraph
        graph={data?.graph}
        details={data?.nodeDetails || {}}
        assetsById={data?.assetsById || {}}
      />
    </section>
  );
}

export default SurfaceMapPage;
