import { Navigate, Route, Routes } from "react-router-dom";
import AppLayout from "../components/layout/AppLayout";
import KillChainPage from "../pages/KillChainPage";
import OverviewPage from "../pages/OverviewPage";
import ReportPage from "../pages/ReportPage";
import ScanPage from "../pages/ScanPage";
import SurfaceMapPage from "../pages/SurfaceMapPage";
import ImpactPage from "../pages/ImpactPage";
import SimulatePage from "../pages/SimulatePage";
import DiffPage from "../pages/DiffPage";
import CtoPage from "../pages/CtoPage";

function App() {
  return (
    <Routes>
      <Route element={<AppLayout />}>
        <Route path="/" element={<ScanPage />} />
        <Route path="/cto" element={<CtoPage />} />
        <Route path="/overview" element={<OverviewPage />} />
        <Route path="/surface-map" element={<SurfaceMapPage />} />
        <Route path="/kill-chain" element={<KillChainPage />} />
        <Route path="/impact" element={<ImpactPage />} />
        <Route path="/simulate" element={<SimulatePage />} />
        <Route path="/diff" element={<DiffPage />} />
        <Route path="/report" element={<ReportPage />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

export default App;

