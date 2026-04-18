import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import App from "./app/App";
import "./styles/global.css";
import "./styles/brand.css";
import "./styles/interactions.css";
import ErrorBoundary from "./components/ErrorBoundary";
import { ToastProvider } from "./hooks/useToast.jsx";
import ToastManager from "./components/ToastManager";

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <ErrorBoundary>
      <ToastProvider>
        <BrowserRouter>
          <App />
          <ToastManager />
        </BrowserRouter>
      </ToastProvider>
    </ErrorBoundary>
  </React.StrictMode>
);
