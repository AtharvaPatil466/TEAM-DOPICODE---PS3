import { Component } from "react";

class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, info) {
    console.error("[ShadowTrace] ErrorBoundary caught:", error);
    console.error("[ShadowTrace] Component stack:", info?.componentStack);
  }

  handleRetry = () => {
    window.location.reload();
  };

  handleLoadDemo = () => {
    try {
      sessionStorage.setItem("shadowtrace_force_demo", "true");
    } catch { /* */ }
    window.location.href = "/app/scan";
  };

  render() {
    if (!this.state.hasError) {
      return this.props.children;
    }

    const msg = this.state.error?.message || "An unexpected error occurred.";

    return (
      <div
        style={{
          minHeight: "100vh",
          background: "#0D1B2A",
          color: "#F0F4F8",
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          padding: 32,
          fontFamily: "'Inter', 'DM Sans', system-ui, sans-serif",
        }}
      >
        {/* Icon */}
        <div
          style={{
            width: 48,
            height: 48,
            border: "2px solid #E63946",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            marginBottom: 24,
            fontSize: 24,
            color: "#E63946",
            fontWeight: 700,
          }}
        >
          !
        </div>

        {/* Heading */}
        <h1
          style={{
            fontSize: "2rem",
            fontWeight: 800,
            letterSpacing: "0.12em",
            textTransform: "uppercase",
            margin: "0 0 16px 0",
          }}
        >
          SIGNAL LOST
        </h1>

        {/* Error message */}
        <pre
          style={{
            fontFamily: "'JetBrains Mono', 'Fira Code', 'Courier New', monospace",
            fontSize: "0.8rem",
            color: "#8BA4BE",
            background: "#111F30",
            border: "1px solid #1E3048",
            borderRadius: 0,
            padding: "16px 24px",
            maxWidth: 520,
            width: "100%",
            whiteSpace: "pre-wrap",
            wordBreak: "break-word",
            margin: "0 0 32px 0",
            lineHeight: 1.6,
          }}
        >
          {msg}
        </pre>

        {/* Buttons */}
        <div style={{ display: "flex", gap: 12 }}>
          <button
            type="button"
            onClick={this.handleRetry}
            style={{
              padding: "12px 24px",
              background: "#E63946",
              color: "#fff",
              fontSize: "0.875rem",
              fontWeight: 700,
              textTransform: "uppercase",
              letterSpacing: "0.06em",
              border: "1px solid #E63946",
              borderRadius: 0,
              cursor: "pointer",
              fontFamily: "inherit",
            }}
          >
            Retry
          </button>
          <button
            type="button"
            onClick={this.handleLoadDemo}
            style={{
              padding: "12px 24px",
              background: "transparent",
              color: "#A8BCCF",
              fontSize: "0.875rem",
              fontWeight: 700,
              textTransform: "uppercase",
              letterSpacing: "0.06em",
              border: "1px solid #2B4A6F",
              borderRadius: 0,
              cursor: "pointer",
              fontFamily: "inherit",
            }}
          >
            Load Demo
          </button>
        </div>
      </div>
    );
  }
}

export default ErrorBoundary;
