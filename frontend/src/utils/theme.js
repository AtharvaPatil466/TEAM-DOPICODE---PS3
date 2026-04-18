export const severityColors = {
  Critical: "#ff5d5d",
  High: "#ff8c42",
  Medium: "#ffd166",
  Neutral: "#78c4d4"
};

export function severityClass(severity) {
  switch (severity) {
    case "Critical":
      return "severity severity-critical";
    case "High":
      return "severity severity-high";
    case "Medium":
      return "severity severity-medium";
    default:
      return "severity severity-neutral";
  }
}
