import { severityClass } from "../../utils/theme";

function SeverityBadge({ severity }) {
  return <span className={severityClass(severity)}>{severity}</span>;
}

export default SeverityBadge;
