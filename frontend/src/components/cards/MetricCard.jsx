function MetricCard({ label, value, tone = "neutral" }) {
  return (
    <article className={`metric-card metric-${tone}`}>
      <p>{label}</p>
      <span className="metric-kicker">Live posture signal</span>
      <strong>{value}</strong>
    </article>
  );
}

export default MetricCard;
