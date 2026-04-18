function MetricCard({ label, value, tone = "neutral" }) {
  return (
    <article className={`metric-card metric-${tone}`}>
      <p>{label}</p>
      <strong>{value}</strong>
    </article>
  );
}

export default MetricCard;
