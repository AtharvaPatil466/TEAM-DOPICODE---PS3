function NarrativeCard({ narrative }) {
  return (
    <section className="panel narrative-card">
      <p className="eyebrow">Executive framing</p>
      <h2>The story judges should understand in 10 seconds</h2>
      <p>{narrative}</p>
      <div className="narrative-points">
        <span>Exposure</span>
        <span>Evidence</span>
        <span>Recommended move</span>
      </div>
    </section>
  );
}

export default NarrativeCard;
