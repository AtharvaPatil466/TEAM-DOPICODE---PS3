function PriorityActionsCard({ actions }) {
  return (
    <section className="panel">
      <div className="panel-header">
        <div>
          <p className="eyebrow">This Week</p>
          <h2>Priority actions</h2>
        </div>
      </div>

      <div className="action-list">
        {actions.map((action) => (
          <article key={action.title} className="action-card">
            <h3>{action.title}</h3>
            <p>{action.detail}</p>
          </article>
        ))}
      </div>
    </section>
  );
}

export default PriorityActionsCard;
