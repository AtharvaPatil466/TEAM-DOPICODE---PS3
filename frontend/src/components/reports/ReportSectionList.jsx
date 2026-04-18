function ReportSectionList({ sections }) {
  return (
    <section className="report-stack">
      {sections.map((section) => (
        <article key={section.heading} className="panel report-card">
          <p className="eyebrow">Report block</p>
          <h2>{section.heading}</h2>
          <p>{section.body}</p>
        </article>
      ))}
    </section>
  );
}

export default ReportSectionList;
