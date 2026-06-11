const stats = [
  { value: "60+", label: "Commands", sub: "CLI & MCP" },
  { value: "32", label: "CVEs tracked", sub: "Critical → Low" },
  { value: "7", label: "Scanners", sub: "Specialised" },
  { value: "100%", label: "Local", sub: "No telemetry" },
];

const StatsSection = () => {
  return (
    <section aria-label="Key metrics" className="relative py-16 overflow-hidden">
      <div className="absolute inset-0 bg-navy" aria-hidden="true" />
      <div
        className="absolute inset-0"
        aria-hidden="true"
        style={{
          backgroundImage: `radial-gradient(ellipse 100% 100% at 50% 0%, hsl(var(--ultramarine) / 0.1), transparent 50%)`,
        }}
      />

      <div className="relative z-10 container mx-auto px-4 sm:px-6">
        <dl className="grid grid-cols-2 md:grid-cols-4 gap-8 md:gap-12">
          {stats.map((stat, index) => (
            <div
              key={stat.label}
              className="text-center group"
              style={{ animationDelay: `${index * 0.15}s` }}
            >
              <dt className="sr-only">{stat.label}</dt>
              <dd>
                <span
                  className="stat-number text-gradient-ultramarine mb-1 block group-hover:glow-text transition-all"
                  aria-hidden="true"
                >
                  {stat.value}
                </span>
                <span className="text-foreground font-semibold text-sm sm:text-base block">
                  {stat.label}
                </span>
                <span className="text-muted-foreground/70 text-xs mt-0.5 block font-mono">
                  {stat.sub}
                </span>
              </dd>
            </div>
          ))}
        </dl>
      </div>
    </section>
  );
};

export default StatsSection;
