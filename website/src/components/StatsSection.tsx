const stats = [
  { value: "60+", label: "Commands" },
  { value: "32", label: "CVEs" },
  { value: "7", label: "Scanners" },
  { value: "100%", label: "Local" },
];

const StatsSection = () => {
  return (
    <section className="relative py-16 overflow-hidden">
      <div className="absolute inset-0 bg-navy" />
      <div 
        className="absolute inset-0"
        style={{
          backgroundImage: `radial-gradient(ellipse 100% 100% at 50% 0%, hsl(var(--ultramarine) / 0.1), transparent 50%)`,
        }}
      />

      <div className="relative z-10 container mx-auto px-6">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-8 md:gap-12">
          {stats.map((stat, index) => (
            <div 
              key={stat.label}
              className="text-center group"
              style={{ animationDelay: `${index * 0.15}s` }}
            >
              <div className="stat-number text-gradient-ultramarine mb-2 group-hover:glow-text transition-all">
                {stat.value}
              </div>
              <div className="text-foreground font-medium">{stat.label}</div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
};

export default StatsSection;
