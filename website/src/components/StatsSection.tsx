import { useEffect, useRef, useState } from "react";

const stats = [
  { value: 60, suffix: "+", label: "Commands", sub: "CLI & MCP" },
  { value: 32, suffix: "", label: "CVEs tracked", sub: "Critical → Low" },
  { value: 7, suffix: "", label: "Scanners", sub: "Specialised" },
  { value: 100, suffix: "%", label: "Local", sub: "No telemetry" },
];

function useCountUp(target: number, active: boolean, duration = 1200) {
  const [count, setCount] = useState(0);
  const rafRef = useRef<number | null>(null);

  useEffect(() => {
    // Respect prefers-reduced-motion
    if (typeof window !== "undefined" && window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      setCount(target);
      return;
    }
    if (!active) return;

    const start = performance.now();
    const step = (now: number) => {
      const elapsed = now - start;
      const progress = Math.min(elapsed / duration, 1);
      // Ease-out cubic
      const eased = 1 - Math.pow(1 - progress, 3);
      setCount(Math.round(eased * target));
      if (progress < 1) {
        rafRef.current = requestAnimationFrame(step);
      }
    };
    rafRef.current = requestAnimationFrame(step);
    return () => {
      if (rafRef.current != null) cancelAnimationFrame(rafRef.current);
    };
  }, [active, target, duration]);

  return count;
}

function StatItem({
  stat,
  index,
  active,
}: {
  stat: (typeof stats)[0];
  index: number;
  active: boolean;
}) {
  const count = useCountUp(stat.value, active, 1000 + index * 150);

  return (
    <div
      className={`text-center group transition-all duration-700 ${
        active ? "opacity-100 translate-y-0" : "opacity-0 translate-y-4"
      }`}
      style={{
        transitionDelay: `${index * 120}ms`,
      }}
    >
      <dt className="sr-only">{stat.label}</dt>
      <dd>
        <span
          className="stat-number text-gradient-ultramarine mb-1 block group-hover:glow-text transition-all tabular-nums"
          aria-hidden="true"
        >
          {count}{stat.suffix}
        </span>
        <span className="text-foreground font-semibold text-sm sm:text-base block">
          {stat.label}
        </span>
        <span className="text-muted-foreground/70 text-xs mt-0.5 block font-mono">
          {stat.sub}
        </span>
      </dd>
      {/* Accessible static value for screen readers */}
      <span className="sr-only">
        {stat.value}{stat.suffix} {stat.label} — {stat.sub}
      </span>
    </div>
  );
}

const StatsSection = () => {
  const sectionRef = useRef<HTMLElement>(null);
  const [hasAnimated, setHasAnimated] = useState(false);

  useEffect(() => {
    const el = sectionRef.current;
    if (!el) return;

    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting && !hasAnimated) {
          setHasAnimated(true);
        }
      },
      { threshold: 0.3 }
    );

    observer.observe(el);
    return () => observer.disconnect();
  }, [hasAnimated]);

  return (
    <section
      ref={sectionRef}
      aria-label="Key metrics"
      className="relative py-16 overflow-hidden"
    >
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
            <StatItem key={stat.label} stat={stat} index={index} active={hasAnimated} />
          ))}
        </dl>
      </div>
    </section>
  );
};

export default StatsSection;
