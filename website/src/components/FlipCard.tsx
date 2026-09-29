import { useState, useEffect, useRef } from "react";
import { LucideIcon } from "lucide-react";

interface FlipCardProps {
  icon: LucideIcon;
  title: string;
  description: string;
  highlight: string;
  terminalLines: string[];
  index: number;
}

const FlipCard = ({
  icon: Icon,
  title,
  description,
  highlight,
  terminalLines,
  index,
}: FlipCardProps) => {
  const [isFlipped, setIsFlipped] = useState(false);
  const [visibleLines, setVisibleLines] = useState<number>(0);
  const cardRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (isFlipped && visibleLines < terminalLines.length) {
      const timer = setTimeout(() => {
        setVisibleLines((prev) => prev + 1);
      }, 380);
      return () => clearTimeout(timer);
    }
    if (!isFlipped) {
      setVisibleLines(0);
    }
  }, [isFlipped, visibleLines, terminalLines.length]);

  const handleToggle = () => setIsFlipped((f) => !f);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      handleToggle();
    }
  };

  return (
    <div
      ref={cardRef}
      role="button"
      tabIndex={0}
      aria-pressed={isFlipped}
      aria-label={
        isFlipped
          ? `${title} — showing terminal example. Press Enter to flip back.`
          : `${title} — ${description} Press Enter to see terminal example.`
      }
      className="relative h-72 perspective-1000 cursor-pointer outline-none focus-visible:ring-2 focus-visible:ring-primary focus-visible:ring-offset-2 focus-visible:ring-offset-background rounded-2xl"
      style={{ animationDelay: `${index * 0.1}s` }}
      onClick={handleToggle}
      onKeyDown={handleKeyDown}
    >
      <div
        className={`relative w-full h-full transition-transform duration-500 transform-style-3d ${
          isFlipped ? "rotate-y-180" : ""
        }`}
        aria-hidden="true"
      >
        {/* Front face */}
        <div className="absolute inset-0 backface-hidden">
          <div className="card-noir p-6 h-full flex flex-col group">
            <div className="flex items-start justify-between mb-4">
              <div className="p-3 rounded-xl bg-primary/10 text-primary group-hover:bg-primary/20 transition-colors">
                <Icon className="w-6 h-6" />
              </div>
              <span className="text-xs font-mono text-primary/80 bg-primary/10 px-2 py-1 rounded border border-primary/20">
                {highlight}
              </span>
            </div>
            <h3 className="font-display text-xl font-semibold mb-3 text-foreground">
              {title}
            </h3>
            <p className="text-sm text-muted-foreground leading-relaxed flex-1">
              {description}
            </p>
            <p className="text-xs text-primary/60 mt-4 font-mono flex items-center gap-1.5">
              <span className="inline-block w-1.5 h-1.5 rounded-full bg-primary/50 animate-pulse" />
              Click to see example
            </p>
          </div>
        </div>

        {/* Back face */}
        <div className="absolute inset-0 backface-hidden rotate-y-180">
          <div className="h-full rounded-2xl border border-primary/30 bg-background/98 overflow-hidden shadow-lg">
            <div className="flex items-center gap-2 px-4 py-2.5 bg-secondary/60 border-b border-border">
              <div className="w-3 h-3 rounded-full bg-danger" />
              <div className="w-3 h-3 rounded-full bg-gold" />
              <div className="w-3 h-3 rounded-full bg-success" />
              <span className="ml-2 text-xs text-muted-foreground font-mono">
                {title.toLowerCase()}
              </span>
            </div>

            <div className="p-4 font-mono text-xs leading-relaxed overflow-hidden">
              {terminalLines.map((line, i) => (
                <p
                  key={i}
                  className={`transition-opacity duration-300 ${
                    i < visibleLines ? "opacity-100" : "opacity-0"
                  } ${
                    line.startsWith("$")
                      ? "text-muted-foreground"
                      : line.startsWith("✓")
                      ? "text-success"
                      : line.startsWith("🔍") || line.startsWith("→")
                      ? "text-primary"
                      : line.startsWith("⚠") || line.startsWith("!")
                      ? "text-gold"
                      : "text-foreground"
                  } ${i > 0 ? "mt-1.5" : ""}`}
                >
                  {line}
                </p>
              ))}
            </div>

            <p className="absolute bottom-3 right-3 text-xs text-primary/50 font-mono">
              ← flip back
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default FlipCard;
