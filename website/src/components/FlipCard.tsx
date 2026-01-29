import { useState, useEffect } from "react";
import { LucideIcon } from "lucide-react";

interface FlipCardProps {
  icon: LucideIcon;
  title: string;
  description: string;
  highlight: string;
  terminalLines: string[];
  index: number;
}

const FlipCard = ({ icon: Icon, title, description, highlight, terminalLines, index }: FlipCardProps) => {
  const [isFlipped, setIsFlipped] = useState(false);
  const [visibleLines, setVisibleLines] = useState<number>(0);

  useEffect(() => {
    if (isFlipped && visibleLines < terminalLines.length) {
      const timer = setTimeout(() => {
        setVisibleLines(prev => prev + 1);
      }, 400);
      return () => clearTimeout(timer);
    }
    if (!isFlipped) {
      setVisibleLines(0);
    }
  }, [isFlipped, visibleLines, terminalLines.length]);

  return (
    <div 
      className="relative h-72 perspective-1000 cursor-pointer"
      style={{ animationDelay: `${index * 0.1}s` }}
      onClick={() => setIsFlipped(!isFlipped)}
    >
      <div 
        className={`relative w-full h-full transition-transform duration-500 transform-style-3d ${
          isFlipped ? "rotate-y-180" : ""
        }`}
      >
        <div className="absolute inset-0 backface-hidden">
          <div className="card-noir p-6 h-full flex flex-col group">
            <div className="flex items-start justify-between mb-4">
              <div className="p-3 rounded-xl bg-primary/10 text-primary group-hover:bg-primary/20 transition-colors">
                <Icon className="w-6 h-6" />
              </div>
              <span className="text-xs font-mono text-primary/80 bg-primary/10 px-2 py-1 rounded">
                {highlight}
              </span>
            </div>
            <h3 className="font-display text-xl font-semibold mb-3 text-foreground">
              {title}
            </h3>
            <p className="text-sm text-muted-foreground leading-relaxed flex-1">
              {description}
            </p>
            <p className="text-xs text-primary/60 mt-4 font-mono">
              Click to see example →
            </p>
          </div>
        </div>

        <div className="absolute inset-0 backface-hidden rotate-y-180">
          <div className="h-full rounded-xl border border-border bg-background/95 overflow-hidden">
            <div className="flex items-center gap-2 px-4 py-2 bg-secondary/50 border-b border-border">
              <div className="w-3 h-3 rounded-full bg-danger" />
              <div className="w-3 h-3 rounded-full bg-primary" />
              <div className="w-3 h-3 rounded-full bg-success" />
              <span className="ml-2 text-xs text-muted-foreground font-mono">{title.toLowerCase()}</span>
            </div>
            
            <div className="p-4 font-mono text-xs leading-relaxed overflow-hidden">
              {terminalLines.map((line, i) => (
                <p 
                  key={i}
                  className={`transition-opacity duration-300 ${
                    i < visibleLines ? "opacity-100" : "opacity-0"
                  } ${
                    line.startsWith("$") ? "text-muted-foreground" :
                    line.startsWith("✓") ? "text-success" :
                    line.startsWith("🔍") || line.startsWith("→") ? "text-primary" :
                    line.startsWith("⚠") || line.startsWith("!") ? "text-primary" :
                    "text-foreground"
                  } ${i > 0 ? "mt-1" : ""}`}
                >
                  {line}
                </p>
              ))}
            </div>

            <p className="absolute bottom-3 right-3 text-xs text-primary/60 font-mono">
              ← Click to flip back
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default FlipCard;
