import { Github, FileText, Shield, Heart } from "lucide-react";

const Footer = () => {
  const links = [
    {
      label: "Quick Start",
      href: "https://github.com/hlsitechio/Shellockolm-AI-CLI-MCP-Scanner/blob/main/docs/QUICK_START.md",
      icon: FileText,
    },
    {
      label: "GitHub Scanner",
      href: "https://github.com/hlsitechio/Shellockolm-AI-CLI-MCP-Scanner/blob/main/docs/GITHUB_SCANNER.md",
      icon: Github,
    },
    {
      label: "Privacy & Security",
      href: "https://github.com/hlsitechio/Shellockolm-AI-CLI-MCP-Scanner/blob/main/PRIVACY_AND_SECURITY.md",
      icon: Shield,
    },
    {
      label: "Contributing",
      href: "https://github.com/hlsitechio/Shellockolm-AI-CLI-MCP-Scanner/blob/main/CONTRIBUTING.md",
      icon: Heart,
    },
  ];

  return (
    <footer
      role="contentinfo"
      className="relative py-14 border-t border-border"
    >
      <div className="absolute inset-0 bg-gradient-dark" aria-hidden="true" />

      <div className="relative z-10 container mx-auto px-4 sm:px-6">
        <div className="flex flex-col md:flex-row items-center justify-between gap-8">
          {/* Brand */}
          <div className="text-center md:text-left">
            <h2 className="font-display text-2xl font-bold text-gradient-gold mb-1">
              Shellockolm
            </h2>
            <p className="text-sm text-muted-foreground italic">
              "Elementary, my dear developer!"
            </p>
          </div>

          {/* Navigation links */}
          <nav aria-label="Footer navigation">
            <ul className="flex flex-wrap justify-center gap-5 sm:gap-6">
              {links.map((link) => (
                <li key={link.label}>
                  <a
                    href={link.href}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-2 text-sm text-muted-foreground hover:text-primary transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary rounded-sm"
                  >
                    <link.icon className="w-4 h-4 shrink-0" aria-hidden="true" />
                    {link.label}
                  </a>
                </li>
              ))}
            </ul>
          </nav>
        </div>

        {/* Bottom bar */}
        <div className="mt-10 pt-7 border-t border-border/40 flex flex-col sm:flex-row items-center justify-between gap-3 text-sm text-muted-foreground">
          <p>
            MIT License &nbsp;·&nbsp; Built by{" "}
            <span className="text-foreground/70 font-medium">HLSITech</span>
          </p>
          <a
            href="https://github.com/hlsitechio/Shellockolm-AI-CLI-MCP-Scanner"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-2 hover:text-primary transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary rounded-sm"
            aria-label="View Shellockolm source code on GitHub"
          >
            <Github className="w-4 h-4 shrink-0" aria-hidden="true" />
            <span className="truncate max-w-xs sm:max-w-none">
              github.com/hlsitechio/Shellockolm-AI-CLI-MCP-Scanner
            </span>
          </a>
        </div>
      </div>
    </footer>
  );
};

export default Footer;
