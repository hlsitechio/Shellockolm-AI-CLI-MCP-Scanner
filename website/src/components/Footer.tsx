import { Github, FileText, Shield, Heart } from "lucide-react";

const Footer = () => {
  const links = [
    { label: "Quick Start", href: "https://github.com/hlsitechio/shellockolm/blob/main/docs/QUICK_START.md", icon: FileText },
    { label: "GitHub Scanner", href: "https://github.com/hlsitechio/shellockolm/blob/main/docs/GITHUB_SCANNER.md", icon: Github },
    { label: "Privacy & Security", href: "https://github.com/hlsitechio/shellockolm/blob/main/PRIVACY_AND_SECURITY.md", icon: Shield },
    { label: "Contributing", href: "https://github.com/hlsitechio/shellockolm/blob/main/CONTRIBUTING.md", icon: Heart },
  ];

  return (
    <footer className="relative py-16 border-t border-border">
      <div className="absolute inset-0 bg-gradient-dark" />
      
      <div className="relative z-10 container mx-auto px-6">
        <div className="flex flex-col md:flex-row items-center justify-between gap-8">
          <div className="text-center md:text-left">
            <h3 className="font-display text-2xl font-bold text-gradient-gold mb-2">
              Shellockolm
            </h3>
            <p className="text-sm text-muted-foreground italic">
              "Elementary, my dear developer!"
            </p>
          </div>

          <div className="flex flex-wrap justify-center gap-6">
            {links.map((link) => (
              <a
                key={link.label}
                href={link.href}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-2 text-sm text-muted-foreground hover:text-primary transition-colors"
              >
                <link.icon className="w-4 h-4" />
                {link.label}
              </a>
            ))}
          </div>
        </div>

        <div className="mt-12 pt-8 border-t border-border/50 flex flex-col md:flex-row items-center justify-between gap-4 text-sm text-muted-foreground">
          <p>MIT License • Built by HLSITech</p>
          <a
            href="https://github.com/hlsitechio/shellockolm"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-2 hover:text-primary transition-colors"
          >
            <Github className="w-4 h-4" />
            github.com/hlsitechio/shellockolm
          </a>
        </div>
      </div>
    </footer>
  );
};

export default Footer;
