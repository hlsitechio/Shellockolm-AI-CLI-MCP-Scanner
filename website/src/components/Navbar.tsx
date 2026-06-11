import { Github, Menu, X, Star, Shield } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useState, useEffect } from "react";

const Navbar = () => {
  const [isScrolled, setIsScrolled] = useState(false);
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);

  useEffect(() => {
    const handleScroll = () => {
      setIsScrolled(window.scrollY > 50);
    };
    window.addEventListener("scroll", handleScroll);
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  const navLinks = [
    { label: "Features", href: "#features" },
    { label: "Install", href: "#install" },
    { label: "Services", href: "#services" },
  ];

  const scrollToSection = (href: string) => {
    const element = document.querySelector(href);
    element?.scrollIntoView({ behavior: "smooth" });
    setIsMobileMenuOpen(false);
  };

  return (
    <nav
      role="navigation"
      aria-label="Main navigation"
      className={`fixed top-0 left-0 right-0 z-50 transition-all duration-300 ${
        isScrolled
          ? "bg-background/90 backdrop-blur-lg border-b border-border shadow-lg"
          : "bg-transparent"
      }`}
    >
      <div className="container mx-auto px-4 sm:px-6">
        <div className="flex items-center justify-between h-16">
          {/* Logo */}
          <a
            href="/"
            className="flex items-center gap-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary focus-visible:ring-offset-2 focus-visible:ring-offset-background rounded-sm"
            aria-label="Shellockolm — home"
          >
            <Shield className="w-5 h-5 text-primary shrink-0" aria-hidden="true" />
            <span className="font-display text-xl font-bold text-gradient-ultramarine">
              Shellockolm
            </span>
          </a>

          {/* Desktop nav links */}
          <div className="hidden md:flex items-center gap-8" role="list">
            {navLinks.map((link) => (
              <button
                key={link.label}
                role="listitem"
                onClick={() => scrollToSection(link.href)}
                className="text-sm text-muted-foreground hover:text-foreground transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary rounded-sm px-1 py-0.5"
              >
                {link.label}
              </button>
            ))}
          </div>

          {/* Desktop CTA buttons */}
          <div className="hidden md:flex items-center gap-3">
            <Button
              variant="outline"
              size="sm"
              className="border-primary/50 hover:bg-primary/10 text-primary hover:text-primary gap-2"
              onClick={() =>
                window.open(
                  "https://github.com/hlsitechio/Shellockolm-AI-CLI-MCP-Scanner",
                  "_blank",
                  "noopener noreferrer"
                )
              }
              aria-label="Star Shellockolm on GitHub"
            >
              <Star className="w-4 h-4 fill-primary" aria-hidden="true" />
              Star on GitHub
            </Button>
            <Button
              size="sm"
              className="bg-primary text-primary-foreground hover:bg-primary/90"
              onClick={() => scrollToSection("#services")}
            >
              Get Help
            </Button>
          </div>

          {/* Mobile menu toggle */}
          <button
            className="md:hidden p-2 rounded-md hover:bg-secondary transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
            onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
            aria-expanded={isMobileMenuOpen}
            aria-controls="mobile-menu"
            aria-label={isMobileMenuOpen ? "Close navigation menu" : "Open navigation menu"}
          >
            {isMobileMenuOpen ? (
              <X className="w-6 h-6 text-foreground" aria-hidden="true" />
            ) : (
              <Menu className="w-6 h-6 text-foreground" aria-hidden="true" />
            )}
          </button>
        </div>

        {/* Mobile menu */}
        {isMobileMenuOpen && (
          <div
            id="mobile-menu"
            className="md:hidden py-4 border-t border-border bg-background/95 backdrop-blur-sm"
          >
            <div className="flex flex-col gap-2">
              {navLinks.map((link) => (
                <button
                  key={link.label}
                  onClick={() => scrollToSection(link.href)}
                  className="text-left text-muted-foreground hover:text-foreground hover:bg-secondary/50 transition-colors py-3 px-2 rounded-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
                >
                  {link.label}
                </button>
              ))}
              <div className="flex flex-col gap-2 pt-2 border-t border-border/50 mt-2">
                <Button
                  variant="outline"
                  size="sm"
                  className="border-primary/50 text-primary w-full justify-center gap-2"
                  onClick={() =>
                    window.open(
                      "https://github.com/hlsitechio/Shellockolm-AI-CLI-MCP-Scanner",
                      "_blank",
                      "noopener noreferrer"
                    )
                  }
                  aria-label="Star Shellockolm on GitHub"
                >
                  <Github className="w-4 h-4" aria-hidden="true" />
                  Star on GitHub
                </Button>
                <Button
                  size="sm"
                  className="bg-primary text-primary-foreground w-full"
                  onClick={() => scrollToSection("#services")}
                >
                  Get Help
                </Button>
              </div>
            </div>
          </div>
        )}
      </div>
    </nav>
  );
};

export default Navbar;
