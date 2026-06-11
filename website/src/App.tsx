import Navbar from "@/components/Navbar";
import HeroSection from "@/components/HeroSection";
import LiveDemoSection from "@/components/LiveDemoSection";
import FeaturesSection from "@/components/FeaturesSection";
import StatsSection from "@/components/StatsSection";
import InstallSection from "@/components/InstallSection";
import PricingSection from "@/components/PricingSection";
import Footer from "@/components/Footer";

const App = () => {
  return (
    <div className="min-h-screen bg-background">
      {/* Skip-to-content for keyboard users */}
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:absolute focus:top-4 focus:left-4 focus:z-[100] focus:px-4 focus:py-2 focus:bg-primary focus:text-primary-foreground focus:rounded-md focus:font-medium focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2"
      >
        Skip to content
      </a>

      <Navbar />

      <main id="main-content">
        <HeroSection />
        <StatsSection />
        <LiveDemoSection />
        <section id="features" aria-label="Features">
          <FeaturesSection />
        </section>
        <section id="install" aria-label="Installation">
          <InstallSection />
        </section>
        <section id="services" aria-label="Services and pricing">
          <PricingSection />
        </section>
      </main>

      <Footer />
    </div>
  );
};

export default App;
