import Navbar from "@/components/Navbar";
import HeroSection from "@/components/HeroSection";
import FeaturesSection from "@/components/FeaturesSection";
import StatsSection from "@/components/StatsSection";
import InstallSection from "@/components/InstallSection";
import Footer from "@/components/Footer";

const App = () => {
  return (
    <div className="min-h-screen bg-background">
      <Navbar />
      <main>
        <HeroSection />
        <StatsSection />
        <section id="features">
          <FeaturesSection />
        </section>
        <section id="install">
          <InstallSection />
        </section>
      </main>
      <Footer />
    </div>
  );
};

export default App;
