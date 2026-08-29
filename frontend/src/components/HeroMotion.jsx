import { useEffect } from "react";
import gsap from "gsap";

export default function HeroMotion() {
  useEffect(() => {
    const timeline = gsap.timeline();
    timeline.from(".hero-word", { yPercent: 115, opacity: 0, duration: 1.15, stagger: 0.12, ease: "power4.out", delay: 0.35 });
    timeline.from([".hero-kicker", ".hero-bottom", ".query-card"], { y: 24, opacity: 0, duration: 0.8, stagger: 0.12, ease: "power3.out" }, "-=0.65");
    const orbit = gsap.to(".hero-orb", { rotation: 16, x: "-3vw", y: "2vh", duration: 12, repeat: -1, yoyo: true, ease: "sine.inOut" });
    return () => {
      timeline.kill();
      orbit.kill();
    };
  }, []);

  return null;
}
