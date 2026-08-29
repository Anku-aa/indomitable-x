import { useEffect, useRef } from "react";

export default function CustomCursor() {
  const dot = useRef(null);
  const ring = useRef(null);

  useEffect(() => {
    if (window.matchMedia("(pointer: coarse)").matches) return undefined;

    document.body.classList.add("has-custom-cursor");
    const move = (event) => {
      if (dot.current) {
        dot.current.style.left = `${event.clientX}px`;
        dot.current.style.top = `${event.clientY}px`;
      }
      if (ring.current) {
        ring.current.style.left = `${event.clientX}px`;
        ring.current.style.top = `${event.clientY}px`;
      }
    };
    const over = (event) => {
      if (event.target.closest("a,button,input,textarea")) {
        ring.current?.classList.add("cursor-active");
      }
    };
    const out = (event) => {
      if (event.target.closest("a,button,input,textarea")) {
        ring.current?.classList.remove("cursor-active");
      }
    };

    window.addEventListener("pointermove", move);
    document.addEventListener("pointerover", over);
    document.addEventListener("pointerout", out);
    return () => {
      document.body.classList.remove("has-custom-cursor");
      window.removeEventListener("pointermove", move);
      document.removeEventListener("pointerover", over);
      document.removeEventListener("pointerout", out);
    };
  }, []);

  return (
    <>
      <div ref={dot} className="cursor-dot" aria-hidden="true" />
      <div ref={ring} className="cursor-ring" aria-hidden="true" />
    </>
  );
}
