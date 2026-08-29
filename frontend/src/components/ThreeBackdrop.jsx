import { useEffect, useRef } from "react";
import * as THREE from "three";

export default function ThreeBackdrop() {
  const canvas = useRef(null);

  useEffect(() => {
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(42, window.innerWidth / window.innerHeight, 0.1, 100);
    camera.position.z = 7;
    const renderer = new THREE.WebGLRenderer({ canvas: canvas.current, alpha: true, antialias: true });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 1.5));
    renderer.setSize(window.innerWidth, window.innerHeight);
    const points = new THREE.BufferGeometry();
    const positions = new Float32Array(220 * 3);

    for (let index = 0; index < positions.length; index += 3) {
      positions[index] = (Math.random() - 0.5) * 13;
      positions[index + 1] = (Math.random() - 0.5) * 8;
      positions[index + 2] = (Math.random() - 0.5) * 7;
    }

    points.setAttribute("position", new THREE.BufferAttribute(positions, 3));
    const stars = new THREE.Points(
      points,
      new THREE.PointsMaterial({ color: 0xdfff00, size: 0.025, transparent: true, opacity: 0.65 }),
    );
    const ring = new THREE.Mesh(
      new THREE.TorusGeometry(2.2, 0.006, 8, 90),
      new THREE.MeshBasicMaterial({ color: 0xdfff00, transparent: true, opacity: 0.18 }),
    );
    ring.rotation.x = 1.1;
    scene.add(stars, ring);

    let frame;
    const animate = () => {
      stars.rotation.y += 0.0007;
      ring.rotation.z += 0.0012;
      renderer.render(scene, camera);
      frame = requestAnimationFrame(animate);
    };
    animate();

    const resize = () => {
      camera.aspect = window.innerWidth / window.innerHeight;
      camera.updateProjectionMatrix();
      renderer.setSize(window.innerWidth, window.innerHeight);
    };
    window.addEventListener("resize", resize);
    return () => {
      cancelAnimationFrame(frame);
      window.removeEventListener("resize", resize);
      renderer.dispose();
      points.dispose();
    };
  }, []);

  return <canvas ref={canvas} className="three-backdrop" aria-hidden="true" />;
}
