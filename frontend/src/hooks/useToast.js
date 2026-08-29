import { useEffect, useState } from "react";

export function useToast() {
  const [message, setMessage] = useState("");

  useEffect(() => {
    if (!message) return undefined;
    const timer = setTimeout(() => setMessage(""), 2800);
    return () => clearTimeout(timer);
  }, [message]);

  return [message, setMessage];
}
