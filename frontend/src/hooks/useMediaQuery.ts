import { useEffect, useState } from "react";

// useMediaQuery tracks a CSS media query, for the few decisions that have to be
// made in script rather than in a stylesheet — whether to run an animation loop
// at all, for instance.
export function useMediaQuery(query: string): boolean {
  const [matches, setMatches] = useState(() => typeof window !== "undefined" && window.matchMedia(query).matches);
  useEffect(() => {
    const mq = window.matchMedia(query);
    const onChange = () => setMatches(mq.matches);
    onChange();
    mq.addEventListener("change", onChange);
    return () => mq.removeEventListener("change", onChange);
  }, [query]);
  return matches;
}
