import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import type { Capabilities } from "@/lib/types";

// useCapabilities reports what this deployment can actually deliver, so the
// console can warn before an operator sets a policy the server cannot honour.
//
// session_recording is false when the server has no browser isolation: frames
// are captured from a server-side browser, so without one there is nothing to
// record. Without this, enabling recording looks like it worked and only turns
// out to be inert when someone opens an empty player — possibly mid-incident.
export function useCapabilities() {
  return useQuery<Capabilities>({
    queryKey: ["capabilities"],
    queryFn: async () => (await api.get<Capabilities>("/capabilities")).data,
    // Server capability changes only on redeploy; no reason to re-ask.
    staleTime: Infinity,
  });
}
