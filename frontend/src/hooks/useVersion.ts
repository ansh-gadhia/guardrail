import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import type { VersionInfo } from "@/lib/types";

// useVersion fetches the build version surfaced by the API for the UI footer.
export function useVersion() {
  return useQuery<VersionInfo>({
    queryKey: ["version"],
    queryFn: async () => (await api.get<VersionInfo>("/version")).data,
    staleTime: Infinity,
  });
}
