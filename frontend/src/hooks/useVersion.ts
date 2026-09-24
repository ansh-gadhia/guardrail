import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import type { VersionInfo } from "@/lib/types";

// useVersion fetches the build version surfaced by the API for the foot of the sidebar.
export function useVersion() {
  return useQuery<VersionInfo>({
    queryKey: ["version"],
    queryFn: async () => (await api.get<VersionInfo>("/version")).data,
    staleTime: Infinity,
  });
}
