import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { useAuth } from "@/store/auth";
import type { Branding } from "@/lib/types";

/** What an unbranded console shows: the vendor seal. */
export const VENDOR_BRANDING: Branding = {
  client_name: "",
  client_logo: "",
  enabled: true,
  configured: false,
};

/**
 * The organization's branding, read once and shared by everything that paints it.
 *
 * Every signed-in page renders the brand, so this is deliberately a long-lived
 * cache keyed on nothing but the endpoint: the settings page invalidates it when
 * an administrator changes it, and nothing else needs it to be fresher than that.
 * A failure falls back to the vendor seal rather than to an empty rail — a
 * console that briefly cannot reach the API should still look like a product.
 */
export function useBranding() {
  const principal = useAuth((s) => s.principal);
  return useQuery<Branding>({
    queryKey: ["branding"],
    queryFn: async () => (await api.get<Branding>("/settings/branding")).data,
    enabled: !!principal,
    staleTime: 5 * 60_000,
    retry: 1,
    placeholderData: VENDOR_BRANDING,
  });
}
