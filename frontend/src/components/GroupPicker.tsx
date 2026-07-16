import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, problemDetail } from "@/lib/api";
import type { AssetGroup } from "@/lib/types";
import { useAuth } from "@/store/auth";
import { Skeleton, cn } from "@/components/ui";
import { IconCheck, IconFolder, IconPlus } from "@/components/icons";
import { toast } from "@/components/Toast";

/* GroupPicker selects the asset groups a device belongs to. Groups are the unit
   roles are scoped to, so putting a device in a group is what actually grants
   reach — the picker therefore lives on the device form itself, and can create a
   group inline rather than sending the operator elsewhere first. */
export function GroupPicker({ value, onChange }: { value: string[]; onChange: (ids: string[]) => void }) {
  const qc = useQueryClient();
  const canWrite = useAuth((s) => s.has("group:write"));
  const canRead = useAuth((s) => s.has("group:read"));
  const [adding, setAdding] = useState(false);
  const [name, setName] = useState("");

  const groups = useQuery<AssetGroup[]>({
    queryKey: ["asset-groups"],
    queryFn: async () => (await api.get<{ data: AssetGroup[] }>("/asset-groups")).data.data,
    enabled: canRead,
  });

  const create = useMutation({
    mutationFn: async () => (await api.post<AssetGroup>("/asset-groups", { name, type: "folder" })).data,
    onSuccess: (g) => {
      setName("");
      setAdding(false);
      onChange([...value, g.id]);
      void qc.invalidateQueries({ queryKey: ["asset-groups"] });
    },
    onError: (err) => toast.error(problemDetail(err, "Could not create group")),
  });

  if (!canRead) return null;
  const toggle = (id: string) => onChange(value.includes(id) ? value.filter((v) => v !== id) : [...value, id]);
  const list = groups.data ?? [];

  return (
    <div>
      {groups.isLoading ? (
        <Skeleton className="h-8" />
      ) : (
        <div className="flex flex-wrap items-center gap-1.5">
          {list.map((g) => {
            const on = value.includes(g.id);
            return (
              <button
                key={g.id}
                type="button"
                onClick={() => toggle(g.id)}
                aria-pressed={on}
                className={cn(
                  "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs transition",
                  on
                    ? "border-accent/40 bg-accent-soft text-accent"
                    : "border-line bg-surface-2/50 text-muted hover:border-line-strong hover:text-fg",
                )}
              >
                {on ? <IconCheck size={12} /> : <IconFolder size={12} className="opacity-50" />}
                {g.name}
              </button>
            );
          })}
          {!list.length && !adding && <span className="text-xs text-faint">No groups yet.</span>}
          {canWrite &&
            (adding ? (
              <span className="inline-flex items-center gap-1.5">
                <input
                  className="input h-7 w-36 px-2 py-0 text-xs"
                  value={name}
                  autoFocus
                  placeholder="Group name"
                  onChange={(e) => setName(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" && name.trim()) create.mutate();
                    if (e.key === "Escape") {
                      setAdding(false);
                      setName("");
                    }
                  }}
                />
                <button
                  type="button"
                  className="text-2xs font-medium text-accent hover:underline disabled:opacity-40"
                  disabled={!name.trim() || create.isPending}
                  onClick={() => create.mutate()}
                >
                  {create.isPending ? "Adding…" : "Add"}
                </button>
              </span>
            ) : (
              <button
                type="button"
                className="inline-flex items-center gap-1 rounded-full border border-dashed border-line px-2.5 py-1 text-xs text-faint transition hover:border-accent/40 hover:text-accent"
                onClick={() => setAdding(true)}
              >
                <IconPlus size={12} /> New group
              </button>
            ))}
        </div>
      )}
    </div>
  );
}
