import { useCallback, useEffect, useState } from "react";
import { ipc, type Settings } from "@/lib/ipc";

/**
 * Load and persist operator settings.
 *
 * Settings live in the Rust side's config file, so a change made here is what
 * every subsequent backend call uses — the UI never carries endpoints itself.
 */
export function useSettings() {
  const [settings, setSettings] = useState<Settings | null>(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    ipc
      .getSettings()
      .then(setSettings)
      .catch((err) => setError(err instanceof Error ? err.message : String(err)));
  }, []);

  const save = useCallback(async (next: Settings) => {
    setSaving(true);
    setError(null);
    try {
      const saved = await ipc.setSettings(next);
      setSettings(saved);
      return true;
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      return false;
    } finally {
      setSaving(false);
    }
  }, []);

  return { settings, save, saving, error };
}
