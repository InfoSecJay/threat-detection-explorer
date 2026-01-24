import { createContext, useContext, useEffect, useState, ReactNode } from 'react';
import { mitreApi, MitreData, MitreTactic, MitreTechnique } from '../services/api';

interface MitreContextType {
  tactics: Record<string, MitreTactic>;
  techniques: Record<string, MitreTechnique>;
  isLoading: boolean;
  error: Error | null;
  getTacticName: (tacticId: string) => string;
  getTechniqueName: (techniqueId: string) => string;
  getTacticUrl: (tacticId: string) => string;
  getTechniqueUrl: (techniqueId: string) => string;
  refresh: () => Promise<void>;
}

const MitreContext = createContext<MitreContextType | null>(null);

export function MitreProvider({ children }: { children: ReactNode }) {
  const [tactics, setTactics] = useState<Record<string, MitreTactic>>({});
  const [techniques, setTechniques] = useState<Record<string, MitreTechnique>>({});
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);

  const loadMitreData = async () => {
    try {
      setIsLoading(true);
      setError(null);
      const data = await mitreApi.getData();
      setTactics(data.tactics);
      setTechniques(data.techniques);
    } catch (err) {
      setError(err instanceof Error ? err : new Error('Failed to load MITRE data'));
      console.error('Failed to load MITRE data:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadMitreData();
  }, []);

  const getTacticName = (tacticId: string): string => {
    const tactic = tactics[tacticId];
    return tactic?.name || tacticId;
  };

  const getTechniqueName = (techniqueId: string): string => {
    const technique = techniques[techniqueId];
    return technique?.name || '';
  };

  const getTacticUrl = (tacticId: string): string => {
    const tactic = tactics[tacticId];
    return tactic?.url || `https://attack.mitre.org/tactics/${tacticId}/`;
  };

  const getTechniqueUrl = (techniqueId: string): string => {
    const technique = techniques[techniqueId];
    return technique?.url || `https://attack.mitre.org/techniques/${techniqueId.replace('.', '/')}/`;
  };

  const refresh = async () => {
    await mitreApi.refresh();
    await loadMitreData();
  };

  return (
    <MitreContext.Provider
      value={{
        tactics,
        techniques,
        isLoading,
        error,
        getTacticName,
        getTechniqueName,
        getTacticUrl,
        getTechniqueUrl,
        refresh,
      }}
    >
      {children}
    </MitreContext.Provider>
  );
}

export function useMitre(): MitreContextType {
  const context = useContext(MitreContext);
  if (!context) {
    throw new Error('useMitre must be used within a MitreProvider');
  }
  return context;
}
