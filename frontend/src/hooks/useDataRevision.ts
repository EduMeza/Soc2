import { useEffect, useState } from 'react';

export function useDataRevision() {
  const [revision, setRevision] = useState(0);
  useEffect(() => {
    const refresh = () => setRevision(value => value + 1);
    const storage = (event: StorageEvent) => { if (event.key === 'soc-data-version') refresh(); };
    window.addEventListener('soc-data-changed', refresh);
    window.addEventListener('storage', storage);
    return () => {
      window.removeEventListener('soc-data-changed', refresh);
      window.removeEventListener('storage', storage);
    };
  }, []);
  return revision;
}
