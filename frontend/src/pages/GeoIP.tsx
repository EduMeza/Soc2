import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import { useDataRevision } from '../hooks/useDataRevision';
import { GeoThreatMap } from '../maps/GeoThreatMap';

interface GeoIPPoint {
  ip: string;
  country: string;
  country_code: string;
  region: string;
  city: string;
  latitude: number;
  longitude: number;
  asn?: string | null;
  isp?: string | null;
  event_count: number;
  severity: string;
}

export const GeoIP: React.FC = () => {
  const revision = useDataRevision();
  const [geoipData, setGeoipData] = useState<GeoIPPoint[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [retry, setRetry] = useState(0);

  useEffect(() => {
    const fetchGeoIP = async () => {
      try {
        setLoading(true);
        setError(null);
        const response = await api.getGeoip([]);
        const results = response.results || [];
        setGeoipData(results);
      } catch (err) {
        console.error('Error fetching GeoIP:', err);
        setError('Error al cargar datos GeoIP');
      } finally {
        setLoading(false);
      }
    };
    fetchGeoIP();
  }, [retry, revision]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-4 border-emerald-500 border-t-transparent"></div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="error-panel space-y-4">
        <p>{error}</p>
        <button className="btn-secondary" onClick={()=>setRetry(retry+1)}>Reintentar</button>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-extrabold text-white">GeoIP / Mapa de Amenazas</h2>
          <p className="text-slate-400 text-sm">Geolocalización de IPs públicas detectadas en eventos</p>
        </div>
        <div className="text-right text-sm text-slate-400">
          <p>{geoipData.length} IPs con coordenadas válidas</p>
        </div>
      </div>

      <section className="bg-slate-900 rounded-2xl p-6 border border-slate-800 shadow-xl">
        <h3 className="text-xl font-extrabold mb-4 text-white">Mapa de Amenazas Interactivo</h3>
        <GeoThreatMap data={geoipData} height="500px" />
      </section>

      {geoipData.length > 0 && (
        <section className="bg-slate-900 rounded-2xl p-6 border border-slate-800 shadow-xl">
          <h3 className="text-xl font-extrabold mb-4 text-white">Detalle de IPs Geolocalizadas</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {geoipData.map((ip) => (
              <div key={ip.ip} className="bg-slate-950 rounded-xl p-5 border border-slate-800 shadow-lg hover:border-emerald-500/30 transition">
                <div className="flex items-center gap-3 mb-3">
                  <span className="text-2xl">{ip.country_code === 'US' ? '🇺🇸' : ip.country_code === 'RU' ? '🇷🇺' : ip.country_code === 'NL' ? '🇳🇱' : '🌐'}</span>
                  <div>
                    <p className="font-bold text-white font-mono text-sm">{ip.ip}</p>
                    <p className="text-xs text-slate-400">{ip.country} - {ip.region}, {ip.city}</p>
                  </div>
                  <span className={`ml-auto px-2 py-0.5 text-xs font-bold rounded ${
                    ip.severity === 'Critical' ? 'bg-red-900 text-red-300' :
                    ip.severity === 'High' ? 'bg-orange-900 text-orange-300' :
                    ip.severity === 'Medium' ? 'bg-yellow-900 text-yellow-300' :
                    'bg-green-900 text-green-300'
                  }`}>
                    {ip.severity}
                  </span>
                </div>
                <div className="grid grid-cols-2 gap-2 text-xs text-slate-400 mb-3">
                  <div><span className="text-slate-500">Eventos:</span> <span className="text-white ml-1">{ip.event_count}</span></div>
                  <div><span className="text-slate-500">ASN:</span> <span className="text-white ml-1">{ip.asn || 'N/A'}</span></div>
                  <div><span className="text-slate-500">ISP:</span> <span className="text-white ml-1">{ip.isp || 'N/A'}</span></div>
                  <div><span className="text-slate-500">Coords:</span> <span className="text-white ml-1">{ip.latitude.toFixed(4)}, {ip.longitude.toFixed(4)}</span></div>
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      {geoipData.length === 0 && (
        <section className="bg-slate-900 rounded-2xl p-12 border border-slate-800 shadow-xl text-center">
          <div className="text-6xl mb-4">🌍</div>
          <h3 className="text-xl font-bold text-slate-300 mb-2">No hay IPs públicas con geolocalización disponible</h3>
          <p className="text-slate-500">
            Las IPs detectadas en los eventos son privadas (RFC1918), reservadas (TEST-NET) 
            o no tienen coordenadas en la base de datos offline.
          </p>
          <p className="text-xs text-slate-600 mt-4">
            Para habilitar geolocalización completa, configure una base de datos GeoIP (MaxMind GeoLite2) 
            o una API de geolocalización en la configuración del backend.
          </p>
        </section>
      )}
    </div>
  );
};

export default GeoIP;
