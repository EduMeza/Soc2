import React from 'react';
import { MapContainer, TileLayer, Marker, Popup, CircleMarker } from 'react-leaflet';
import 'leaflet/dist/leaflet.css';
import L from 'leaflet';

delete (L.Icon.Default.prototype as any)._getIconUrl;

L.Icon.Default.mergeOptions({
  iconRetinaUrl: 'https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon-2x.png',
  iconUrl: 'https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon.png',
  shadowUrl: 'https://unpkg.com/leaflet@1.9.4/dist/images/marker-shadow.png',
});

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

interface GeoThreatMapProps {
  data: GeoIPPoint[];
  height?: string;
}

const SEVERITY_COLORS: Record<string, string> = {
  Critical: '#ef4444',
  High: '#f97316',
  Medium: '#eab308',
  Low: '#22c55e',
  Unknown: '#64748b',
};

export const GeoThreatMap: React.FC<GeoThreatMapProps> = ({ data, height = '500px' }) => {
  if (!data || data.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-slate-500 p-8" style={{ height }}>
        <div className="text-6xl mb-4">🌍</div>
        <p className="text-lg font-medium">No existen IPs públicas con geolocalización disponible</p>
        <p className="text-sm mt-2">Las IPs detectadas son privadas, reservadas o sin coordenadas conocidas</p>
      </div>
    );
  }

  const center = [20, 0] as [number, number];

  return (
    <div className="w-full rounded-xl overflow-hidden border border-slate-800" style={{ height }}>
      <MapContainer
        center={center}
        zoom={2}
        scrollWheelZoom={true}
        style={{ width: '100%', height: '100%' }}
      >
        <TileLayer
          attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
          url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
        />
        {data.map((point) => {
          const color = SEVERITY_COLORS[point.severity] || SEVERITY_COLORS.Unknown;
          const radius = Math.max(8, Math.min(30, Math.log(point.event_count + 1) * 6));
          
          return (
            <CircleMarker
              key={point.ip}
              center={[point.latitude, point.longitude]}
              radius={radius}
              pathOptions={{
                color,
                fillColor: color,
                fillOpacity: 0.7,
                weight: 2,
                opacity: 0.9,
              }}
            >
              <Popup>
                <div className="min-w-[200px] p-2">
                  <div className="flex items-center gap-2 mb-2">
                    <span className="font-mono text-sm text-slate-700">{point.ip}</span>
                    <span
                      className="px-1.5 py-0.5 text-xs font-bold rounded"
                      style={{
                        backgroundColor: `${color}20`,
                        color,
                        border: `1px solid ${color}60`,
                      }}
                    >
                      {point.severity}
                    </span>
                  </div>
                  <div className="text-xs text-slate-600 space-y-1">
                    <div><span className="font-medium">País:</span> {point.country} ({point.country_code})</div>
                    <div><span className="font-medium">Ciudad:</span> {point.city}, {point.region}</div>
                    <div><span className="font-medium">Eventos:</span> {point.event_count}</div>
                    {point.asn && <div><span className="font-medium">ASN:</span> {point.asn}</div>}
                    {point.isp && <div><span className="font-medium">ISP:</span> {point.isp}</div>}
                    <div><span className="font-medium">Coords:</span> {point.latitude.toFixed(4)}, {point.longitude.toFixed(4)}</div>
                  </div>
                </div>
              </Popup>
            </CircleMarker>
          );
        })}
      </MapContainer>
    </div>
  );
};

export default GeoThreatMap;