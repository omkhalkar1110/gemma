import { useEffect, useState, useCallback, useRef } from 'react';
import { ActivityLogItem, DashboardKPIs, PolicySetting } from '../types';

export function useRealtimeFeed() {
  const [logs, setLogs] = useState<ActivityLogItem[]>([]);
  const [kpis, setKpis] = useState<DashboardKPIs | null>(null);
  const [policies, setPolicies] = useState<PolicySetting[]>([]);
  const [loading, setLoading] = useState(true);
  const [wsConnected, setWsConnected] = useState(false);
  const [kpiPulsing, setKpiPulsing] = useState(false);

  const wsRef = useRef<WebSocket | null>(null);

  // Fetch initial data
  const fetchData = useCallback(async () => {
    try {
      const [logsRes, kpisRes, polsRes] = await Promise.all([
        fetch('/api/v1/dashboard/activity').catch(() => null),
        fetch('/api/v1/dashboard/kpis').catch(() => null),
        fetch('/api/v1/policies').catch(() => null)
      ]);

      if (logsRes && logsRes.ok) {
        const text = await logsRes.text();
        try { setLogs(JSON.parse(text)); } catch (_) {}
      }
      if (kpisRes && kpisRes.ok) {
        const text = await kpisRes.text();
        try { setKpis(JSON.parse(text)); } catch (_) {}
      }
      if (polsRes && polsRes.ok) {
        const text = await polsRes.text();
        try { setPolicies(JSON.parse(text)); } catch (_) {}
      }
    } catch (err) {
      console.warn('Dashboard data refresh caught:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  // Set up WebSocket connection
  useEffect(() => {
    fetchData();

    let retryTimeout: any = null;
    let isMounted = true;

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/live-feed`;

    const connectWs = () => {
      if (!isMounted) return;
      try {
        const ws = new WebSocket(wsUrl);
        wsRef.current = ws;

        ws.onopen = () => {
          if (isMounted) setWsConnected(true);
        };

        ws.onmessage = (event) => {
          if (!isMounted) return;
          try {
            const data = JSON.parse(event.data);

            if (data.type === 'NEW_ACTIVITY') {
              const newItem: ActivityLogItem = data.payload;

              // Avoid duplicates
              setLogs((prev) => {
                if (prev.some((item) => item.id === newItem.id)) {
                  return prev;
                }
                return [newItem, ...prev];
              });

              setKpiPulsing(true);
              setTimeout(() => {
                if (isMounted) setKpiPulsing(false);
              }, 1200);

              fetch('/api/v1/dashboard/kpis')
                .then((res) => (res.ok ? res.text() : Promise.reject()))
                .then((text) => JSON.parse(text))
                .then((updatedKpis) => {
                  if (isMounted) setKpis(updatedKpis);
                })
                .catch(() => {});
            } else if (data.type === 'POLICY_UPDATE') {
              const { key, enabled } = data.payload;
              setPolicies((prev) =>
                prev.map((p) => (p.key === key ? { ...p, enabled } : p))
              );
            }
          } catch (_) {
            // Ignore invalid messages
          }
        };

        ws.onclose = () => {
          if (!isMounted) return;
          setWsConnected(false);
          retryTimeout = setTimeout(connectWs, 5000);
        };

        ws.onerror = () => {
          if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) {
            try {
              ws.close();
            } catch (_) {}
          }
        };
      } catch (_) {
        if (isMounted) setWsConnected(false);
      }
    };

    connectWs();

    return () => {
      isMounted = false;
      if (retryTimeout) clearTimeout(retryTimeout);
      if (wsRef.current) {
        try {
          wsRef.current.close();
        } catch (_) {}
      }
    };
  }, [fetchData]);

  // Polling fallback
  useEffect(() => {
    const interval = setInterval(() => {
      fetchData();
    }, wsConnected ? 60000 : 15000); // 15 seconds to avoid aggressive 429 rate limits

    return () => clearInterval(interval);
  }, [wsConnected, fetchData]);

  // Toggle Policy handler
  const togglePolicy = async (key: string, enabled: boolean) => {
    setPolicies((prev) =>
      prev.map((p) => (p.key === key ? { ...p, enabled } : p))
    );

    try {
      const res = await fetch(`/api/v1/policies/${key}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled })
      });
      if (!res.ok) {
        fetchData();
      }
    } catch (_) {
      fetchData();
    }
  };

  return {
    logs,
    kpis,
    policies,
    loading,
    wsConnected,
    kpiPulsing,
    togglePolicy,
    refreshData: fetchData
  };
}

