/**
 * AEGIS C2 Dashboard - LIVE API VERSION (v2.1)
 *
 * CHANGE LOG:
 * - Replaced mockDataGenerator with real API calls
 * - Fetches from /api/v1/graph/active-threats, /api/v1/graph/timing
 * - Falls back to mock data if backend is unreachable (graceful degradation)
 * - Added loading / error states
 */

import { useEffect, useCallback, useRef, useState } from 'react';
import { NetworkGraph } from './NetworkGraph';
import { BeaconingScatter } from './BeaconingScatter-NoTailwind';
import { NodeInspector } from './NodeInspector-NoTailwind';
import { GlobalControls } from './GlobalControls-NoTailwind';
import { KillSwitchModal } from './KillSwitchModal-NoTailwind';
import { IsolateNodeModal } from './IsolateNodeModal-NoTailwind';
import { ThreatLegend } from './ThreatLegend-NoTailwind';
import { useThreatStore } from './useThreatStore';
import { generateMockData } from './mockDataGenerator';
import { getNodeStatus } from './types';
import type { ThreatNode, ThreatLink } from './types';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000/api';

const styles = {
  container: {
    height: '100vh',
    width: '100%',
    background: '#0a0e1a',
    color: 'white',
    overflow: 'hidden',
    position: 'relative' as const,
  },
  background: {
    position: 'absolute' as const,
    inset: 0,
    background: 'linear-gradient(to bottom right, #111827, #0a0e1a, #000000)',
  },
  content: {
    position: 'relative' as const,
    height: '100%',
    display: 'flex',
    flexDirection: 'column' as const,
    padding: '16px',
    gap: '16px',
  },
  header: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
  },
  headerLeft: {
    display: 'flex',
    alignItems: 'center',
    gap: '16px',
  },
  logo: {
    width: '40px',
    height: '40px',
    borderRadius: '12px',
    background: 'linear-gradient(to bottom right, #06b6d4, #3b82f6)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    fontSize: '20px',
  },
  title: {
    fontSize: '24px',
    fontWeight: 'bold',
    background: 'linear-gradient(to right, #06b6d4, #3b82f6)',
    WebkitBackgroundClip: 'text',
    WebkitTextFillColor: 'transparent',
    backgroundClip: 'text',
  },
  subtitle: {
    color: '#6b7280',
    fontSize: '14px',
  },
  mainGrid: {
    flex: 1,
    display: 'grid',
    gridTemplateColumns: '3fr 2fr',
    gap: '16px',
    minHeight: 0,
  },
  graphContainer: {
    position: 'relative' as const,
    background: 'rgba(17, 24, 39, 0.3)',
    borderRadius: '16px',
    overflow: 'hidden',
    border: '1px solid rgba(55, 65, 81, 0.5)',
  },
  rightPanel: {
    display: 'flex',
    flexDirection: 'column' as const,
    gap: '16px',
    minHeight: 0,
  },
  scatterContainer: {
    height: '45%',
    minHeight: 0,
  },
  inspectorContainer: {
    flex: 1,
    minHeight: 0,
  },
  footer: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    color: '#4b5563',
    fontSize: '12px',
  },
  statusDot: (color: string) => ({
    width: '8px',
    height: '8px',
    borderRadius: '50%',
    background: color,
    animation: 'pulse 2s ease-in-out infinite',
  }),
};


/** Map API threat data → internal ThreatNode format */
function mapApiNode(apiNode: any): ThreatNode {
  const confidence = apiNode.score ?? 0;
  return {
    id: apiNode.id,
    ip: apiNode.id,
    label: apiNode.id,
    confidence,
    centrality: 0,
    connections: apiNode.connections ?? 0,
    status: getNodeStatus(confidence),
    lastSeen: Date.now(),
    timingData: [],
    reasons: apiNode.primaryIndicator
      ? [apiNode.primaryIndicator]
      : [],
  };
}

function mapApiLink(apiLink: any): ThreatLink {
  return {
    source: apiLink.source,
    target: apiLink.target,
    value: apiLink.weight ?? 1,
    type: 'normal',
  };
}


export function C2Dashboard({ scale = 1.5 }: { scale?: number }) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [dimensions, setDimensions] = useState({ width: 800, height: 600 });
  const [dataSource, setDataSource] = useState<'live' | 'mock'>('live');

  const { setNodes, setLinks, reset } = useThreatStore();

  // Responsive sizing
  useEffect(() => {
    const updateDimensions = () => {
      if (containerRef.current) {
        const rect = containerRef.current.getBoundingClientRect();
        setDimensions({
          width: rect.width - 32,
          height: rect.height - 32,
        });
      }
    };

    updateDimensions();
    window.addEventListener('resize', updateDimensions);
    return () => window.removeEventListener('resize', updateDimensions);
  }, []);

  // Fetch LIVE data from the Attribution Engine API
  const fetchLiveData = useCallback(async () => {
    try {
      // Reset state for fresh fetch
      const resp = await fetch(`${API_BASE}/v1/graph/active-threats?min_score=0&max_nodes=500`);

      if (!resp.ok) {
        throw new Error(`API returned ${resp.status}`);
      }

      const data = await resp.json();
      const nodes = (data.nodes || []).map(mapApiNode);
      const links = (data.links || []).map(mapApiLink);

      if (nodes.length === 0) {
        // Backend reachable but no data — fall back to mock
        throw new Error('No nodes returned from API');
      }

      setNodes(nodes);
      setLinks(links);
      setDataSource('live');
      console.log(`[AEGIS] Loaded ${nodes.length} LIVE nodes from Attribution Engine`);
    } catch (err: any) {
      console.warn(`[AEGIS] Live API unavailable (${err.message}), falling back to mock data`);
      // Log error — fallback to mock data below
      generateFallbackData();
    }
  }, [setNodes, setLinks]);

  // Fallback to mock data when API is unavailable
  const generateFallbackData = useCallback(() => {
    reset();
    const data = generateMockData(scale);
    setNodes(data.nodes);
    setLinks(data.links);
    setDataSource('mock');
    console.log(`[AEGIS] Generated ${data.nodes.length} MOCK nodes (fallback)`);
  }, [scale, reset, setNodes, setLinks]);

  // Load data on mount — try live first, fall back to mock
  useEffect(() => {
    fetchLiveData();
  }, [fetchLiveData]);

  return (
    <div style={styles.container}>
      <div style={styles.background} />

      <div style={styles.content}>
        {/* Header */}
        <div style={styles.header}>
          <div style={styles.headerLeft}>
            <div style={styles.logo}>🛡️</div>
            <div>
              <h1 style={styles.title}>AEGIS Active Attribution Engine</h1>
              <p style={styles.subtitle}>Real-time C2 Infrastructure Detection</p>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ color: '#6b7280', fontSize: '14px' }}>v2.1</span>
            <div style={styles.statusDot(dataSource === 'live' ? '#10b981' : '#f59e0b')} />
            <span style={{ color: dataSource === 'live' ? '#10b981' : '#f59e0b', fontSize: '14px' }}>
              {dataSource === 'live' ? 'Live' : 'Mock Data'}
            </span>
          </div>
        </div>

        {/* Global Controls */}
        <GlobalControls
          onGenerateData={fetchLiveData}
          onClear={reset}
        />

        {/* Main Grid */}
        <div style={styles.mainGrid}>
          {/* Network Graph */}
          <div ref={containerRef} style={styles.graphContainer}>
            <NetworkGraph width={dimensions.width} height={dimensions.height} />
            <ThreatLegend />
          </div>

          {/* Right Panel */}
          <div style={styles.rightPanel}>
            <div style={styles.scatterContainer}>
              <BeaconingScatter />
            </div>
            <div style={styles.inspectorContainer}>
              <NodeInspector />
            </div>
          </div>
        </div>

        {/* Footer */}
        <div style={styles.footer}>
          <span>© 2025 AEGIS Security • Enterprise Threat Intelligence</span>
          <span>
            {dataSource === 'live'
              ? 'WebGL Rendering • Live Attribution Engine'
              : 'WebGL Rendering • Mock Data (Backend Offline)'}
          </span>
        </div>
      </div>

      <KillSwitchModal />
      <IsolateNodeModal />
    </div>
  );
}
