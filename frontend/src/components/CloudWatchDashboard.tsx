import React, { useState, useEffect, useRef } from 'react';
import { Plus, Trash2, Edit3, X, RefreshCw, Layout, ChevronDown } from 'lucide-react';
import type { Agent, Alert } from '../types';

interface Widget {
  id: string;
  x: number; // grid columns (0-11)
  y: number; // grid row
  w: number; // width span (1-12)
  h: number; // height span
  title: string;
  dataSource: 'CloudWatch' | 'Other' | 'Create';
  dataType: 'Metrics' | 'Logs' | 'Alarms';
  experience: 'Console' | 'QueryStudio';
  widgetType: 'Line' | 'Table' | 'Number' | 'Gauge';
  metricName?: string; // 'cpu' | 'ram' | 'disk' | 'threat' | 'network'
  agentId?: string;
  logFacility?: string;
  logQuery?: string;
  alertSeverity?: string;
  alertStatus?: string;
}

interface Props {
  agents: Agent[];
  recentAlerts: Alert[];
}

const DEFAULT_WIDGETS: Widget[] = [
  {
    id: 'w-cpu-prod-01',
    x: 0, y: 0, w: 6, h: 6,
    title: 'Primary Host CPU Utilization',
    dataSource: 'CloudWatch',
    dataType: 'Metrics',
    experience: 'Console',
    widgetType: 'Line',
    metricName: 'cpu',
    agentId: ''
  },
  {
    id: 'w-active-alarms',
    x: 6, y: 0, w: 6, h: 6,
    title: 'Active Security Alarms',
    dataSource: 'CloudWatch',
    dataType: 'Alarms',
    experience: 'Console',
    widgetType: 'Table',
    alertSeverity: 'all',
    alertStatus: 'open'
  },
  {
    id: 'w-web-logs',
    x: 0, y: 6, w: 8, h: 6,
    title: 'Live Web Access Logs',
    dataSource: 'CloudWatch',
    dataType: 'Logs',
    experience: 'QueryStudio',
    widgetType: 'Table',
    logFacility: 'web',
    logQuery: ''
  },
  {
    id: 'w-threat-gauge',
    x: 8, y: 6, w: 4, h: 6,
    title: 'Primary Host Threat Score',
    dataSource: 'CloudWatch',
    dataType: 'Metrics',
    experience: 'Console',
    widgetType: 'Gauge',
    metricName: 'threat',
    agentId: ''
  },
  {
    id: 'w-system-status',
    x: 0, y: 12, w: 6, h: 5,
    title: 'Aegis System Status',
    dataSource: 'CloudWatch',
    dataType: 'Metrics',
    experience: 'Console',
    widgetType: 'Number',
    metricName: 'system_status'
  },
  {
    id: 'w-active-alerts-count',
    x: 6, y: 12, w: 6, h: 5,
    title: 'Overall Active Incident Alerts',
    dataSource: 'CloudWatch',
    dataType: 'Metrics',
    experience: 'Console',
    widgetType: 'Number',
    metricName: 'active_alerts'
  }
];

const overlaps = (w1: Widget, w2: Widget) => {
  const w1x = Number(w1.x);
  const w1y = Number(w1.y);
  const w1w = Number(w1.w);
  const w1h = Number(w1.h);

  const w2x = Number(w2.x);
  const w2y = Number(w2.y);
  const w2w = Number(w2.w);
  const w2h = Number(w2.h);

  return !(
    w1x + w1w <= w2x ||
    w2x + w2w <= w1x ||
    w1y + w1h <= w2y ||
    w2y + w2h <= w1y
  );
};

const resolveCollisions = (allWidgets: Widget[], activeId: string): Widget[] => {
  const sorted = [...allWidgets].sort((a, b) => {
    const ay = Number(a.y);
    const by = Number(b.y);
    if (ay !== by) return ay - by;
    return Number(a.x) - Number(b.x);
  });

  const activeWidget = sorted.find(w => w.id === activeId);
  if (!activeWidget) return allWidgets;

  const positioned: Widget[] = [];
  positioned.push(activeWidget);

  sorted.forEach(w => {
    if (w.id === activeId) return;

    let current = { ...w };
    let hasCollision = true;

    while (hasCollision) {
      hasCollision = false;
      for (const other of positioned) {
        if (overlaps(current, other)) {
          current.y = Number(other.y) + Number(other.h);
          hasCollision = true;
          break;
        }
      }
    }
    positioned.push(current);
  });

  return positioned;
};

const compactLayout = (allWidgets: Widget[]): Widget[] => {
  const sorted = [...allWidgets].sort((a, b) => Number(a.y) - Number(b.y));
  const compacted: Widget[] = [];

  sorted.forEach(w => {
    let current = { ...w };
    while (Number(current.y) > 0) {
      current.y = Number(current.y) - 1;
      let collides = false;
      for (const other of compacted) {
        if (overlaps(current, other)) {
          collides = true;
          break;
        }
      }
      if (collides) {
        current.y = Number(current.y) + 1;
        break;
      }
    }
    compacted.push(current);
  });

  return compacted;
};

export default function CloudWatchDashboard({ agents, recentAlerts }: Props) {
  const [widgets, setWidgets] = useState<Widget[]>(() => {
    const saved = localStorage.getItem('cw_widgets');
    return saved ? JSON.parse(saved) : DEFAULT_WIDGETS;
  });
  
  const [autosave, setAutosave] = useState<boolean>(() => {
    const saved = localStorage.getItem('cw_autosave');
    return saved ? JSON.parse(saved) : true;
  });

  const [activeDragId, setActiveDragId] = useState<string | null>(null);
  const [activeResizeId, setActiveResizeId] = useState<string | null>(null);
  const [dragOffset, setDragOffset] = useState<{ x: number; y: number } | null>(null);
  const [ghostCoords, setGhostCoords] = useState<{ x: number; y: number; w: number; h: number } | null>(null);

  const [isConfigModalOpen, setIsConfigModalOpen] = useState(false);
  const [isMetadataModalOpen, setIsMetadataModalOpen] = useState(false);
  const [editingWidgetId, setEditingWidgetId] = useState<string | null>(null);

  // Form states for modal
  const [formDataSource, setFormDataSource] = useState<'CloudWatch' | 'Other' | 'Create'>('CloudWatch');
  const [formDataType, setFormDataType] = useState<'Metrics' | 'Logs' | 'Alarms'>('Metrics');
  const [formExperience, setFormExperience] = useState<'Console' | 'QueryStudio'>('Console');
  const [formWidgetType, setFormWidgetType] = useState<'Line' | 'Table' | 'Number' | 'Gauge'>('Line');
  const [formTitle, setFormTitle] = useState('');
  const [formMetricName, setFormMetricName] = useState('cpu');
  const [formAgentId, setFormAgentId] = useState('');
  const [formLogFacility, setFormLogFacility] = useState('all');
  const [formLogQuery, setFormLogQuery] = useState('');
  const [formAlertSeverity, setFormAlertSeverity] = useState('all');
  const [formAlertStatus, setFormAlertStatus] = useState('all');

  const containerRef = useRef<HTMLDivElement>(null);
  const [isDropdownOpen, setIsDropdownOpen] = useState(false);

  useEffect(() => {
    if (agents.length > 0 && !formAgentId) {
      setFormAgentId(agents[0].id);
    }
  }, [agents, formAgentId]);

  const saveToStorage = (updatedWidgets: Widget[]) => {
    localStorage.setItem('cw_widgets', JSON.stringify(updatedWidgets));
  };

  const handleSaveDashboard = () => {
    saveToStorage(widgets);
    alert('Dashboard configuration saved successfully!');
  };

  const handleToggleAutosave = () => {
    const newVal = !autosave;
    setAutosave(newVal);
    localStorage.setItem('cw_autosave', JSON.stringify(newVal));
    if (newVal) {
      saveToStorage(widgets);
    }
  };

  const handleAddWidgetClick = () => {
    setEditingWidgetId(null);
    setFormTitle('New Widget');
    setFormDataSource('CloudWatch');
    setFormDataType('Metrics');
    setFormExperience('Console');
    setFormWidgetType('Line');
    setFormMetricName('cpu');
    if (agents.length > 0) setFormAgentId(agents[0].id);
    setFormLogFacility('all');
    setFormLogQuery('');
    setFormAlertSeverity('all');
    setFormAlertStatus('all');
    setIsConfigModalOpen(true);
  };

  const handleEditWidgetClick = (w: Widget) => {
    setEditingWidgetId(w.id);
    setFormTitle(w.title);
    setFormDataSource(w.dataSource);
    setFormDataType(w.dataType);
    setFormExperience(w.experience);
    setFormWidgetType(w.widgetType);
    setFormMetricName(w.metricName || 'cpu');
    setFormAgentId(w.agentId || (agents.length > 0 ? agents[0].id : ''));
    setFormLogFacility(w.logFacility || 'all');
    setFormLogQuery(w.logQuery || '');
    setFormAlertSeverity(w.alertSeverity || 'all');
    setFormAlertStatus(w.alertStatus || 'all');
    setIsConfigModalOpen(true);
  };

  const handleDeleteWidget = (id: string) => {
    if (confirm('Are you sure you want to remove this widget?')) {
      const updated = widgets.filter(w => w.id !== id);
      setWidgets(updated);
      if (autosave) saveToStorage(updated);
    }
  };

  const handleModalSave = (e: React.FormEvent) => {
    e.preventDefault();
    if (editingWidgetId) {
      // Edit mode
      const updated = widgets.map(w => {
        if (w.id === editingWidgetId) {
          return {
            ...w,
            title: formTitle || `${formDataType} - ${formWidgetType}`,
            dataSource: formDataSource,
            dataType: formDataType,
            experience: formExperience,
            widgetType: formWidgetType,
            metricName: formMetricName,
            agentId: formAgentId,
            logFacility: formLogFacility,
            logQuery: formLogQuery,
            alertSeverity: formAlertSeverity,
            alertStatus: formAlertStatus
          };
        }
        return w;
      });
      setWidgets(updated);
      if (autosave) saveToStorage(updated);
    } else {
      // Create mode
      // Find empty slot or append
      const maxRow = widgets.reduce((max, w) => Math.max(max, w.y + w.h), 0);
      const newWidget: Widget = {
        id: `widget-${Date.now()}`,
        x: 0,
        y: maxRow,
        w: formWidgetType === 'Gauge' || formWidgetType === 'Number' ? 4 : 6,
        h: 6,
        title: formTitle || `${formDataType} - ${formWidgetType}`,
        dataSource: formDataSource,
        dataType: formDataType,
        experience: formExperience,
        widgetType: formWidgetType,
        metricName: formMetricName,
        agentId: formAgentId,
        logFacility: formLogFacility,
        logQuery: formLogQuery,
        alertSeverity: formAlertSeverity,
        alertStatus: formAlertStatus
      };
      const updated = [...widgets, newWidget];
      setWidgets(updated);
      if (autosave) saveToStorage(updated);
    }
    setIsConfigModalOpen(false);
  };

  const handleResetLayout = () => {
    if (confirm('Reset dashboard to default CloudWatch widgets?')) {
      setWidgets(DEFAULT_WIDGETS);
      saveToStorage(DEFAULT_WIDGETS);
      setIsDropdownOpen(false);
    }
  };

  const handleClearAll = () => {
    if (confirm('Are you sure you want to clear all widgets?')) {
      setWidgets([]);
      saveToStorage([]);
      setIsDropdownOpen(false);
    }
  };

  // Drag handles
  const handleDragStart = (e: React.MouseEvent, widgetId: string) => {
    e.preventDefault();
    setActiveDragId(widgetId);
    setDragOffset({ x: 0, y: 0 });
    
    const widget = widgets.find(w => w.id === widgetId);
    if (!widget) return;
    
    setGhostCoords({ x: widget.x, y: widget.y, w: widget.w, h: widget.h });

    const rect = containerRef.current?.getBoundingClientRect();
    if (!rect) return;
    const colWidth = (rect.width - 24) / 12;
    const rowHeight = 52; // 40px height + 12px gap

    const startX = e.clientX;
    const startY = e.clientY;
    const initialX = widget.x;
    const initialY = widget.y;

    let lastGhostX = initialX;
    let lastGhostY = initialY;

    const onMouseMove = (moveEvent: MouseEvent) => {
      const deltaX = moveEvent.clientX - startX;
      const deltaY = moveEvent.clientY - startY;

      // Smooth absolute positioning of the dragged card
      setDragOffset({ x: deltaX, y: deltaY });

      // Target grid coordinates
      let newX = Math.round(initialX + deltaX / colWidth);
      let newY = Math.round(initialY + deltaY / rowHeight);

      // Bounds
      newX = Math.max(0, Math.min(12 - widget.w, newX));
      newY = Math.max(0, newY);

      if (newX !== lastGhostX || newY !== lastGhostY) {
        lastGhostX = newX;
        lastGhostY = newY;
        setGhostCoords({ x: newX, y: newY, w: widget.w, h: widget.h });
      }
    };

    const onMouseUp = () => {
      window.removeEventListener('mousemove', onMouseMove);
      window.removeEventListener('mouseup', onMouseUp);
      
      setWidgets(current => {
        const updated = current.map(w => w.id === widgetId ? { ...w, x: lastGhostX, y: lastGhostY } : w);
        const compacted = compactLayout(resolveCollisions(updated, widgetId));
        if (autosave) saveToStorage(compacted);
        return compacted;
      });

      setActiveDragId(null);
      setDragOffset(null);
      setGhostCoords(null);
    };

    window.addEventListener('mousemove', onMouseMove);
    window.addEventListener('mouseup', onMouseUp);
  };

  const handleResizeStart = (e: React.MouseEvent, widgetId: string) => {
    e.preventDefault();
    e.stopPropagation();
    setActiveResizeId(widgetId);
    const rect = containerRef.current?.getBoundingClientRect();
    if (!rect) return;
    const colWidth = (rect.width - 24) / 12;
    const rowHeight = 52; // 40px height + 12px gap

    const startX = e.clientX;
    const startY = e.clientY;
    const widget = widgets.find(w => w.id === widgetId);
    if (!widget) return;

    const initialW = widget.w;
    const initialH = widget.h;

    let lastW = initialW;
    let lastH = initialH;

    const onMouseMove = (moveEvent: MouseEvent) => {
      const deltaX = moveEvent.clientX - startX;
      const deltaY = moveEvent.clientY - startY;

      let newW = Math.round(initialW + deltaX / colWidth);
      let newH = Math.round(initialH + deltaY / rowHeight);

      // Bounds
      newW = Math.max(2, Math.min(12 - widget.x, newW));
      newH = Math.max(3, newH);

      if (newW !== lastW || newH !== lastH) {
        lastW = newW;
        lastH = newH;
        setWidgets(prev => {
          const mapped = prev.map(w => w.id === widgetId ? { ...w, w: newW, h: newH } : w);
          return resolveCollisions(mapped, widgetId);
        });
      }
    };

    const onMouseUp = () => {
      window.removeEventListener('mousemove', onMouseMove);
      window.removeEventListener('mouseup', onMouseUp);
      setActiveResizeId(null);
      
      setWidgets(current => {
        const compacted = compactLayout(current);
        if (autosave) saveToStorage(compacted);
        return compacted;
      });
    };

    window.addEventListener('mousemove', onMouseMove);
    window.addEventListener('mouseup', onMouseUp);
  };

  const displayWidgets = (() => {
    if (activeDragId && ghostCoords) {
      const temp = widgets.map(w => w.id === activeDragId ? { ...w, x: ghostCoords.x, y: ghostCoords.y } : w);
      return resolveCollisions(temp, activeDragId);
    }
    if (activeResizeId) {
      return resolveCollisions(widgets, activeResizeId);
    }
    return widgets;
  })();

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14, minWidth: 0, animation: 'fadeInUp 0.25s ease-out' }}>
      
      {/* CloudWatch Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span style={{ fontSize: '0.72rem', color: 'var(--text-3)', fontFamily: "'IBM Plex Mono', monospace" }}>AWS / CLOUDWATCH</span>
            <span style={{ fontSize: '0.65rem', background: 'rgba(235,133,0,0.15)', color: '#ff9900', border: '1px solid rgba(235,133,0,0.3)', padding: '1px 4px', borderRadius: 2 }}>{agents.length > 0 ? `${agents.length} Hosts` : 'Loading...'}</span>
          </div>
          <h1 className="page-title" style={{ fontSize: '1.25rem', marginTop: 3, display: 'flex', alignItems: 'center', gap: 8 }}>
            <Layout size={18} style={{ color: '#ff9900' }} /> Aegis SOC Dashboard
            <span style={{ fontSize: '0.8rem', color: 'var(--text-3)', fontWeight: 400 }}>· Dashboard</span>
          </h1>
        </div>

        {/* Buttons / Controls */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          
          {/* Autosave Status */}
          <div 
            onClick={handleToggleAutosave}
            style={{ 
              display: 'flex', alignItems: 'center', gap: 6, fontSize: '0.76rem', 
              color: 'var(--text-2)', background: 'var(--bg-surface)', border: '1px solid var(--border-1)', 
              padding: '4px 10px', borderRadius: 'var(--r-xs)', cursor: 'pointer', userSelect: 'none' 
            }}
          >
            <span>Autosave:</span>
            <strong style={{ color: autosave ? 'var(--low)' : 'var(--critical-dim)' }}>
              {autosave ? 'On' : 'Off'}
            </strong>
          </div>

          <button className="btn btn-outline" onClick={handleAddWidgetClick} style={{ height: 30, fontSize: '0.78rem', borderColor: 'var(--border-1)' }}>
            <Plus size={14} style={{ color: '#ff9900' }} /> Add widget
          </button>

          {/* Actions Dropdown */}
          <div style={{ position: 'relative' }}>
            <button className="btn btn-outline" onClick={() => setIsDropdownOpen(!isDropdownOpen)} style={{ height: 30, fontSize: '0.78rem', gap: 4 }}>
              Actions <ChevronDown size={12} />
            </button>
            {isDropdownOpen && (
              <>
                <div style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, zIndex: 90 }} onClick={() => setIsDropdownOpen(false)} />
                <div className="glass-panel" style={{ position: 'absolute', right: 0, top: 34, width: 180, zIndex: 100, padding: 6, display: 'flex', flexDirection: 'column', gap: 4 }}>
                  <button 
                    onClick={() => { setIsMetadataModalOpen(true); setIsDropdownOpen(false); }} 
                    style={{ background: 'transparent', border: 'none', color: 'var(--text-1)', fontSize: '0.78rem', padding: '6px 8px', textAlign: 'left', cursor: 'pointer', borderRadius: 4, width: '100%' }}
                    className="hover-card"
                  >
                    Dashboard metadata
                  </button>
                  <button 
                    onClick={handleResetLayout} 
                    style={{ background: 'transparent', border: 'none', color: 'var(--text-1)', fontSize: '0.78rem', padding: '6px 8px', textAlign: 'left', cursor: 'pointer', borderRadius: 4, width: '100%' }}
                    className="hover-card"
                  >
                    Reset default layout
                  </button>
                  <div style={{ height: 1, background: 'var(--border-0)', margin: '2px 0' }} />
                  <button 
                    onClick={handleClearAll} 
                    style={{ background: 'transparent', border: 'none', color: 'var(--critical-dim)', fontSize: '0.78rem', padding: '6px 8px', textAlign: 'left', cursor: 'pointer', borderRadius: 4, width: '100%' }}
                    className="hover-card"
                  >
                    Clear all widgets
                  </button>
                </div>
              </>
            )}
          </div>

          <button className="btn btn-primary" onClick={handleSaveDashboard} disabled={autosave} style={{ height: 30, fontSize: '0.78rem', background: '#ff9900', borderColor: '#ff9900' }}>
            Save dashboard
          </button>
        </div>
      </div>

      <div style={{ height: 1, background: 'var(--border-1)', width: '100%' }} />

      {/* Grid Canvas */}
      <div 
        ref={containerRef}
        style={{ 
          position: 'relative', 
          background: 'rgba(0, 0, 0, 0.15)',
          backgroundImage: (activeDragId || activeResizeId) 
            ? 'radial-gradient(rgba(255, 153, 0, 0.12) 1px, transparent 1px)' 
            : 'radial-gradient(rgba(255, 255, 255, 0.03) 1px, transparent 1px)',
          backgroundSize: (activeDragId || activeResizeId) 
            ? 'calc((100% - 11 * 12px) / 12 + 12px) 52px' 
            : '32px 32px',
          borderRadius: 'var(--r-md)',
          padding: 12,
          minHeight: 'calc(100vh - 160px)',
          height: Math.max(600, displayWidgets.reduce((max, w) => Math.max(max, Number(w.y) + Number(w.h)), 0) * 52 + 12 + 12),
          overflowY: 'auto',
          border: (activeDragId || activeResizeId) 
            ? '1px dashed rgba(255, 153, 0, 0.4)' 
            : '1px dashed var(--border-0)',
          transition: 'background-image 0.2s ease, border-color 0.2s ease, height 0.3s cubic-bezier(0.2, 0.8, 0.2, 1)'
        }}
      >
        {/* Ghost placeholder card showing snap coordinate while dragging */}
        {activeDragId && ghostCoords && (
          <div
            style={{
              position: 'absolute',
              left: `calc(${ghostCoords.x} * (100% - 11 * 12px) / 12 + ${ghostCoords.x} * 12px + 12px)`,
              top: `${ghostCoords.y * 52 + 12}px`,
              width: `calc(${ghostCoords.w} * (100% - 11 * 12px) / 12 + (${ghostCoords.w} - 1) * 12px)`,
              height: `${ghostCoords.h * 40 + (ghostCoords.h - 1) * 12}px`,
              border: '2px dashed rgba(255, 153, 0, 0.6)',
              background: 'rgba(255, 153, 0, 0.04)',
              borderRadius: 'var(--r-md)',
              zIndex: 5,
              pointerEvents: 'none',
              transition: 'left 0.15s cubic-bezier(0.2, 0.8, 0.2, 1), top 0.15s cubic-bezier(0.2, 0.8, 0.2, 1), width 0.15s cubic-bezier(0.2, 0.8, 0.2, 1), height 0.15s cubic-bezier(0.2, 0.8, 0.2, 1)'
            }}
          />
        )}

        {displayWidgets.map(w => {
          const isDragged = activeDragId === w.id;
          const isResized = activeResizeId === w.id;
          const original = widgets.find(x => x.id === w.id);

          const renderX = isDragged && original ? original.x : w.x;
          const renderY = isDragged && original ? original.y : w.y;
          const renderW = isDragged && original ? original.w : w.w;
          const renderH = isDragged && original ? original.h : w.h;

          return (
            <div
              key={w.id}
              style={{
                position: 'absolute',
                left: `calc(${renderX} * (100% - 11 * 12px) / 12 + ${renderX} * 12px + 12px)`,
                top: `${renderY * 52 + 12}px`,
                width: `calc(${renderW} * (100% - 11 * 12px) / 12 + (${renderW} - 1) * 12px)`,
                height: `${renderH * 40 + (renderH - 1) * 12}px`,
                display: 'flex',
                flexDirection: 'column',
                zIndex: (isDragged || isResized) ? 100 : 10,
                boxShadow: (isDragged || isResized) 
                  ? '0 12px 32px rgba(255, 153, 0, 0.2), 0 0 0 1px rgba(255, 153, 0, 0.4)' 
                  : '0 4px 12px rgba(0,0,0,0.1)',
                borderColor: (isDragged || isResized) 
                  ? 'rgba(255, 153, 0, 0.4)' 
                  : undefined,
                transform: (isDragged && dragOffset) ? `translate3d(${dragOffset.x}px, ${dragOffset.y}px, 0)` : undefined,
                opacity: isDragged ? 0.85 : 1,
                transition: (isDragged || isResized) 
                  ? 'none' 
                  : 'left 0.3s cubic-bezier(0.2, 0.8, 0.2, 1), top 0.3s cubic-bezier(0.2, 0.8, 0.2, 1), width 0.3s cubic-bezier(0.2, 0.8, 0.2, 1), height 0.3s cubic-bezier(0.2, 0.8, 0.2, 1), box-shadow 0.2s ease, border-color 0.2s ease',
                borderTop: '3px solid #ff9900' // orange accent bar for AWS style!
              }}
              className="glass-panel"
            >
            {/* Widget Header */}
            <div 
              style={{ 
                padding: '6px 10px', 
                background: 'rgba(255, 255, 255, 0.02)', 
                borderBottom: '1px solid var(--border-0)', 
                display: 'flex', 
                justifyContent: 'space-between', 
                alignItems: 'center',
                cursor: 'grab'
              }}
              onMouseDown={(e) => handleDragStart(e, w.id)}
            >
              <span style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-0)', textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap', maxWidth: '70%' }}>
                {w.title}
              </span>
              <div style={{ display: 'flex', gap: 6 }} onMouseDown={e => e.stopPropagation()}>
                <button 
                  onClick={() => handleEditWidgetClick(w)} 
                  style={{ background: 'transparent', border: 'none', color: 'var(--text-3)', cursor: 'pointer', padding: 2 }}
                  title="Configure"
                >
                  <Edit3 size={11} />
                </button>
                <button 
                  onClick={() => handleDeleteWidget(w.id)} 
                  style={{ background: 'transparent', border: 'none', color: 'var(--critical-dim)', cursor: 'pointer', padding: 2 }}
                  title="Remove"
                >
                  <Trash2 size={11} />
                </button>
              </div>
            </div>

            {/* Widget Body Content */}
            <div style={{ flex: 1, padding: 10, minHeight: 0, display: 'flex', flexDirection: 'column' }}>
              <WidgetContent widget={w} agents={agents} recentAlerts={recentAlerts} />
            </div>

            {/* Resize handle */}
            <div
              style={{
                position: 'absolute',
                right: 0,
                bottom: 0,
                width: 12,
                height: 12,
                cursor: 'se-resize',
                background: 'linear-gradient(135deg, transparent 50%, var(--text-3) 50%)',
                borderBottomRightRadius: 'inherit',
                opacity: 0.5
              }}
              onMouseDown={(e) => handleResizeStart(e, w.id)}
            />
          </div>
        );
      })}

        {widgets.length === 0 && (
          <div style={{ gridColumn: '1 / span 12', gridRow: '2 / span 4', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', color: 'var(--text-3)', gap: 8 }}>
            <Layout size={32} style={{ opacity: 0.3 }} />
            <span style={{ fontSize: '0.85rem' }}>No widgets on this dashboard yet.</span>
            <button className="btn btn-primary" onClick={handleAddWidgetClick} style={{ background: '#ff9900', borderColor: '#ff9900', fontSize: '0.78rem', marginTop: 4 }}>
              Add your first widget
            </button>
          </div>
        )}
      </div>

      {/* Widget Configuration Modal (Matches AWS CloudWatch "Add widget" style) */}
      {isConfigModalOpen && (
        <div style={{
          position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
          background: 'rgba(0,0,0,0.65)', backdropFilter: 'blur(4px)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          zIndex: 1000, padding: 16
        }}>
          <div 
            className="glass-panel" 
            style={{
              width: '100%', maxWidth: 780, maxHeight: '90vh', overflowY: 'auto',
              display: 'flex', flexDirection: 'column', 
              boxShadow: '0 24px 64px rgba(0,0,0,0.4)', borderColor: 'rgba(255, 255, 255, 0.08)'
            }}
          >
            {/* Modal Title */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '16px 20px', borderBottom: '1px solid var(--border-1)' }}>
              <h2 style={{ fontSize: '1rem', margin: 0, fontWeight: 600 }}>{editingWidgetId ? 'Edit widget' : 'Add widget'}</h2>
              <button 
                onClick={() => setIsConfigModalOpen(false)} 
                style={{ background: 'transparent', border: 'none', color: 'var(--text-3)', cursor: 'pointer' }}
              >
                <X size={16} />
              </button>
            </div>

            <form onSubmit={handleModalSave} style={{ display: 'flex', flexDirection: 'column', flex: 1 }}>
              {/* Form Content Split Layout */}
              <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 2fr', gap: 20, padding: 20 }}>
                
                {/* Left Side: Data sources types */}
                <div style={{ borderRight: '1px solid var(--border-0)', paddingRight: 20 }}>
                  <h3 style={{ fontSize: '0.82rem', color: 'var(--text-1)', marginBottom: 12 }}>Data sources types</h3>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                    <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: '0.78rem', cursor: 'pointer' }}>
                      <input type="radio" checked={formDataSource === 'CloudWatch'} onChange={() => setFormDataSource('CloudWatch')} name="ds_type" style={{ accentColor: '#ff9900' }} />
                      <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                        <span style={{ width: 12, height: 12, background: '#ff9900', borderRadius: 2 }} />
                        <strong>Cloudwatch</strong>
                      </div>
                    </label>
                    <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: '0.78rem', cursor: 'pointer', opacity: 0.5 }}>
                      <input type="radio" checked={formDataSource === 'Other'} onChange={() => setFormDataSource('Other')} name="ds_type" style={{ accentColor: '#ff9900' }} disabled />
                      <span>Other content types</span>
                    </label>
                    <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: '0.78rem', cursor: 'pointer', opacity: 0.5 }}>
                      <input type="radio" checked={formDataSource === 'Create'} onChange={() => setFormDataSource('Create')} name="ds_type" style={{ accentColor: '#ff9900' }} disabled />
                      <span>Create data sources</span>
                    </label>
                  </div>
                </div>

                {/* Right Side: Widget Configuration */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                  
                  {/* Widget Config Label */}
                  <div>
                    <h3 style={{ fontSize: '0.85rem', color: 'var(--text-1)', marginBottom: 10 }}>Widget Configuration</h3>
                    
                    {/* Data type tabs */}
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginBottom: 10 }}>
                      <span style={{ fontSize: '0.7rem', color: 'var(--text-3)', fontWeight: 600, letterSpacing: '0.04em' }}>DATA TYPE</span>
                      <div style={{ display: 'flex', gap: 6 }}>
                        {(['Metrics', 'Logs', 'Alarms'] as const).map(dt => (
                          <button
                            key={dt} type="button"
                            onClick={() => {
                              setFormDataType(dt);
                              if (dt === 'Logs') setFormWidgetType('Table');
                            }}
                            style={{
                              flex: 1, padding: '5px 8px', fontSize: '0.76rem', borderRadius: 4,
                              background: formDataType === dt ? 'rgba(235, 133, 0, 0.15)' : 'var(--bg-surface)',
                              color: formDataType === dt ? '#ff9900' : 'var(--text-2)',
                              border: formDataType === dt ? '1px solid #ff9900' : '1px solid var(--border-1)',
                              cursor: 'pointer', fontWeight: formDataType === dt ? 600 : 400
                            }}
                          >
                            {dt}
                          </button>
                        ))}
                      </div>
                    </div>

                    {/* Preferred experience tabs */}
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginBottom: 12 }}>
                      <span style={{ fontSize: '0.7rem', color: 'var(--text-3)', fontWeight: 600, letterSpacing: '0.04em' }}>PREFERRED EXPERIENCE</span>
                      <div style={{ display: 'flex', gap: 6 }}>
                        {(['Console', 'QueryStudio'] as const).map(exp => (
                          <button
                            key={exp} type="button"
                            onClick={() => setFormExperience(exp)}
                            style={{
                              flex: 1, padding: '4px 8px', fontSize: '0.72rem', borderRadius: 4,
                              background: formExperience === exp ? 'var(--border-1)' : 'transparent',
                              color: formExperience === exp ? 'var(--text-0)' : 'var(--text-3)',
                              border: '1px solid var(--border-1)',
                              cursor: 'pointer'
                            }}
                          >
                            {exp === 'Console' ? 'Metrics Console' : 'Query Studio'}
                          </button>
                        ))}
                      </div>
                    </div>
                  </div>

                  {/* Widget type grid selection */}
                  <div>
                    <span style={{ fontSize: '0.7rem', color: 'var(--text-3)', fontWeight: 600, letterSpacing: '0.04em', display: 'block', marginBottom: 6 }}>WIDGET TYPE</span>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                      
                      {/* Line Option */}
                      <div 
                        onClick={() => formDataType !== 'Logs' && setFormWidgetType('Line')}
                        style={{
                          border: formWidgetType === 'Line' ? '1px solid #ff9900' : '1px solid var(--border-1)',
                          background: formWidgetType === 'Line' ? 'rgba(235, 133, 0, 0.05)' : 'var(--bg-surface)',
                          borderRadius: 4, padding: 8, cursor: formDataType === 'Logs' ? 'not-allowed' : 'pointer', display: 'flex', gap: 8, alignItems: 'center',
                          opacity: formDataType === 'Logs' ? 0.35 : 1
                        }}
                      >
                        <input type="radio" checked={formWidgetType === 'Line'} onChange={() => {}} disabled={formDataType === 'Logs'} style={{ accentColor: '#ff9900' }} />
                        <div style={{ minWidth: 0 }}>
                          <strong style={{ fontSize: '0.78rem', display: 'block', color: 'var(--text-0)' }}>Line</strong>
                          <span style={{ fontSize: '0.62rem', color: 'var(--text-3)' }}>Compare metrics over time</span>
                        </div>
                      </div>

                      {/* Table Option */}
                      <div 
                        onClick={() => setFormWidgetType('Table')}
                        style={{
                          border: formWidgetType === 'Table' ? '1px solid #ff9900' : '1px solid var(--border-1)',
                          background: formWidgetType === 'Table' ? 'rgba(235, 133, 0, 0.05)' : 'var(--bg-surface)',
                          borderRadius: 4, padding: 8, cursor: 'pointer', display: 'flex', gap: 8, alignItems: 'center'
                        }}
                      >
                        <input type="radio" checked={formWidgetType === 'Table'} onChange={() => {}} style={{ accentColor: '#ff9900' }} />
                        <div style={{ minWidth: 0 }}>
                          <strong style={{ fontSize: '0.78rem', display: 'block', color: 'var(--text-0)' }}>Data table</strong>
                          <span style={{ fontSize: '0.62rem', color: 'var(--text-3)' }}>Compare values in a table</span>
                        </div>
                      </div>

                      {/* Number Option */}
                      <div 
                        onClick={() => formDataType !== 'Logs' && setFormWidgetType('Number')}
                        style={{
                          border: formWidgetType === 'Number' ? '1px solid #ff9900' : '1px solid var(--border-1)',
                          background: formWidgetType === 'Number' ? 'rgba(235, 133, 0, 0.05)' : 'var(--bg-surface)',
                          borderRadius: 4, padding: 8, cursor: formDataType === 'Logs' ? 'not-allowed' : 'pointer', display: 'flex', gap: 8, alignItems: 'center',
                          opacity: formDataType === 'Logs' ? 0.35 : 1
                        }}
                      >
                        <input type="radio" checked={formWidgetType === 'Number'} onChange={() => {}} disabled={formDataType === 'Logs'} style={{ accentColor: '#ff9900' }} />
                        <div style={{ minWidth: 0 }}>
                          <strong style={{ fontSize: '0.78rem', display: 'block', color: 'var(--text-0)' }}>Number</strong>
                          <span style={{ fontSize: '0.62rem', color: 'var(--text-3)' }}>Instantly see latest value</span>
                        </div>
                      </div>

                      {/* Gauge Option */}
                      <div 
                        onClick={() => formDataType !== 'Logs' && setFormWidgetType('Gauge')}
                        style={{
                          border: formWidgetType === 'Gauge' ? '1px solid #ff9900' : '1px solid var(--border-1)',
                          background: formWidgetType === 'Gauge' ? 'rgba(235, 133, 0, 0.05)' : 'var(--bg-surface)',
                          borderRadius: 4, padding: 8, cursor: formDataType === 'Logs' ? 'not-allowed' : 'pointer', display: 'flex', gap: 8, alignItems: 'center',
                          opacity: formDataType === 'Logs' ? 0.35 : 1
                        }}
                      >
                        <input type="radio" checked={formWidgetType === 'Gauge'} onChange={() => {}} disabled={formDataType === 'Logs'} style={{ accentColor: '#ff9900' }} />
                        <div style={{ minWidth: 0 }}>
                          <strong style={{ fontSize: '0.78rem', display: 'block', color: 'var(--text-0)' }}>Gauge</strong>
                          <span style={{ fontSize: '0.62rem', color: 'var(--text-3)' }}>Metric within a range</span>
                        </div>
                      </div>

                    </div>
                  </div>

                </div>
              </div>

              <div style={{ height: 1, background: 'var(--border-0)' }} />

              {/* Dynamic Details Inputs */}
              <div style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 12 }}>
                <h3 style={{ fontSize: '0.82rem', color: 'var(--text-1)', margin: 0 }}>Widget Configuration Details</h3>
                
                {/* Title */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  <label style={{ fontSize: '0.72rem', color: 'var(--text-3)', fontWeight: 600 }}>WIDGET TITLE</label>
                  <input 
                    type="text" value={formTitle} onChange={e => setFormTitle(e.target.value)} 
                    placeholder="e.g. Host CPU Usage" className="search-input" 
                    style={{ background: 'var(--bg-surface)', border: '1px solid var(--border-1)', width: '100%', fontSize: '0.8rem', padding: '6px 10px' }}
                  />
                </div>

                {/* METRICS specific configs */}
                {formDataType === 'Metrics' && (
                  <div style={{ display: 'grid', gridTemplateColumns: ['system_status', 'active_alerts', 'critical_alerts', 'high_alerts', 'medium_alerts', 'low_alerts', 'mitre_coverage', 'agent_count'].includes(formMetricName) ? '1fr' : '1fr 1fr', gap: 12 }}>
                    {!['system_status', 'active_alerts', 'critical_alerts', 'high_alerts', 'medium_alerts', 'low_alerts', 'mitre_coverage', 'agent_count'].includes(formMetricName) && (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                        <label style={{ fontSize: '0.72rem', color: 'var(--text-3)', fontWeight: 600 }}>TARGET HOST</label>
                        <select 
                          value={formAgentId} onChange={e => setFormAgentId(e.target.value)} 
                          className="select-input" style={{ width: '100%', background: 'var(--bg-surface)', border: '1px solid var(--border-1)', fontSize: '0.8rem' }}
                        >
                          {agents.map(a => <option key={a.id} value={a.id}>{a.name} ({a.ip})</option>)}
                        </select>
                      </div>
                    )}
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                      <label style={{ fontSize: '0.72rem', color: 'var(--text-3)', fontWeight: 600 }}>METRIC NAME</label>
                      <select 
                        value={formMetricName} onChange={e => setFormMetricName(e.target.value)} 
                        className="select-input" style={{ width: '100%', background: 'var(--bg-surface)', border: '1px solid var(--border-1)', fontSize: '0.8rem' }}
                      >
                        <option value="cpu">CPU Utilization (%)</option>
                        <option value="ram">RAM Usage (%)</option>
                        <option value="disk">Disk Usage (%)</option>
                        <option value="threat">Threat Score</option>
                        <option value="network">Network Traffic (Mbps)</option>
                        <option value="system_status">System Status (Safe/Alerting)</option>
                        <option value="active_alerts">Active Alerts Count</option>
                        <option value="critical_alerts">Critical Alerts Count</option>
                        <option value="high_alerts">High Alerts Count</option>
                        <option value="medium_alerts">Medium Alerts Count</option>
                        <option value="low_alerts">Low Alerts Count</option>
                        <option value="mitre_coverage">MITRE Techniques Covered</option>
                        <option value="agent_count">Online Agents Count</option>
                      </select>
                    </div>
                  </div>
                )}

                {/* LOGS specific configs */}
                {formDataType === 'Logs' && (
                  <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 2fr', gap: 12 }}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                      <label style={{ fontSize: '0.72rem', color: 'var(--text-3)', fontWeight: 600 }}>LOG FACILITY</label>
                      <select 
                        value={formLogFacility} onChange={e => setFormLogFacility(e.target.value)} 
                        className="select-input" style={{ width: '100%', background: 'var(--bg-surface)', border: '1px solid var(--border-1)', fontSize: '0.8rem' }}
                      >
                        <option value="all">All Facilities</option>
                        <option value="web">Web Access Logs</option>
                        <option value="auth">Authentication Logs</option>
                        <option value="syslog">Syslog system events</option>
                        <option value="daemon">Background daemons</option>
                      </select>
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                      <label style={{ fontSize: '0.72rem', color: 'var(--text-3)', fontWeight: 600 }}>QUERY FILTER STRING</label>
                      <input 
                        type="text" value={formLogQuery} onChange={e => setFormLogQuery(e.target.value)} 
                        placeholder="e.g. error, failed login, critical" className="search-input" 
                        style={{ background: 'var(--bg-surface)', border: '1px solid var(--border-1)', width: '100%', fontSize: '0.8rem', padding: '6px 10px' }}
                      />
                    </div>
                  </div>
                )}

                {/* ALARMS specific configs */}
                {formDataType === 'Alarms' && (
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                      <label style={{ fontSize: '0.72rem', color: 'var(--text-3)', fontWeight: 600 }}>ALARM SEVERITY</label>
                      <select 
                        value={formAlertSeverity} onChange={e => setFormAlertSeverity(e.target.value)} 
                        className="select-input" style={{ width: '100%', background: 'var(--bg-surface)', border: '1px solid var(--border-1)', fontSize: '0.8rem' }}
                      >
                        <option value="all">All Severities</option>
                        <option value="critical">Critical</option>
                        <option value="high">High</option>
                        <option value="medium">Medium</option>
                        <option value="low">Low</option>
                      </select>
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                      <label style={{ fontSize: '0.72rem', color: 'var(--text-3)', fontWeight: 600 }}>ALARM STATUS</label>
                      <select 
                        value={formAlertStatus} onChange={e => setFormAlertStatus(e.target.value)} 
                        className="select-input" style={{ width: '100%', background: 'var(--bg-surface)', border: '1px solid var(--border-1)', fontSize: '0.8rem' }}
                      >
                        <option value="all">All States</option>
                        <option value="open">Open (Active)</option>
                        <option value="investigating">Investigating</option>
                        <option value="resolved">Resolved</option>
                      </select>
                    </div>
                  </div>
                )}

              </div>

              {/* Modal Footer */}
              <div style={{ padding: '12px 20px', borderTop: '1px solid var(--border-1)', display: 'flex', justifyContent: 'flex-end', gap: 8, background: 'rgba(0,0,0,0.1)' }}>
                <button type="button" className="btn btn-outline" onClick={() => setIsConfigModalOpen(false)} style={{ fontSize: '0.8rem' }}>
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary" style={{ background: '#ff9900', borderColor: '#ff9900', color: 'white', fontWeight: 600, fontSize: '0.8rem' }}>
                  {editingWidgetId ? 'Update widget' : 'Create widget'}
                </button>
              </div>

            </form>
          </div>
        </div>
      )}

      {/* Real-time Dashboard Metadata Modal */}
      {isMetadataModalOpen && (
        <div style={{
          position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
          background: 'rgba(0,0,0,0.65)', backdropFilter: 'blur(4px)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          zIndex: 1000, padding: 16
        }}>
          <div 
            className="glass-panel" 
            style={{
              width: '100%', maxWidth: 540,
              display: 'flex', flexDirection: 'column', 
              boxShadow: '0 24px 64px rgba(0,0,0,0.4)', borderColor: 'rgba(255, 255, 255, 0.08)'
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '16px 20px', borderBottom: '1px solid var(--border-1)' }}>
              <h2 style={{ fontSize: '1rem', margin: 0, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 8 }}>
                <Layout size={16} style={{ color: '#ff9900' }} /> Aegis SOC Dashboard Metadata
              </h2>
              <button onClick={() => setIsMetadataModalOpen(false)} style={{ background: 'transparent', border: 'none', color: 'var(--text-3)', cursor: 'pointer' }}>
                <X size={16} />
              </button>
            </div>

            <div style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 12, fontSize: '0.8rem' }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                <div style={{ padding: 12, background: 'var(--bg-surface)', border: '1px solid var(--border-1)', borderRadius: 6 }}>
                  <span style={{ fontSize: '0.68rem', color: 'var(--text-3)', display: 'block' }}>TOTAL MONITORED HOSTS</span>
                  <strong style={{ fontSize: '1.2rem', color: 'var(--accent)' }}>{agents.length} Hosts</strong>
                </div>
                <div style={{ padding: 12, background: 'var(--bg-surface)', border: '1px solid var(--border-1)', borderRadius: 6 }}>
                  <span style={{ fontSize: '0.68rem', color: 'var(--text-3)', display: 'block' }}>ACTIVE INCIDENT ALARMS</span>
                  <strong style={{ fontSize: '1.2rem', color: recentAlerts.filter(a => a.status !== 'resolved').length > 0 ? 'var(--critical)' : 'var(--low)' }}>
                    {recentAlerts.filter(a => a.status !== 'resolved').length} Open
                  </strong>
                </div>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: 6, background: 'rgba(0,0,0,0.15)', padding: 12, borderRadius: 6, border: '1px solid var(--border-0)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--text-3)' }}>Critical Severity:</span>
                  <span style={{ fontWeight: 600, color: 'var(--critical)' }}>{recentAlerts.filter(a => a.severity === 'critical' && a.status !== 'resolved').length}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--text-3)' }}>High Severity:</span>
                  <span style={{ fontWeight: 600, color: 'var(--high)' }}>{recentAlerts.filter(a => a.severity === 'high' && a.status !== 'resolved').length}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--text-3)' }}>Medium Severity:</span>
                  <span style={{ fontWeight: 600, color: 'var(--medium)' }}>{recentAlerts.filter(a => a.severity === 'medium' && a.status !== 'resolved').length}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--text-3)' }}>Low Severity:</span>
                  <span style={{ fontWeight: 600, color: 'var(--low)' }}>{recentAlerts.filter(a => a.severity === 'low' && a.status !== 'resolved').length}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', borderTop: '1px solid var(--border-0)', paddingTop: 6, marginTop: 2 }}>
                  <span style={{ color: 'var(--text-3)' }}>MITRE Techniques Covered:</span>
                  <span style={{ fontWeight: 600, color: 'var(--purple)' }}>{new Set(recentAlerts.map(a => a.mitreTechnique).filter(Boolean)).size}</span>
                </div>
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.72rem', color: 'var(--text-3)', fontFamily: "'IBM Plex Mono', monospace" }}>
                <span>Telemetry Ingestion: Live WebSocket / SWR</span>
                <span style={{ color: 'var(--low)', fontWeight: 600 }}>● Active</span>
              </div>
            </div>

            <div style={{ padding: '12px 20px', borderTop: '1px solid var(--border-1)', display: 'flex', justifyContent: 'flex-end', background: 'rgba(0,0,0,0.1)' }}>
              <button className="btn btn-outline" onClick={() => setIsMetadataModalOpen(false)} style={{ fontSize: '0.8rem' }}>
                Close
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}

/* WIDGET CONTENT RENDERING ENGINE */
interface ContentProps {
  widget: Widget;
  agents: Agent[];
  recentAlerts: Alert[];
}

function WidgetContent({ widget, agents, recentAlerts }: ContentProps) {
  const [loading, setLoading] = useState(false);
  const [logData, setLogData] = useState<any[]>([]);
  const [metricHistory, setMetricHistory] = useState<number[]>([]);

  const targetAgent = widget.agentId ? agents.find(a => a.id === widget.agentId) : agents[0];

  // Generate a mock metric history series based on current real-time agent metrics or system metrics
  useEffect(() => {
    if (widget.dataType === 'Metrics') {
      let currentVal = 0;
      const isSystemMetric = ['system_status', 'active_alerts', 'critical_alerts', 'high_alerts', 'medium_alerts', 'low_alerts', 'mitre_coverage', 'agent_count'].includes(widget.metricName || '');

      if (isSystemMetric) {
        if (widget.metricName === 'system_status') {
          const hasAlertingAgent = agents.some(a => a.status === 'alerting');
          const hasOpenCriticalAlert = recentAlerts.some(a => a.severity === 'critical' && a.status !== 'resolved');
          currentVal = (hasAlertingAgent || hasOpenCriticalAlert) ? 0 : 1;
        } else if (widget.metricName === 'active_alerts') {
          currentVal = recentAlerts.filter(a => a.status !== 'resolved').length;
        } else if (widget.metricName === 'critical_alerts') {
          currentVal = recentAlerts.filter(a => a.status !== 'resolved' && a.severity === 'critical').length;
        } else if (widget.metricName === 'high_alerts') {
          currentVal = recentAlerts.filter(a => a.status !== 'resolved' && a.severity === 'high').length;
        } else if (widget.metricName === 'medium_alerts') {
          currentVal = recentAlerts.filter(a => a.status !== 'resolved' && a.severity === 'medium').length;
        } else if (widget.metricName === 'low_alerts') {
          currentVal = recentAlerts.filter(a => a.status !== 'resolved' && a.severity === 'low').length;
        } else if (widget.metricName === 'mitre_coverage') {
          currentVal = new Set(recentAlerts.map(a => a.mitreTechnique).filter(Boolean)).size;
        } else if (widget.metricName === 'agent_count') {
          currentVal = agents.filter(a => a.status === 'active' || a.status === 'alerting').length;
        }
      } else if (targetAgent) {
        if (widget.metricName === 'cpu') currentVal = targetAgent.cpuUsage;
        else if (widget.metricName === 'ram') currentVal = targetAgent.ramUsage;
        else if (widget.metricName === 'disk') currentVal = targetAgent.diskUsage;
        else if (widget.metricName === 'threat') currentVal = targetAgent.threatScore;
        else if (widget.metricName === 'network') currentVal = (targetAgent.networkIn + targetAgent.networkOut);
      } else {
        return;
      }

      setMetricHistory(prev => {
        if (prev.length === 0) {
          // Initialize history buffer with current real value across initial window
          return Array(12).fill(Math.round(currentVal));
        }
        // Append the latest real-time metric sample and maintain a 12-point sliding window
        const nextHistory = [...prev, Math.round(currentVal)];
        if (nextHistory.length > 12) {
          return nextHistory.slice(nextHistory.length - 12);
        }
        return nextHistory;
      });
    }
  }, [widget.agentId, widget.metricName, targetAgent?.cpuUsage, targetAgent?.ramUsage, targetAgent?.diskUsage, targetAgent?.threatScore, targetAgent?.networkIn, targetAgent?.networkOut, agents, recentAlerts]);

  // Fetch real-time log data if type is Logs
  useEffect(() => {
    if (widget.dataType === 'Logs') {
      const fetchLogs = async () => {
        setLoading(true);
        try {
          const facilityQuery = widget.logFacility && widget.logFacility !== 'all' ? `&facility=${widget.logFacility}` : '';
          const searchQuery = widget.logQuery ? `&q=${encodeURIComponent(widget.logQuery)}` : '';
          const r = await fetch(`/api/logs?limit=25${facilityQuery}${searchQuery}`);
          if (r.ok) {
            const data = await r.json();
            setLogData(data.logs || []);
          }
        } catch (e) {
          console.error(e);
        } finally {
          setLoading(false);
        }
      };

      fetchLogs();
      const interval = setInterval(fetchLogs, 5000);
      return () => clearInterval(interval);
    }
  }, [widget.logFacility, widget.logQuery]);

  // RENDER ALARMS (ALERTS)
  if (widget.dataType === 'Alarms') {
    const filteredAlarms = recentAlerts.filter(a => {
      if (widget.alertSeverity && widget.alertSeverity !== 'all' && a.severity !== widget.alertSeverity) return false;
      if (widget.alertStatus && widget.alertStatus !== 'all' && a.status !== widget.alertStatus) return false;
      return true;
    });

    if (widget.widgetType === 'Table') {
      return (
        <div style={{ flex: 1, overflowY: 'auto', maxHeight: '100%', fontSize: '0.76rem' }}>
          <table className="sec-table" style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ position: 'sticky', top: 0, background: 'var(--bg-surface)' }}>
                <th>Time</th>
                <th>Severity</th>
                <th>Host</th>
                <th>Title</th>
              </tr>
            </thead>
            <tbody>
              {filteredAlarms.slice(0, 15).map(a => {
                const isCritical = a.severity === 'critical' || a.severity === 'high';
                return (
                  <tr 
                    key={a.id} 
                    style={{ 
                      background: isCritical ? 'rgba(239, 68, 68, 0.06)' : undefined,
                      borderLeft: isCritical ? '3px solid var(--critical)' : undefined
                    }}
                  >
                    <td style={{ color: 'var(--text-3)', fontFamily: "'IBM Plex Mono', monospace" }}>
                      {new Date(a.timestamp).toLocaleTimeString('en-US', { hour12: false })}
                    </td>
                    <td>
                      <span className={`badge badge-${a.severity}`} style={{ fontSize: '0.62rem', padding: '1px 4px' }}>
                        {a.severity}
                      </span>
                    </td>
                    <td style={{ fontWeight: 500 }}>{a.agentName}</td>
                    <td title={a.description} style={{ color: isCritical ? 'var(--text-0)' : 'var(--text-2)' }}>{a.title}</td>
                  </tr>
                );
              })}
              {filteredAlarms.length === 0 && (
                <tr>
                  <td colSpan={4} style={{ textAlign: 'center', padding: '20px 0', color: 'var(--text-3)' }}>
                    No active alarms in this state.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      );
    }

    // Default alarm display is number
    const openAlarmCount = filteredAlarms.filter(a => a.status !== 'resolved').length;
    return (
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', position: 'relative' }}>
        <span style={{ fontSize: '3rem', fontWeight: 700, color: openAlarmCount > 0 ? 'var(--critical)' : 'var(--low)', textShadow: '0 0 10px rgba(0,0,0,0.3)' }}>
          {openAlarmCount}
        </span>
        <span style={{ fontSize: '0.72rem', color: 'var(--text-3)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
          Active SOC Alarms
        </span>
      </div>
    );
  }

  // RENDER LOGS
  if (widget.dataType === 'Logs') {
    if (loading && logData.length === 0) {
      return (
        <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-3)' }}>
          <RefreshCw size={18} className="spin" />
        </div>
      );
    }

    return (
      <div style={{ flex: 1, overflowY: 'auto', maxHeight: '100%', fontSize: '0.74rem' }}>
        <table className="sec-table" style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ position: 'sticky', top: 0, background: 'var(--bg-surface)' }}>
              <th>Time</th>
              <th>Host</th>
              <th>Facility</th>
              <th>Log Message</th>
            </tr>
          </thead>
          <tbody>
            {logData.slice(0, 15).map(l => {
              const msgLower = l.message.toLowerCase();
              const isAlert = msgLower.includes('fail') || msgLower.includes('err') || msgLower.includes('denied') || msgLower.includes('block') || msgLower.includes('alert') || msgLower.includes('warn');
              return (
                <tr 
                  key={l.id} 
                  style={{ 
                    background: isAlert ? 'rgba(245, 158, 11, 0.05)' : undefined,
                    borderLeft: isAlert ? '3px solid var(--warning)' : undefined
                  }}
                >
                  <td style={{ color: 'var(--text-3)', fontFamily: "'IBM Plex Mono', monospace", whiteSpace: 'nowrap' }}>
                    {new Date(l.timestamp).toLocaleTimeString('en-US', { hour12: false })}
                  </td>
                  <td style={{ fontWeight: 500, whiteSpace: 'nowrap' }}>{l.agentName}</td>
                  <td>
                    <span className="badge badge-neutral" style={{ fontSize: '0.58rem', padding: '1px 3px' }}>
                      {l.facility}
                    </span>
                  </td>
                  <td style={{ fontFamily: "'IBM Plex Mono', monospace", color: isAlert ? 'var(--text-0)' : 'var(--text-2)', fontSize: '0.72rem' }}>
                    {l.message}
                  </td>
                </tr>
              );
            })}
            {logData.length === 0 && (
              <tr>
                <td colSpan={4} style={{ textAlign: 'center', padding: '20px 0', color: 'var(--text-3)' }}>
                  No logs found matching criteria.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    );
  }

  // RENDER METRICS
  if (widget.dataType === 'Metrics') {
    const isSystemMetric = ['system_status', 'active_alerts', 'critical_alerts', 'high_alerts', 'medium_alerts', 'low_alerts', 'mitre_coverage', 'agent_count'].includes(widget.metricName || '');

    if (!targetAgent && !isSystemMetric) {
      return (
        <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-3)', fontSize: '0.8rem' }}>
          No host selected or active.
        </div>
      );
    }

    let metricValue: number | string = 0;
    let suffix = '%';
    let color = 'var(--accent)';

    if (isSystemMetric) {
      if (widget.metricName === 'system_status') {
        const hasAlertingAgent = agents.some(a => a.status === 'alerting');
        const hasOpenCriticalAlert = recentAlerts.some(a => a.severity === 'critical' && a.status !== 'resolved');
        const isSafe = !(hasAlertingAgent || hasOpenCriticalAlert);
        metricValue = isSafe ? 'SAFE' : 'ALERTING';
        suffix = '';
        color = isSafe ? 'var(--low)' : 'var(--critical)';
      } else if (widget.metricName === 'active_alerts') {
        const count = recentAlerts.filter(a => a.status !== 'resolved').length;
        metricValue = count;
        suffix = '';
        color = count > 0 ? 'var(--critical)' : 'var(--low)';
      } else if (widget.metricName === 'critical_alerts') {
        const count = recentAlerts.filter(a => a.status !== 'resolved' && a.severity === 'critical').length;
        metricValue = count;
        suffix = '';
        color = count > 0 ? 'var(--critical)' : 'var(--low)';
      } else if (widget.metricName === 'high_alerts') {
        const count = recentAlerts.filter(a => a.status !== 'resolved' && a.severity === 'high').length;
        metricValue = count;
        suffix = '';
        color = 'var(--high)';
      } else if (widget.metricName === 'medium_alerts') {
        const count = recentAlerts.filter(a => a.status !== 'resolved' && a.severity === 'medium').length;
        metricValue = count;
        suffix = '';
        color = 'var(--medium)';
      } else if (widget.metricName === 'low_alerts') {
        const count = recentAlerts.filter(a => a.status !== 'resolved' && a.severity === 'low').length;
        metricValue = count;
        suffix = '';
        color = 'var(--low)';
      } else if (widget.metricName === 'mitre_coverage') {
        const count = new Set(recentAlerts.map(a => a.mitreTechnique).filter(Boolean)).size;
        metricValue = count;
        suffix = ' Techs';
        color = 'var(--purple)';
      } else if (widget.metricName === 'agent_count') {
        metricValue = agents.filter(a => a.status === 'active' || a.status === 'alerting').length;
        suffix = ` / ${agents.length}`;
        color = 'var(--accent)';
      }
    } else if (targetAgent) {
      if (widget.metricName === 'cpu') {
        metricValue = targetAgent.cpuUsage;
        color = 'var(--info)';
      } else if (widget.metricName === 'ram') {
        metricValue = targetAgent.ramUsage;
        color = 'var(--purple)';
      } else if (widget.metricName === 'disk') {
        metricValue = targetAgent.diskUsage;
        color = '#38bdf8';
      } else if (widget.metricName === 'threat') {
        metricValue = targetAgent.threatScore;
        suffix = '/100';
        color = metricValue > 70 ? 'var(--critical)' : metricValue > 40 ? 'var(--high)' : 'var(--low)';
      } else if (widget.metricName === 'network') {
        metricValue = Math.round(targetAgent.networkIn + targetAgent.networkOut);
        suffix = ' Mbps';
        color = '#10b981';
      }
    }

    // Number Style Widget
    if (widget.widgetType === 'Number') {
      return (
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
          <div style={{ fontSize: metricValue === 'ALERTING' ? '2.2rem' : '3rem', fontWeight: 700, color, textShadow: `0 0 15px ${color}1a` }}>
            {metricValue}{suffix}
          </div>
          <div style={{ fontSize: '0.72rem', color: 'var(--text-3)', textTransform: 'uppercase', letterSpacing: '0.04em', marginTop: 4 }}>
            {isSystemMetric ? widget.title : `Latest ${widget.metricName?.toUpperCase()}`}
          </div>
        </div>
      );
    }

    // Gauge Style Widget
    if (widget.widgetType === 'Gauge') {
      let percent = typeof metricValue === 'number' ? metricValue : (metricValue === 'SAFE' ? 100 : 0);
      const needleRotation = -90 + (percent / 100) * 180;
      return (
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', position: 'relative' }}>
          <svg width="130" height="75" viewBox="0 0 100 60" style={{ overflow: 'visible' }}>
            {/* Background semi-circles zones */}
            <path d="M 10 50 A 40 40 0 0 1 36.6 20" fill="none" stroke="#10b981" strokeWidth="6" opacity="0.25" strokeLinecap="round" />
            <path d="M 36.6 20 A 40 40 0 0 1 63.3 20" fill="none" stroke="#f59e0b" strokeWidth="6" opacity="0.25" />
            <path d="M 63.3 20 A 40 40 0 0 1 90 50" fill="none" stroke="#ef4444" strokeWidth="6" opacity="0.25" strokeLinecap="round" />
            
            {/* Filled value semi-circle */}
            <path 
              d="M 10 50 A 40 40 0 0 1 90 50" 
              fill="none" 
              stroke={color} 
              strokeWidth="6" 
              strokeLinecap="round" 
              strokeDasharray="126" 
              strokeDashoffset={126 - (percent / 100) * 126}
              style={{ transition: 'stroke-dashoffset 0.8s ease-out' }}
            />
            
            {/* Needle pointer */}
            <g transform={`rotate(${needleRotation}, 50, 50)`}>
              <polygon 
                points="49,50 51,50 50,16" 
                fill="#ef4444" 
              />
            </g>
            {/* Center Cap */}
            <circle cx="50" cy="50" r="3.5" fill="var(--text-0)" />

            {/* Min / Max Labels */}
            <text x="8" y="58" textAnchor="middle" fill="var(--text-3)" fontSize="5">0</text>
            <text x="92" y="58" textAnchor="middle" fill="var(--text-3)" fontSize="5">100</text>

            {/* Value text in middle */}
            <text x="50" y="44" textAnchor="middle" fill="var(--text-0)" fontSize="12" fontWeight="bold">
              {metricValue}{suffix}
            </text>
            <text x="50" y="55" textAnchor="middle" fill="var(--text-3)" fontSize="5" fontWeight="700" letterSpacing="0.04em">
              {widget.metricName?.toUpperCase()}
            </text>
          </svg>
        </div>
      );
    }

    // Default Line chart style
    if (metricHistory.length > 0) {
      const minVal = Math.min(...metricHistory);
      const maxVal = Math.max(...metricHistory, 10);
      const avgVal = Math.round(metricHistory.reduce((s, x) => s + x, 0) / metricHistory.length);

      const points = metricHistory.map((val, idx) => {
        const x = 10 + (idx * (180 / 11));
        const y = 70 - (val / maxVal) * 55; // margin offset
        return { x, y };
      });
      
      // Compute smooth cubic Bezier path
      let bezierPath = '';
      if (points.length > 0) {
        bezierPath = `M ${points[0].x} ${points[0].y}`;
        for (let i = 0; i < points.length - 1; i++) {
          const p0 = points[i];
          const p1 = points[i + 1];
          const cpX1 = p0.x + (p1.x - p0.x) / 2;
          const cpY1 = p0.y;
          const cpX2 = p0.x + (p1.x - p0.x) / 2;
          const cpY2 = p1.y;
          bezierPath += ` C ${cpX1} ${cpY1}, ${cpX2} ${cpY2}, ${p1.x} ${p1.y}`;
        }
      }

      const bezierAreaPath = bezierPath ? `${bezierPath} L ${points[points.length - 1].x} 80 L ${points[0].x} 80 Z` : '';

      return (
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0 }}>
          <div style={{ flex: 1, position: 'relative' }}>
            <svg width="100%" height="100%" viewBox="0 0 200 90" preserveAspectRatio="none">
              <defs>
                <linearGradient id={`gradient-${widget.id}`} x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={color} stopOpacity="0.25" />
                  <stop offset="100%" stopColor={color} stopOpacity="0" />
                </linearGradient>
              </defs>
              <line x1="0" y1="20" x2="200" y2="20" stroke="rgba(255,255,255,0.03)" strokeWidth="0.5" />
              <line x1="0" y1="50" x2="200" y2="50" stroke="rgba(255,255,255,0.03)" strokeWidth="0.5" />
              <line x1="0" y1="80" x2="200" y2="80" stroke="rgba(255,255,255,0.03)" strokeWidth="0.5" />
              {bezierPath && (
                <>
                  <path d={bezierPath} fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                  <path d={bezierAreaPath} fill={`url(#gradient-${widget.id})`} />
                </>
              )}
              {points.map((p, idx) => (
                <circle 
                  key={idx} cx={p.x} cy={p.y} r="2" fill={color} 
                  style={{ cursor: 'pointer' }}
                >
                  <title>{`Val: ${metricHistory[idx]}${suffix}`}</title>
                </circle>
              ))}
            </svg>
          </div>
          {/* Detailed Min / Max / Avg summary row */}
          <div style={{ display: 'flex', justifyContent: 'space-around', fontSize: '0.66rem', color: 'var(--text-3)', borderTop: '1px solid var(--border-0)', paddingTop: 6, marginTop: 4 }}>
            <span>Min: <strong style={{ color: 'var(--text-1)' }}>{minVal}{suffix}</strong></span>
            <span>Max: <strong style={{ color: 'var(--text-1)' }}>{maxVal}{suffix}</strong></span>
            <span>Avg: <strong style={{ color: 'var(--text-1)' }}>{avgVal}{suffix}</strong></span>
          </div>
        </div>
      );
    }
  }

  return (
    <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-3)' }}>
      No widget type matches selection
    </div>
  );
}
