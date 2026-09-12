import React, { useState } from 'react';

// Common Chart Interfaces
interface DataPoint {
  label: string;
  value: number;
  [key: string]: any;
}

// ----------------------------------------------------
// 1. AREA CHART Component
// ----------------------------------------------------
interface AreaChartProps {
  data: DataPoint[];
  height?: number;
  color?: string;
  fillColor?: string;
  gridLines?: boolean;
}

export const AreaChart: React.FC<AreaChartProps> = ({
  data,
  height = 200,
  color = 'hsl(var(--accent-color))',
  fillColor = 'hsl(var(--accent-color) / 0.15)',
  gridLines = true
}) => {
  const [hoveredIdx, setHoveredIdx] = useState<number | null>(null);
  
  if (data.length === 0) return null;

  const padding = { top: 20, right: 20, bottom: 30, left: 40 };
  const width = 500;
  const chartWidth = width - padding.left - padding.right;
  const chartHeight = height - padding.top - padding.bottom;

  const maxVal = Math.max(...data.map(d => d.value), 10);
  const minVal = 0;
  const valRange = maxVal - minVal;

  // Map data points to SVG coordinates
  const points = data.map((d, index) => {
    const x = padding.left + (index / (data.length - 1)) * chartWidth;
    const y = padding.top + chartHeight - ((d.value - minVal) / valRange) * chartHeight;
    return { x, y, label: d.label, val: d.value };
  });

  // Build the SVG path for line and area fill
  const linePath = points.reduce((path, p, i) => {
    return i === 0 ? `M ${p.x} ${p.y}` : `${path} L ${p.x} ${p.y}`;
  }, '');

  const areaPath = points.length > 0
    ? `${linePath} L ${points[points.length - 1].x} ${padding.top + chartHeight} L ${points[0].x} ${padding.top + chartHeight} Z`
    : '';

  // Grid levels (y axis)
  const yTicks = 4;
  const gridLinesY = Array.from({ length: yTicks }).map((_, i) => {
    const ratio = i / (yTicks - 1);
    const y = padding.top + ratio * chartHeight;
    const value = Math.round(maxVal - ratio * valRange);
    return { y, value };
  });

  return (
    <div style={{ position: 'relative', width: '100%' }}>
      <svg viewBox={`0 0 ${width} ${height}`} style={{ width: '100%', height: 'auto', overflow: 'visible' }}>
        {/* Gradients */}
        <defs>
          <linearGradient id="chartGradient" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={color} stopOpacity={0.25} />
            <stop offset="100%" stopColor={color} stopOpacity={0.0} />
          </linearGradient>
        </defs>

        {/* Grid lines */}
        {gridLines && gridLinesY.map((g, i) => (
          <g key={i}>
            <line
              x1={padding.left}
              y1={g.y}
              x2={width - padding.right}
              y2={g.y}
              stroke="hsl(var(--border-primary))"
              strokeWidth={1}
              strokeDasharray="4 4"
            />
            <text
              x={padding.left - 10}
              y={g.y + 4}
              textAnchor="end"
              fontSize="10px"
              fill="hsl(var(--text-secondary))"
            >
              {g.value}
            </text>
          </g>
        ))}

        {/* X Axis Labels */}
        {points.map((p, i) => (
          <g key={i}>
            {i % Math.ceil(points.length / 6) === 0 && (
              <text
                x={p.x}
                y={height - 10}
                textAnchor="middle"
                fontSize="10px"
                fill="hsl(var(--text-secondary))"
              >
                {p.label}
              </text>
            )}
          </g>
        ))}

        {/* Fill Area */}
        <path d={areaPath} fill="url(#chartGradient)" />

        {/* Line Stroke */}
        <path d={linePath} fill="none" stroke={color} strokeWidth={2} />

        {/* Data points & Interactive hovers */}
        {points.map((p, i) => (
          <g
            key={i}
            onMouseEnter={() => setHoveredIdx(i)}
            onMouseLeave={() => setHoveredIdx(null)}
            style={{ cursor: 'pointer' }}
          >
            {/* Transparent hover target */}
            <rect
              x={p.x - 15}
              y={padding.top}
              width={30}
              height={chartHeight}
              fill="transparent"
            />
            {/* Visible circle on hover or endpoint */}
            {(hoveredIdx === i || i === points.length - 1) && (
              <circle
                cx={p.x}
                cy={p.y}
                r={hoveredIdx === i ? 5 : 3.5}
                fill={color}
                stroke="hsl(var(--bg-secondary))"
                strokeWidth={2}
              />
            )}
          </g>
        ))}
      </svg>

      {/* Tooltip Overlay */}
      {hoveredIdx !== null && (
        <div style={{
          position: 'absolute',
          top: points[hoveredIdx].y - 45,
          left: `${(points[hoveredIdx].x / width) * 100}%`,
          transform: 'translateX(-50%)',
          backgroundColor: 'hsl(var(--bg-secondary))',
          border: '1px solid hsl(var(--border-primary))',
          padding: '4px 8px',
          borderRadius: 'var(--radius-sm)',
          boxShadow: 'var(--shadow-md)',
          pointerEvents: 'none',
          fontSize: '11px',
          whiteSpace: 'nowrap',
          zIndex: 10
        }}>
          <div style={{ fontWeight: 600, color: 'hsl(var(--text-primary))' }}>{points[hoveredIdx].val}</div>
          <div style={{ color: 'hsl(var(--text-secondary))', fontSize: '9px' }}>{points[hoveredIdx].label}</div>
        </div>
      )}
    </div>
  );
};

// ----------------------------------------------------
// 2. BAR CHART Component
// ----------------------------------------------------
interface BarChartProps {
  data: DataPoint[];
  height?: number;
  color?: string;
}

export const BarChart: React.FC<BarChartProps> = ({
  data,
  height = 200,
  color = 'hsl(var(--accent-color))'
}) => {
  const [hoveredIdx, setHoveredIdx] = useState<number | null>(null);

  if (data.length === 0) return null;

  const padding = { top: 20, right: 10, bottom: 30, left: 40 };
  const width = 500;
  const chartWidth = width - padding.left - padding.right;
  const chartHeight = height - padding.top - padding.bottom;

  const maxVal = Math.max(...data.map(d => d.value), 10);
  const minVal = 0;
  const valRange = maxVal - minVal;

  const barSpacing = 12;
  const totalBarSpacing = barSpacing * (data.length - 1);
  const barWidth = (chartWidth - totalBarSpacing) / data.length;

  const bars = data.map((d, index) => {
    const x = padding.left + index * (barWidth + barSpacing);
    const barH = ((d.value - minVal) / valRange) * chartHeight;
    const y = padding.top + chartHeight - barH;
    return { x, y, width: barWidth, height: barH, label: d.label, val: d.value };
  });

  return (
    <div style={{ position: 'relative', width: '100%' }}>
      <svg viewBox={`0 0 ${width} ${height}`} style={{ width: '100%', height: 'auto', overflow: 'visible' }}>
        {/* Grid lines */}
        {Array.from({ length: 4 }).map((_, i) => {
          const ratio = i / 3;
          const y = padding.top + ratio * chartHeight;
          const value = Math.round(maxVal - ratio * valRange);
          return (
            <g key={i}>
              <line
                x1={padding.left}
                y1={y}
                x2={width - padding.right}
                y2={y}
                stroke="hsl(var(--border-primary))"
                strokeWidth={1}
                strokeDasharray="4 4"
              />
              <text
                x={padding.left - 10}
                y={y + 4}
                textAnchor="end"
                fontSize="10px"
                fill="hsl(var(--text-secondary))"
              >
                {value}
              </text>
            </g>
          );
        })}

        {/* X Axis Labels */}
        {bars.map((b, i) => (
          <text
            key={i}
            x={b.x + b.width / 2}
            y={height - 10}
            textAnchor="middle"
            fontSize="10px"
            fill="hsl(var(--text-secondary))"
          >
            {b.label}
          </text>
        ))}

        {/* Bars */}
        {bars.map((b, i) => (
          <rect
            key={i}
            x={b.x}
            y={b.y}
            width={b.width}
            height={Math.max(b.height, 2)} // ensure at least 2px height
            rx={2}
            fill={hoveredIdx === i ? color : `stroke` ? `${color}dd` : color}
            opacity={hoveredIdx !== null && hoveredIdx !== i ? 0.65 : 1}
            style={{ transition: 'all 0.15s ease', cursor: 'pointer' }}
            onMouseEnter={() => setHoveredIdx(i)}
            onMouseLeave={() => setHoveredIdx(null)}
          />
        ))}
      </svg>

      {/* Tooltip Overlay */}
      {hoveredIdx !== null && (
        <div style={{
          position: 'absolute',
          top: bars[hoveredIdx].y - 45,
          left: `${((bars[hoveredIdx].x + bars[hoveredIdx].width / 2) / width) * 100}%`,
          transform: 'translateX(-50%)',
          backgroundColor: 'hsl(var(--bg-secondary))',
          border: '1px solid hsl(var(--border-primary))',
          padding: '4px 8px',
          borderRadius: 'var(--radius-sm)',
          boxShadow: 'var(--shadow-md)',
          pointerEvents: 'none',
          fontSize: '11px',
          whiteSpace: 'nowrap',
          zIndex: 10
        }}>
          <div style={{ fontWeight: 600, color: 'hsl(var(--text-primary))' }}>{bars[hoveredIdx].val}</div>
          <div style={{ color: 'hsl(var(--text-secondary))', fontSize: '9px' }}>{bars[hoveredIdx].label}</div>
        </div>
      )}
    </div>
  );
};

// ----------------------------------------------------
// 3. GAUGE CHART (Security Score Circle)
// ----------------------------------------------------
interface GaugeChartProps {
  score: number;
  label?: string;
  size?: number;
  strokeWidth?: number;
  color?: string;
}

export const GaugeChart: React.FC<GaugeChartProps> = ({
  score,
  label = 'Score',
  size = 140,
  strokeWidth = 12,
  color = 'hsl(var(--accent-color))'
}) => {
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
      <svg width={size} height={size} style={{ transform: 'rotate(-90deg)', overflow: 'visible' }}>
        {/* Background track circle */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="hsl(var(--border-primary))"
          strokeWidth={strokeWidth}
        />
        {/* Active progress circle */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth={strokeWidth}
          strokeDasharray={circumference}
          strokeDashoffset={strokeDashoffset}
          strokeLinecap="round"
          style={{ transition: 'stroke-dashoffset 0.8s cubic-bezier(0.4, 0, 0.2, 1)' }}
        />
      </svg>
      {/* Center Labels */}
      <div style={{
        marginTop: `-${size / 2 + 18}px`,
        marginBottom: `${size / 2 - 18}px`,
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center'
      }}>
        <span style={{ fontSize: '1.5rem', fontWeight: 800, fontFamily: 'var(--font-display)' }}>
          {score}
        </span>
        <span style={{ fontSize: '0.675rem', textTransform: 'uppercase', color: 'hsl(var(--text-secondary))', fontWeight: 600 }}>
          {label}
        </span>
      </div>
    </div>
  );
};

// ----------------------------------------------------
// 4. RADIAL BAR CHART (Component Health / Resources)
// ----------------------------------------------------
interface RadialBarProps {
  name: string;
  value: number;
  max?: number;
  color?: string;
  strokeWidth?: number;
  size?: number;
}

export const RadialBar: React.FC<RadialBarProps> = ({
  name,
  value,
  max = 100,
  color = 'hsl(var(--accent-color))',
  strokeWidth = 6,
  size = 50
}) => {
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (value / max) * circumference;

  return (
    <div className="flex items-center gap-4" style={{ padding: '0.4rem 0' }}>
      <svg width={size} height={size} style={{ transform: 'rotate(-90deg)', flexShrink: 0 }}>
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="hsl(var(--border-primary))"
          strokeWidth={strokeWidth}
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth={strokeWidth}
          strokeDasharray={circumference}
          strokeDashoffset={strokeDashoffset}
          strokeLinecap="round"
        />
      </svg>
      <div>
        <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'hsl(var(--text-secondary))', textTransform: 'uppercase' }}>
          {name}
        </div>
        <div style={{ fontSize: '0.875rem', fontWeight: 700 }}>
          {value}%
        </div>
      </div>
    </div>
  );
};
