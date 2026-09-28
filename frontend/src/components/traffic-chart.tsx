import { useEffect, useMemo, useRef, useState } from "react";

import { Button, Empty, Table, Td, Th } from "@/components/ui";
import { formatBytes, formatDate } from "@/lib/utils";

export interface TrafficDay {
  day: string;
  uplink: number;
  downlink: number;
}

/**
 * TrafficChart draws daily traffic as stacked bars: one bar per day, the two directions as
 * its segments.
 *
 * Stacked, because the question the chart answers is "how much, and when" — the total per
 * day is the headline and the split between directions is the detail. One y-axis in binary
 * units, the same ones limits are set in. Every day is in the data even when it is zero, so a
 * quiet day reads as a gap rather than as the neighbouring days drawn closer together.
 *
 * Accessibility: identity is never colour alone (a legend names both series, and the tooltip
 * and table repeat the names), and the same numbers are available as a table.
 */
export function TrafficChart({ days, from, to }: { days: TrafficDay[]; from: string; to: string }) {
  const [showTable, setShowTable] = useState(false);
  const series = useMemo(() => fillDays(days, from, to), [days, from, to]);
  const total = series.reduce((sum, d) => sum + d.uplink + d.downlink, 0);

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center justify-between gap-3 px-4 pt-3">
        <div className="flex items-center gap-4 text-xs text-muted" aria-label="Legend">
          <LegendSwatch color="var(--color-series-up)" label="Uplink (from client)" />
          <LegendSwatch color="var(--color-series-down)" label="Downlink (to client)" />
        </div>
        <Button size="sm" variant="ghost" onClick={() => setShowTable((v) => !v)} aria-pressed={showTable}>
          {showTable ? "Show chart" : "Show table"}
        </Button>
      </div>

      {total === 0 ? (
        <Empty>No traffic in this period.</Empty>
      ) : showTable ? (
        <TrafficTable series={series} />
      ) : (
        <Bars series={series} />
      )}
    </div>
  );
}

function LegendSwatch({ color, label }: { color: string; label: string }) {
  return (
    <span className="inline-flex items-center gap-1.5">
      <span className="inline-block size-2.5 rounded-sm" style={{ background: color }} aria-hidden />
      {label}
    </span>
  );
}

const height = 220;
const margin = { top: 12, right: 12, bottom: 24, left: 64 };

function Bars({ series }: { series: TrafficDay[] }) {
  const container = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(640);
  const [hover, setHover] = useState<number | null>(null);

  useEffect(() => {
    const element = container.current;
    if (!element) return;
    const observer = new ResizeObserver(([entry]) => {
      if (entry) setWidth(Math.max(280, Math.floor(entry.contentRect.width)));
    });
    observer.observe(element);
    return () => observer.disconnect();
  }, []);

  const max = Math.max(1, ...series.map((d) => d.uplink + d.downlink));
  const ticks = niceTicks(max);
  const top = ticks[ticks.length - 1] ?? max;

  const plotWidth = width - margin.left - margin.right;
  const plotHeight = height - margin.top - margin.bottom;
  const band = plotWidth / series.length;
  // Thin bars: at most 60% of the band and never wider than 28px, so a week of data does not
  // turn into slabs.
  const barWidth = Math.max(2, Math.min(28, band * 0.6));
  const y = (value: number) => margin.top + plotHeight - (value / top) * plotHeight;

  // Label every nth day so labels never collide: roughly one per 64px.
  const labelEvery = Math.max(1, Math.ceil(series.length / Math.max(1, Math.floor(plotWidth / 64))));
  const hovered = hover !== null ? series[hover] : undefined;

  return (
    <div ref={container} className="relative px-2 pb-3">
      <svg width={width} height={height} role="img" aria-label="Daily traffic, uplink and downlink stacked">
        {/* Recessive grid: faint lines, muted labels, no border around the plot. */}
        {ticks.map((tick) => (
          <g key={tick}>
            <line
              x1={margin.left}
              x2={width - margin.right}
              y1={y(tick)}
              y2={y(tick)}
              stroke="var(--color-border)"
              strokeWidth={1}
            />
            <text x={margin.left - 8} y={y(tick)} dy="0.32em" textAnchor="end" className="num fill-muted text-[10px]">
              {formatBytes(tick, 0)}
            </text>
          </g>
        ))}

        {series.map((d, i) => {
          const x = margin.left + i * band + (band - barWidth) / 2;
          const up = d.uplink;
          const down = d.downlink;
          const base = y(0);
          const upTop = y(up);
          const downTop = y(up + down);
          const gap = up > 0 && down > 0 ? 2 : 0;

          return (
            <g key={d.day}>
              {up > 0 && (
                <Segment x={x} width={barWidth} top={upTop} bottom={base} color="var(--color-series-up)" rounded={down === 0} />
              )}
              {down > 0 && (
                <Segment
                  x={x}
                  width={barWidth}
                  top={downTop}
                  bottom={upTop - gap}
                  color="var(--color-series-down)"
                  rounded
                />
              )}
              {i % labelEvery === 0 && (
                <text x={x + barWidth / 2} y={height - 6} textAnchor="middle" className="num fill-muted text-[10px]">
                  {shortDay(d.day)}
                </text>
              )}
              {/* The hit target is the whole band, not the bar: a zero day still answers. */}
              <rect
                x={margin.left + i * band}
                y={margin.top}
                width={band}
                height={plotHeight}
                fill="transparent"
                onMouseEnter={() => setHover(i)}
                onMouseLeave={() => setHover((current) => (current === i ? null : current))}
              >
                <title>{`${formatDate(d.day)}: ${formatBytes(d.uplink + d.downlink)}`}</title>
              </rect>
            </g>
          );
        })}

        {hover !== null && (
          <line
            x1={margin.left + hover * band + band / 2}
            x2={margin.left + hover * band + band / 2}
            y1={margin.top}
            y2={margin.top + plotHeight}
            stroke="var(--color-muted)"
            strokeDasharray="2 3"
            pointerEvents="none"
          />
        )}
      </svg>

      {hovered && hover !== null && (
        <div
          className="pointer-events-none absolute top-2 z-10 rounded-md border border-border bg-surface px-3 py-2 text-xs shadow-md"
          style={{
            left: Math.min(width - 190, Math.max(8, margin.left + hover * band + band / 2 + 12)),
          }}
          role="tooltip"
        >
          <div className="mb-1 font-medium">{formatDate(hovered.day)}</div>
          <TooltipRow color="var(--color-series-up)" label="Uplink" value={hovered.uplink} />
          <TooltipRow color="var(--color-series-down)" label="Downlink" value={hovered.downlink} />
          <div className="mt-1 border-t border-border pt-1 text-muted">
            Total <span className="num float-right ml-4 text-text">{formatBytes(hovered.uplink + hovered.downlink)}</span>
          </div>
        </div>
      )}
    </div>
  );
}

/** Segment is a bar piece with a 4px-rounded top when it is the outermost segment. */
function Segment({
  x,
  width,
  top,
  bottom,
  color,
  rounded,
}: {
  x: number;
  width: number;
  top: number;
  bottom: number;
  color: string;
  rounded: boolean;
}) {
  const h = Math.max(0, bottom - top);
  if (h === 0) return null;
  const r = rounded ? Math.min(4, width / 2, h) : 0;
  // A path rather than a rect with rx, so only the top corners are rounded and the bar stays
  // square where it meets the baseline or the segment below.
  const d = [
    `M${x},${bottom}`,
    `V${top + r}`,
    r ? `Q${x},${top} ${x + r},${top}` : "",
    `H${x + width - r}`,
    r ? `Q${x + width},${top} ${x + width},${top + r}` : "",
    `V${bottom}`,
    "Z",
  ].join(" ");
  return <path d={d} fill={color} />;
}

function TooltipRow({ color, label, value }: { color: string; label: string; value: number }) {
  return (
    <div className="flex items-center gap-2">
      <span className="inline-block size-2 rounded-sm" style={{ background: color }} aria-hidden />
      <span className="text-muted">{label}</span>
      <span className="num ml-auto pl-4">{formatBytes(value)}</span>
    </div>
  );
}

function TrafficTable({ series }: { series: TrafficDay[] }) {
  return (
    <Table>
      <thead>
        <tr>
          <Th>Day</Th>
          <Th className="text-right">Uplink</Th>
          <Th className="text-right">Downlink</Th>
          <Th className="text-right">Total</Th>
        </tr>
      </thead>
      <tbody>
        {series
          .filter((d) => d.uplink + d.downlink > 0)
          .map((d) => (
            <tr key={d.day}>
              <Td>{formatDate(d.day)}</Td>
              <Td className="num text-right">{formatBytes(d.uplink)}</Td>
              <Td className="num text-right">{formatBytes(d.downlink)}</Td>
              <Td className="num text-right">{formatBytes(d.uplink + d.downlink)}</Td>
            </tr>
          ))}
      </tbody>
    </Table>
  );
}

/** fillDays inserts every missing day in [from, to] as zero. */
export function fillDays(days: TrafficDay[], from: string, to: string): TrafficDay[] {
  const byDay = new Map(days.map((d) => [d.day, d]));
  const out: TrafficDay[] = [];
  const cursor = new Date(`${from}T00:00:00Z`);
  const end = new Date(`${to}T00:00:00Z`);
  // Bounded, so a malformed range cannot spin: a year and a bit is the API's own maximum.
  for (let guard = 0; cursor <= end && guard < 400; guard++) {
    const key = cursor.toISOString().slice(0, 10);
    out.push(byDay.get(key) ?? { day: key, uplink: 0, downlink: 0 });
    cursor.setUTCDate(cursor.getUTCDate() + 1);
  }
  return out;
}

/** niceTicks picks round binary steps for the y-axis, ending at or just above max. */
export function niceTicks(max: number): number[] {
  const units = [1, 1024, 1024 ** 2, 1024 ** 3, 1024 ** 4, 1024 ** 5];
  let unit = 1;
  for (const candidate of units) if (max >= candidate) unit = candidate;

  const scaled = max / unit;
  const steps = [1, 2, 5, 10, 20, 50, 100, 200, 500, 1000];
  const step = (steps.find((s) => scaled / s <= 4) ?? 1000) * unit;

  const ticks: number[] = [];
  for (let value = 0; value < max + step; value += step) {
    ticks.push(value);
    if (value >= max) break;
  }
  return ticks;
}

function shortDay(day: string): string {
  const date = new Date(`${day}T00:00:00Z`);
  return date.toLocaleDateString(undefined, { month: "short", day: "numeric", timeZone: "UTC" });
}
