import { NavLink } from "react-router-dom";
import {
  Activity,
  Boxes,
  Cpu,
  FileCode2,
  Gauge,
  Layers,
  Moon,
  Radio,
  ScrollText,
  Settings2,
  ShieldCheck,
  Sun,
  TerminalSquare,
  type LucideIcon,
} from "lucide-react";
import { cn } from "@/lib/format";
import { Dot } from "@/components/ui/primitives";
import { useTheme } from "@/hooks/useTheme";
import { useSystem } from "@/state/system";

interface NavEntry {
  to: string;
  label: string;
  icon: LucideIcon;
}

interface NavSection {
  heading: string;
  entries: NavEntry[];
}

export const NAV: NavSection[] = [
  {
    heading: "",
    entries: [{ to: "/", label: "Overview", icon: Gauge }],
  },
  {
    heading: "Local",
    entries: [
      { to: "/agent", label: "Agent", icon: Activity },
      { to: "/telemetry", label: "Telemetry", icon: Radio },
      { to: "/ebpf", label: "eBPF", icon: Cpu },
    ],
  },
  {
    heading: "OIL",
    entries: [
      { to: "/studio", label: "Studio", icon: FileCode2 },
      { to: "/simulator", label: "Simulator", icon: Layers },
      { to: "/registry", label: "Registry", icon: Boxes },
    ],
  },
  {
    heading: "Access",
    entries: [{ to: "/secure-connect", label: "Secure Connect", icon: ShieldCheck }],
  },
  {
    heading: "System",
    entries: [
      { to: "/logs", label: "Logs", icon: ScrollText },
      { to: "/settings", label: "Settings", icon: Settings2 },
    ],
  },
];

const POSTURE_LABEL = {
  protected: "PROTECTED",
  degraded: "DEGRADED",
  down: "NO AGENT",
  unknown: "UNKNOWN",
} as const;

const POSTURE_TONE = {
  protected: "ok",
  degraded: "warn",
  down: "danger",
  unknown: "muted",
} as const;

export function Sidebar({ onOpenPalette }: { onOpenPalette: () => void }) {
  const { posture, live } = useSystem();
  const { theme, toggle } = useTheme();

  return (
    <aside className="flex w-52 shrink-0 flex-col border-r border-border bg-rail">
      <div className="flex h-12 items-center gap-2 px-3">
        <div className="flex h-6 w-6 items-center justify-center rounded-md border-2 border-primary">
          <div className="h-1.5 w-1.5 rounded-full bg-primary" />
        </div>
        <div className="leading-none">
          <div className="text-[13px] font-semibold tracking-tight">Olopa</div>
          <div className="mt-0.5 text-[9px] font-medium uppercase tracking-[0.18em] text-primary">
            Command
          </div>
        </div>
      </div>

      <div className="mx-3 mb-2 flex items-center gap-1.5 rounded-md border border-border bg-surface px-2 py-1.5">
        <Dot tone={POSTURE_TONE[posture]} pulse={live} />
        <span className="font-mono text-[10px] tracking-wider text-fg-muted">
          {POSTURE_LABEL[posture]}
        </span>
      </div>

      <nav className="flex-1 overflow-y-auto px-2 pb-2">
        {NAV.map((section) => (
          <div key={section.heading || "root"} className="mb-1">
            {section.heading && (
              <div className="px-2 pb-1 pt-3 text-[9px] font-semibold uppercase tracking-[0.16em] text-fg-faint">
                {section.heading}
              </div>
            )}
            {section.entries.map(({ to, label, icon: Icon }) => (
              <NavLink
                key={to}
                to={to}
                end={to === "/"}
                className={({ isActive }) =>
                  cn(
                    "flex items-center gap-2 rounded-md px-2 py-1.5 text-xs transition-colors",
                    isActive
                      ? "bg-surface-2 text-fg"
                      : "text-fg-muted hover:bg-surface hover:text-fg",
                  )
                }
              >
                {({ isActive }) => (
                  <>
                    <Icon className={cn("h-3.5 w-3.5", isActive && "text-primary")} />
                    {label}
                  </>
                )}
              </NavLink>
            ))}
          </div>
        ))}
      </nav>

      <div className="m-2 flex items-center gap-1.5">
        <button
          type="button"
          onClick={onOpenPalette}
          className="flex flex-1 items-center gap-2 rounded-md border border-border bg-surface px-2 py-1.5 text-[11px] text-fg-muted transition-colors hover:border-border-strong hover:text-fg"
        >
          <TerminalSquare className="h-3.5 w-3.5" />
          Command
          <kbd className="ml-auto rounded border border-border-strong bg-bg px-1 font-mono text-[9px] text-fg-faint">
            ⌘K
          </kbd>
        </button>
        <button
          type="button"
          onClick={toggle}
          aria-label={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
          title={theme === "dark" ? "Light theme" : "Dark theme"}
          className="flex h-[30px] w-[30px] shrink-0 items-center justify-center rounded-md border border-border bg-surface text-fg-muted transition-colors hover:border-border-strong hover:text-fg"
        >
          {theme === "dark" ? <Sun className="h-3.5 w-3.5" /> : <Moon className="h-3.5 w-3.5" />}
        </button>
      </div>
    </aside>
  );
}
