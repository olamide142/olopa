import { NavLink } from "react-router-dom";
import {
  Activity,
  Server,
  ShieldAlert,
  Network,
  FileCode2,
  Cpu,
  Download,
  type LucideIcon,
} from "lucide-react";
import { cn } from "@/lib/utils";

interface NavItem {
  to: string;
  label: string;
  icon: LucideIcon;
}

const NAV: NavItem[] = [
  { to: "/", label: "Metrics", icon: Activity },
  { to: "/fleet", label: "Fleet", icon: Server },
  { to: "/incidents", label: "Incidents", icon: ShieldAlert },
  { to: "/graph", label: "Graph", icon: Network },
  { to: "/oil", label: "OIL", icon: FileCode2 },
  { to: "/compiler", label: "Compiler", icon: Cpu },
  { to: "/install", label: "Install", icon: Download },
];

export function Sidebar() {
  return (
    <aside className="flex w-56 shrink-0 flex-col border-r border-sidebar-border bg-sidebar">
      <div className="flex h-14 items-center gap-2 px-4">
        <div className="flex h-7 w-7 items-center justify-center rounded-md bg-primary text-primary-foreground">
          <span className="text-sm font-bold">O</span>
        </div>
        <div className="leading-tight">
          <div className="text-sm font-semibold">Olopa</div>
          <div className="text-[10px] uppercase tracking-wider text-muted-foreground">Console</div>
        </div>
      </div>

      <nav className="flex-1 space-y-0.5 px-2 py-2">
        {NAV.map(({ to, label, icon: Icon }) => (
          <NavLink
            key={to}
            to={to}
            end={to === "/"}
            className={({ isActive }) =>
              cn(
                "flex items-center gap-2.5 rounded-md px-2.5 py-2 text-sm font-medium transition-colors",
                isActive
                  ? "bg-primary/10 text-primary"
                  : "text-muted-foreground hover:bg-accent hover:text-accent-foreground",
              )
            }
          >
            <Icon className="h-4 w-4" />
            {label}
          </NavLink>
        ))}
      </nav>

      <div className="border-t border-sidebar-border px-4 py-3 text-[10px] text-muted-foreground">
        olopa-console · v0.1.0
      </div>
    </aside>
  );
}
