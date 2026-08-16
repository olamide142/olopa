import { Plus, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input, Select } from "@/components/ui/input";
import type { RuleTestFixture } from "@/lib/api";

const EVENT_TYPES = ["process_exec", "file", "net", "db_query", "agent_heartbeat"] as const;

export function newFixture(): RuleTestFixture {
  return {
    event_type: "process_exec",
    pid: 1001,
    comm: "bash",
    filename: "/bin/bash",
    net_dst_ip: null,
    net_dst_port: null,
    attrs: {},
  };
}

interface FixtureEditorProps {
  fixtures: RuleTestFixture[];
  onChange: (fixtures: RuleTestFixture[]) => void;
  /** Fixture indices reported as matched by the last test run. */
  matchedIndices?: Set<number>;
}

/** Editable synthetic events sent to POST /api/v1/rules/test. */
export function FixtureEditor({ fixtures, onChange, matchedIndices }: FixtureEditorProps) {
  const update = (index: number, patch: Partial<RuleTestFixture>) => {
    onChange(fixtures.map((f, i) => (i === index ? { ...f, ...patch } : f)));
  };

  const remove = (index: number) => onChange(fixtures.filter((_, i) => i !== index));

  return (
    <div className="space-y-2">
      {fixtures.map((fixture, index) => {
        const matched = matchedIndices?.has(index);
        return (
          <div
            key={index}
            className={
              "space-y-2 rounded-md border p-2.5 " +
              (matched ? "border-success/40 bg-success/5" : "border-border bg-muted/20")
            }
          >
            <div className="flex items-center gap-2">
              <span className="font-mono text-[10px] text-muted-foreground">#{index}</span>
              <Select
                className="h-7 flex-1 text-xs"
                value={fixture.event_type}
                onChange={(e) => update(index, { event_type: e.target.value })}
              >
                {EVENT_TYPES.map((type) => (
                  <option key={type} value={type}>
                    {type}
                  </option>
                ))}
              </Select>
              {matched && <span className="text-[10px] font-semibold uppercase text-success">match</span>}
              <Button
                size="icon"
                variant="ghost"
                className="h-7 w-7"
                onClick={() => remove(index)}
                aria-label={`Remove fixture ${index}`}
              >
                <Trash2 className="h-3.5 w-3.5" />
              </Button>
            </div>

            <div className="grid grid-cols-2 gap-2">
              <Input
                className="h-7 text-xs"
                placeholder="comm"
                value={fixture.comm}
                onChange={(e) => update(index, { comm: e.target.value })}
              />
              <Input
                className="h-7 text-xs"
                type="number"
                placeholder="pid"
                value={fixture.pid}
                onChange={(e) => update(index, { pid: Number(e.target.value) || 0 })}
              />
              <Input
                className="h-7 text-xs"
                placeholder="filename"
                value={fixture.filename ?? ""}
                onChange={(e) => update(index, { filename: e.target.value || null })}
              />
              <div className="flex gap-2">
                <Input
                  className="h-7 text-xs"
                  placeholder="dst ip"
                  value={fixture.net_dst_ip ?? ""}
                  onChange={(e) => update(index, { net_dst_ip: e.target.value || null })}
                />
                <Input
                  className="h-7 w-20 text-xs"
                  type="number"
                  placeholder="port"
                  value={fixture.net_dst_port ?? ""}
                  onChange={(e) =>
                    update(index, { net_dst_port: e.target.value ? Number(e.target.value) : null })
                  }
                />
              </div>
            </div>
          </div>
        );
      })}

      <Button size="sm" variant="outline" className="w-full" onClick={() => onChange([...fixtures, newFixture()])}>
        <Plus className="h-3.5 w-3.5" />
        Add fixture
      </Button>
    </div>
  );
}
