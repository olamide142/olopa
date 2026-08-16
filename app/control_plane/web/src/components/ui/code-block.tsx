import { useState } from "react";
import { Check, Copy } from "lucide-react";
import { cn } from "@/lib/utils";

interface CodeBlockProps {
  /** Raw text to render. Objects should be stringified by the caller. */
  content: string;
  className?: string;
  /** Show a copy-to-clipboard affordance in the top-right corner. */
  copyable?: boolean;
  emptyLabel?: string;
}

/** Monospaced, scrollable viewer for compiler output and JSON artifacts. */
export function CodeBlock({ content, className, copyable = true, emptyLabel = "No output" }: CodeBlockProps) {
  const [copied, setCopied] = useState(false);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(content);
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    } catch {
      /* clipboard unavailable (insecure origin) — ignore */
    }
  };

  if (!content) {
    return (
      <div className={cn("rounded-md border border-border bg-muted/40 p-4 text-xs text-muted-foreground", className)}>
        {emptyLabel}
      </div>
    );
  }

  return (
    <div className={cn("relative", className)}>
      {copyable && (
        <button
          type="button"
          onClick={() => void copy()}
          className="absolute right-2 top-2 rounded-md border border-border bg-card p-1.5 text-muted-foreground transition-colors hover:bg-accent"
          aria-label="Copy to clipboard"
        >
          {copied ? <Check className="h-3.5 w-3.5 text-success" /> : <Copy className="h-3.5 w-3.5" />}
        </button>
      )}
      <pre className="max-h-[28rem] overflow-auto rounded-md border border-border bg-muted/40 p-3 font-mono text-xs leading-relaxed">
        {content}
      </pre>
    </div>
  );
}

/** Pretty-print a JSON value into a CodeBlock. */
export function JsonBlock({
  value,
  className,
  emptyLabel,
}: {
  value: unknown;
  className?: string;
  emptyLabel?: string;
}) {
  const content = value === null || value === undefined ? "" : JSON.stringify(value, null, 2);
  return <CodeBlock content={content} className={className} emptyLabel={emptyLabel} />;
}
