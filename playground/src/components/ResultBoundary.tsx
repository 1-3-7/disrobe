import { Component, type ErrorInfo, type ReactElement, type ReactNode } from "react";

interface ResultBoundaryProps {
  readonly children: ReactNode;
}

interface ResultBoundaryState {
  readonly error: Error | null;
}

export class ResultBoundary extends Component<ResultBoundaryProps, ResultBoundaryState> {
  public override state: ResultBoundaryState = { error: null };

  public static getDerivedStateFromError(error: unknown): ResultBoundaryState {
    return { error: error instanceof Error ? error : new Error(String(error)) };
  }

  public override componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error("playground render boundary caught", error, info.componentStack);
  }

  public override render(): ReactNode {
    const { error }: ResultBoundaryState = this.state;
    if (error !== null) {
      return <BoundaryFallback message={error.message} />;
    }
    return this.props.children;
  }
}

function BoundaryFallback({ message }: { readonly message: string }): ReactElement {
  return (
    <div className="rounded-sm border border-danger/45 bg-danger/[0.05] px-4 py-3" role="alert">
      <span className="font-sans text-[12px] font-semibold uppercase tracking-wide text-danger">render error</span>
      <p className="mt-2 break-words font-mono text-[12.5px] leading-relaxed text-ink">{message}</p>
    </div>
  );
}
