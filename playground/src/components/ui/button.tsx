import type { ComponentProps, ReactElement } from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const buttonVariants = cva(
  "inline-flex shrink-0 cursor-pointer items-center justify-center gap-2 whitespace-nowrap rounded-sm border font-sans text-[12.5px] font-medium leading-none transition-[background-color,border-color,color] duration-150 focus-visible:outline-none disabled:pointer-events-none disabled:cursor-not-allowed disabled:opacity-45",
  {
    variants: {
      variant: {
        default:
          "border-hairline bg-surface text-ink hover:border-hairline-strong hover:bg-inset",
        accent:
          "border-accent/45 bg-accent/[0.08] text-accent hover:border-accent/70 hover:bg-accent/[0.12]",
        danger:
          "border-danger/45 bg-danger/[0.08] text-danger hover:border-danger/70 hover:bg-danger/[0.12]",
        ghost:
          "border-transparent bg-transparent text-ink-muted hover:border-hairline hover:bg-surface hover:text-ink",
      },
      size: {
        sm: "h-8 px-2.5",
        md: "h-9 px-3",
        icon: "size-8 p-0",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "md",
    },
  },
);

export interface ButtonProps
  extends ComponentProps<"button">,
    VariantProps<typeof buttonVariants> {}

export function Button({
  className,
  variant,
  size,
  type = "button",
  ...props
}: ButtonProps): ReactElement {
  return (
    <button
      className={cn(buttonVariants({ variant, size }), className)}
      type={type}
      {...props}
    />
  );
}
