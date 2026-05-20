import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatDate(dateString: string): string {
  return new Date(dateString).toLocaleString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function getStatusColor(status: string): string {
  switch (status) {
    case "completed":
      return "text-green-400 bg-green-400/10 border-green-400/20";
    case "running":
      return "text-blue-400 bg-blue-400/10 border-blue-400/20";
    case "pending":
      return "text-yellow-400 bg-yellow-400/10 border-yellow-400/20";
    case "failed":
      return "text-red-400 bg-red-400/10 border-red-400/20";
    default:
      return "text-gray-400 bg-gray-400/10 border-gray-400/20";
  }
}

export function getStatusDot(status: string): string {
  switch (status) {
    case "completed":
      return "bg-green-400";
    case "running":
      return "bg-blue-400 animate-pulse";
    case "pending":
      return "bg-yellow-400";
    case "failed":
      return "bg-red-400";
    default:
      return "bg-gray-400";
  }
}
