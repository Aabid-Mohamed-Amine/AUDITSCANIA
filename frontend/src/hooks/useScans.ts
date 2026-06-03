"use client";

import {
  useQuery,
  useMutation,
  useQueryClient,
  UseQueryResult,
  UseMutationResult,
} from "@tanstack/react-query";
import { scansApi, Scan, ScanListResponse, CreateScanPayload } from "@/lib/api";

// ---------------------------------------------------------------------------
// Query keys
// ---------------------------------------------------------------------------

export const SCAN_KEYS = {
  all: ["scans"] as const,
  list: (skip: number, limit: number) => ["scans", "list", skip, limit] as const,
  detail: (id: string) => ["scans", "detail", id] as const,
};

// ---------------------------------------------------------------------------
// List scans
// ---------------------------------------------------------------------------

export function useScans(
  skip = 0,
  limit = 50
): UseQueryResult<ScanListResponse> {
  return useQuery({
    queryKey: SCAN_KEYS.list(skip, limit),
    queryFn: () => scansApi.list(skip, limit),
    refetchInterval: (query) => {
      const items = (query.state.data as ScanListResponse | undefined)?.items ?? [];
      const hasActive = items.some(
        (s) => s.status === "running" || s.status === "pending"
      );
      return hasActive ? 3000 : false;
    },
    staleTime: 2000,
  });
}

// ---------------------------------------------------------------------------
// Single scan
// ---------------------------------------------------------------------------

export function useScan(id: string): UseQueryResult<Scan> {
  return useQuery({
    queryKey: SCAN_KEYS.detail(id),
    queryFn: () => scansApi.get(id),
    enabled: Boolean(id),
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      return status === "running" || status === "pending" ? 4000 : false;
    },
    staleTime: 1000,
    // On timeout/network error during polling: retry silently up to 3 times
    // before surfacing an error to the UI
    retry: (failureCount, error: unknown) => {
      const msg = (error as Error)?.message ?? "";
      const isTimeout = msg.includes("timeout") || msg.includes("Network Error");
      return isTimeout && failureCount < 3;
    },
    retryDelay: (attempt) => Math.min(2000 * (attempt + 1), 8000),
  });
}

// ---------------------------------------------------------------------------
// Create scan mutation
// ---------------------------------------------------------------------------

export function useCreateScan(): UseMutationResult<
  Scan,
  Error,
  CreateScanPayload
> {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: scansApi.create,
    onSuccess: () => {
      // Invalidate the list so it refreshes
      queryClient.invalidateQueries({ queryKey: SCAN_KEYS.all });
    },
  });
}

// ---------------------------------------------------------------------------
// Delete scan mutation
// ---------------------------------------------------------------------------

export function useDeleteScan(): UseMutationResult<void, Error, string> {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: scansApi.delete,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: SCAN_KEYS.all });
    },
  });
}

// ---------------------------------------------------------------------------
// Retry scan mutation
// ---------------------------------------------------------------------------

export function useRetryScan(): UseMutationResult<Scan, Error, string> {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: scansApi.retry,
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: SCAN_KEYS.all });
      queryClient.setQueryData(SCAN_KEYS.detail(data.id), data);
    },
  });
}
