import { type UseQueryResult, useQuery } from "@tanstack/react-query";
import { useCallback, useState } from "react";
import { analyze } from "../analysis/analyze";
import { requestScan, ScanApiError } from "../api/scanApi";
import type { ScanFailure, ScanReport, ScanState } from "../types";

/** Transient failures worth a silent retry. A blocked URL will stay blocked. */
const RETRYABLE: ReadonlySet<ScanFailure["code"]> = new Set([
	"network",
	"unexpected",
]);

function toFailure(error: unknown): ScanFailure {
	if (error instanceof ScanApiError) return error.failure;
	return {
		code: "unexpected",
		message: "Algo deu errado ao analisar esse endereço.",
	};
}

/**
 * Collapses React Query's orthogonal flags (`isPending`, `isFetching`,
 * `isError`, `data`, `error`) into one closed union, so the UI can never render
 * a "loading" spinner next to a stale report or read `report` before it exists.
 */
function toScanState(
	target: string | null,
	query: UseQueryResult<ScanReport, unknown>,
): ScanState {
	if (target === null) return { status: "idle" };
	if (query.isPending || query.isFetching)
		return { status: "scanning", url: target };
	if (query.isError)
		return { status: "error", url: target, failure: toFailure(query.error) };
	if (query.data) return { status: "success", report: query.data };
	return { status: "idle" };
}

export interface UseScanResult {
	readonly state: ScanState;
	/** Timestamp of the cached data, so the UI can say when it is not fresh. */
	readonly updatedAt: number;
	scan: (url: string) => void;
	rescan: () => void;
	reset: () => void;
}

export function useScan(): UseScanResult {
	const [target, setTarget] = useState<string | null>(null);

	const query = useQuery({
		queryKey: ["scan", target],
		queryFn: async ({ signal }) => {
			if (target === null) throw new Error("query enabled without a target");
			return requestScan(target, signal);
		},
		// Grading is pure, so it belongs in `select`: React Query memoises it and
		// re-running a cached scan costs nothing.
		select: analyze,
		enabled: target !== null,
		staleTime: 5 * 60 * 1000,
		gcTime: 30 * 60 * 1000,
		retry: (failureCount, error) =>
			failureCount < 2 && RETRYABLE.has(toFailure(error).code),
		refetchOnWindowFocus: false,
	});

	const scan = useCallback((url: string) => setTarget(url.trim()), []);
	const reset = useCallback(() => setTarget(null), []);
	const rescan = useCallback(() => {
		void query.refetch();
	}, [query]);

	return {
		state: toScanState(target, query),
		updatedAt: query.dataUpdatedAt,
		scan,
		rescan,
		reset,
	};
}
