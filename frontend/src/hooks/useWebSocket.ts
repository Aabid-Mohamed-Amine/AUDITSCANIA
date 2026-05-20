"use client";

import { useEffect, useRef, useCallback, useState } from "react";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface WsProgressMessage {
  scan_id: string;
  status: string;
  progress: number;
  message: string;
  data: Record<string, unknown>;
  timestamp: string;
}

type WsStatus = "connecting" | "connected" | "disconnected" | "error";

interface UseWebSocketOptions {
  onMessage?: (msg: WsProgressMessage) => void;
  enabled?: boolean;
  token?: string | null;
}

interface UseWebSocketReturn {
  status: WsStatus;
  lastMessage: WsProgressMessage | null;
  send: (data: string) => void;
  reconnect: () => void;
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

const WS_BASE =
  typeof window !== "undefined"
    ? process.env.NEXT_PUBLIC_WS_URL || "ws://localhost:8000"
    : "ws://localhost:8000";

const MAX_RECONNECT_ATTEMPTS = 10;
const RECONNECT_BASE_DELAY_MS = 1000;

export function useWebSocket(
  scanId: string | null,
  options: UseWebSocketOptions = {}
): UseWebSocketReturn {
  const { onMessage, enabled = true, token } = options;

  const wsRef = useRef<WebSocket | null>(null);
  const reconnectAttempts = useRef(0);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const mountedRef = useRef(true);

  const [status, setStatus] = useState<WsStatus>("disconnected");
  const [lastMessage, setLastMessage] = useState<WsProgressMessage | null>(null);

  const clearReconnectTimer = useCallback(() => {
    if (reconnectTimer.current) {
      clearTimeout(reconnectTimer.current);
      reconnectTimer.current = null;
    }
  }, []);

  const connect = useCallback(() => {
    if (!scanId || !enabled || !mountedRef.current) return;

    // Close any existing connection
    if (wsRef.current) {
      wsRef.current.onclose = null;
      wsRef.current.close();
    }

    const url = token
      ? `${WS_BASE}/ws/${scanId}?token=${encodeURIComponent(token)}`
      : `${WS_BASE}/ws/${scanId}`;
    setStatus("connecting");

    try {
      const ws = new WebSocket(url);
      wsRef.current = ws;

      ws.onopen = () => {
        if (!mountedRef.current) return;
        setStatus("connected");
        reconnectAttempts.current = 0;
        // Send initial ping
        ws.send("ping");
      };

      ws.onmessage = (event: MessageEvent) => {
        if (!mountedRef.current) return;
        try {
          const msg: WsProgressMessage = JSON.parse(event.data as string);
          setLastMessage(msg);
          onMessage?.(msg);
        } catch {
          // Ignore non-JSON messages (e.g. "pong")
        }
      };

      ws.onerror = () => {
        if (!mountedRef.current) return;
        setStatus("error");
      };

      ws.onclose = () => {
        if (!mountedRef.current) return;
        setStatus("disconnected");

        // Exponential back-off reconnect
        if (reconnectAttempts.current < MAX_RECONNECT_ATTEMPTS) {
          const delay =
            RECONNECT_BASE_DELAY_MS *
            Math.pow(1.5, reconnectAttempts.current);
          reconnectAttempts.current += 1;
          reconnectTimer.current = setTimeout(connect, delay);
        }
      };
    } catch {
      setStatus("error");
    }
  }, [scanId, enabled, token, onMessage]);

  // Connect / disconnect when scanId, enabled, or token changes
  useEffect(() => {
    mountedRef.current = true;

    if (scanId && enabled) {
      connect();
    }

    return () => {
      mountedRef.current = false;
      clearReconnectTimer();
      if (wsRef.current) {
        wsRef.current.onclose = null;
        wsRef.current.close();
        wsRef.current = null;
      }
    };
  }, [scanId, enabled, connect, clearReconnectTimer]);

  const send = useCallback((data: string) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(data);
    }
  }, []);

  const reconnect = useCallback(() => {
    clearReconnectTimer();
    reconnectAttempts.current = 0;
    connect();
  }, [connect, clearReconnectTimer]);

  return { status, lastMessage, send, reconnect };
}
