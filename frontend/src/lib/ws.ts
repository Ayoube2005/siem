import { useEffect, useRef, useState } from "react";
import { getToken } from "./api";

export interface WsMessage {
  type: "connected" | "event" | "alert" | "alert_update";
  data: any;
}

/** Subscribe to the real-time SIEM stream. Auto-reconnects with backoff. */
export function useLiveStream(onMessage: (m: WsMessage) => void) {
  const [connected, setConnected] = useState(false);
  const handlerRef = useRef(onMessage);
  handlerRef.current = onMessage;

  useEffect(() => {
    let ws: WebSocket | null = null;
    let retry = 0;
    let closed = false;
    let timer: ReturnType<typeof setTimeout>;

    const connect = () => {
      const token = getToken();
      if (!token) return;
      const proto = location.protocol === "https:" ? "wss" : "ws";
      ws = new WebSocket(`${proto}://${location.host}/ws?token=${encodeURIComponent(token)}`);

      ws.onopen = () => { retry = 0; setConnected(true); };
      ws.onmessage = (e) => {
        try { handlerRef.current(JSON.parse(e.data)); } catch { /* ignore */ }
      };
      ws.onclose = () => {
        setConnected(false);
        if (!closed) {
          retry = Math.min(retry + 1, 6);
          timer = setTimeout(connect, 1000 * retry);
        }
      };
      ws.onerror = () => ws?.close();
    };

    connect();
    return () => { closed = true; clearTimeout(timer); ws?.close(); };
  }, []);

  return { connected };
}
