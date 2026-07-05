"use client";

import { useEffect, useRef } from "react";
import { DashboardEvent, eventsUrl } from "./api";

/**
 * Subscribes to the Command Center's /events SSE stream for the lifetime of the
 * component. Reconnects automatically (native EventSource behavior) — matches
 * command_center.rs's design: each connection is a fresh, cheap `broadcast::Receiver`
 * subscription, never accumulating state on the backend's global engines.
 */
export function useDashboardEvents(onEvent: (event: DashboardEvent) => void) {
  const handlerRef = useRef(onEvent);
  handlerRef.current = onEvent;

  useEffect(() => {
    const source = new EventSource(eventsUrl());
    source.onmessage = (msg) => {
      try {
        const parsed = JSON.parse(msg.data) as DashboardEvent;
        handlerRef.current(parsed);
      } catch {
        // Malformed/partial event — ignore rather than crash the whole feed.
      }
    };
    return () => source.close();
  }, []);
}
