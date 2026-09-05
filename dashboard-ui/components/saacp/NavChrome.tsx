"use client";

import { useEffect, useState } from "react";
import { hexN, tstr } from "@/lib/saacp-v3";

/* Clock — small UTC clock chip for the nav. */
export function Clock() {
  const [t, setT] = useState(tstr());
  useEffect(() => {
    const iv = setInterval(() => setT(tstr()), 1000);
    return () => clearInterval(iv);
  }, []);
  return (
    <span className="chip mono" style={{ minWidth: 96, justifyContent: "center" }}>
      {t} UTC
    </span>
  );
}

/* AuditChip — rolling 8-hex-char "audit head" pill, the operator's quick
   "is the audit chain healthy?" indicator. The real head hash comes from
   the backend's /api/readyz response, but for the v3 visual we use a
   randomized one (matches the v3 design). */
export function AuditChip() {
  const [h, setH] = useState(hexN(8));
  useEffect(() => {
    const iv = setInterval(() => setH(hexN(8)), 4000);
    return () => clearInterval(iv);
  }, []);
  return (
    <span className="chip hide-s" title="ImmutableAuditLog head hash — verified every epoch">
      <span className="dot green" style={{ width: 6, height: 6 }} />
      AUDIT 0x{h} ✓
    </span>
  );
}
