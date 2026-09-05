"use client";

/* SaacpLogo — animated brand mark (verbatim from `commandUI.md`). The
   component is self-contained: its CSS animations are scoped via a
   per-instance `<style>` element so multiple instances on one page
   (e.g. nav + footer) do not collide. */
export function SaacpLogo({ size = 46 }: { size?: number }) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 200 200" width={size} height={size} role="img" aria-label="SAACP">
      <defs>
        <filter id="lgGlowCC" x="-80%" y="-80%" width="260%" height="260%">
          <feGaussianBlur stdDeviation="2.2" result="b" />
          <feMerge>
            <feMergeNode in="b" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
      </defs>
      <style>{`
        .l-hex{fill:none;stroke:rgba(245,244,240,.1);stroke-width:1}
        .l-seg{stroke:#c5f547;stroke-width:2.6;stroke-linecap:round;opacity:.14;animation:lSegCC 6s linear infinite}
        @keyframes lSegCC{0%{opacity:.14}3%{opacity:1}11%{opacity:.14}100%{opacity:.14}}
        .l-conn{stroke:rgba(245,244,240,.18);stroke-width:1;stroke-dasharray:1 5;stroke-linecap:round}
        .l-gate line{stroke:#c5f547;stroke-width:2.6;stroke-linecap:round;opacity:.28;animation:lGateCC 6s linear infinite}
        @keyframes lGateCC{0%,24%{opacity:.28}27%{opacity:1}31%{opacity:.5}35%{opacity:1}41%{opacity:1}46%,74%{opacity:.28}77%{opacity:1}81%{opacity:.5}85%{opacity:1}91%{opacity:1}96%,100%{opacity:.28}}
        .l-shell{fill:#0a0908;stroke:#c5f547;stroke-opacity:.6;stroke-width:1.6}
        .l-core{fill:#c5f547}
        .l-ring{fill:none;stroke:#c5f547;stroke-width:1.2;opacity:0;transform-box:fill-box;transform-origin:center;animation:lRingCC 6s ease-out infinite}
        @keyframes lRingCC{0%{transform:scale(.9);opacity:.85}16%{transform:scale(2.2);opacity:0}100%{transform:scale(2.2);opacity:0}}
        .l-pkt{fill:#c5f547}
        .l-fwd{animation:lFwdCC 6s cubic-bezier(.45,0,.25,1) infinite}
        .l-ret{animation:lRetCC 6s cubic-bezier(.45,0,.25,1) 3s infinite}
        @keyframes lFwdCC{0%{transform:translateX(0);opacity:0}2.5%{opacity:1}5%{transform:translateX(0)}26%{transform:translateX(30px)}42%{transform:translateX(30px)}62%{transform:translateX(76px)}66%{opacity:1}70%{opacity:0}100%{transform:translateX(76px);opacity:0}}
        @keyframes lRetCC{0%{transform:translateX(0);opacity:0}2.5%{opacity:1}5%{transform:translateX(0)}26%{transform:translateX(-30px)}42%{transform:translateX(-30px)}62%{transform:translateX(-76px)}66%{opacity:1}70%{opacity:0}100%{transform:translateX(-76px);opacity:0}}
      `}</style>
      <path className="l-hex" d="M100 22 L167.5 61 L167.5 139 L100 178 L32.5 139 L32.5 61 Z" />
      <g filter="url(#lgGlowCC)">
        <line className="l-seg" x1="110.8" y1="28.2" x2="129.7" y2="39.2" style={{ animationDelay: '0s' }} />
        <line className="l-seg" x1="137.8" y1="43.8" x2="156.7" y2="54.8" style={{ animationDelay: '.5s' }} />
        <line className="l-seg" x1="167.5" y1="73.5" x2="167.5" y2="95.3" style={{ animationDelay: '1s' }} />
        <line className="l-seg" x1="167.5" y1="104.7" x2="167.5" y2="126.5" style={{ animationDelay: '1.5s' }} />
        <line className="l-seg" x1="156.7" y1="145.2" x2="137.8" y2="156.2" style={{ animationDelay: '2s' }} />
        <line className="l-seg" x1="129.7" y1="160.8" x2="110.8" y2="171.8" style={{ animationDelay: '2.5s' }} />
        <line className="l-seg" x1="89.2" y1="171.8" x2="70.3" y2="160.8" style={{ animationDelay: '3s' }} />
        <line className="l-seg" x1="62.2" y1="156.2" x2="43.3" y2="145.2" style={{ animationDelay: '3.5s' }} />
        <line className="l-seg" x1="32.5" y1="126.5" x2="32.5" y2="104.7" style={{ animationDelay: '4s' }} />
        <line className="l-seg" x1="32.5" y1="95.3" x2="32.5" y2="73.5" style={{ animationDelay: '4.5s' }} />
        <line className="l-seg" x1="43.3" y1="54.8" x2="62.2" y2="43.8" style={{ animationDelay: '5s' }} />
        <line className="l-seg" x1="70.3" y1="39.2" x2="89.2" y2="28.2" style={{ animationDelay: '5.5s' }} />
      </g>
      <line className="l-conn" x1="62" y1="100" x2="138" y2="100" />
      <g className="l-gate" filter="url(#lgGlowCC)">
        <line x1="96" y1="86" x2="96" y2="114" />
        <line x1="104" y1="86" x2="104" y2="114" />
      </g>
      <circle className="l-ring" cx="62" cy="100" r="9" style={{ animationDelay: '.1s' }} />
      <circle className="l-shell" cx="62" cy="100" r="8" />
      <circle className="l-core" cx="62" cy="100" r="3.2" />
      <circle className="l-ring" cx="138" cy="100" r="9" style={{ animationDelay: '3.1s' }} />
      <circle className="l-shell" cx="138" cy="100" r="8" />
      <circle className="l-core" cx="138" cy="100" r="3.2" />
      <circle className="l-pkt l-fwd" cx="62" cy="100" r="3.5" filter="url(#lgGlowCC)" />
      <circle className="l-pkt l-ret" cx="138" cy="100" r="3.5" opacity="0" filter="url(#lgGlowCC)" />
    </svg>
  );
}
