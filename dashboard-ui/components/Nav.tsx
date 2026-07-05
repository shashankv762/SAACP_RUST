import Link from "next/link";

const LINKS = [
  { href: "/", label: "Overview" },
  { href: "/agents", label: "Agents" },
  { href: "/mesh", label: "Trust Mesh" },
  { href: "/alerts", label: "Alerts" },
  { href: "/financial", label: "Financial" },
];

export function Nav() {
  return (
    <nav className="nav">
      <span className="nav-brand">SAACP Command Center</span>
      {LINKS.map((l) => (
        <Link key={l.href} href={l.href} className="nav-link">
          {l.label}
        </Link>
      ))}
    </nav>
  );
}
