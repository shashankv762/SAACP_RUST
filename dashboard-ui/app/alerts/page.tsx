import { AlertFeed } from "@/components/AlertFeed";

export default function AlertsPage() {
  return (
    <main className="page">
      <p className="page-title">Security Alerts</p>
      <div className="card">
        <AlertFeed />
      </div>
    </main>
  );
}
