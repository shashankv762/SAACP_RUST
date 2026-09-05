import type { Metadata } from "next";
import { Outfit, JetBrains_Mono } from "next/font/google";
import { DashboardStoreProvider } from "@/lib/store";

const outfit = Outfit({
  subsets: ["latin"],
  weight: ["300", "400", "500", "600", "700"],
  variable: "--font-outfit",
  display: "swap",
});

const jetbrainsMono = JetBrains_Mono({
  subsets: ["latin"],
  weight: ["400", "500", "700"],
  variable: "--font-jetbrains-mono",
  display: "swap",
});

export const metadata: Metadata = {
  title: "SAACP Command Center",
  description: "Live security dashboard for the SAACP gateway fleet.",
};

/*
 * DashboardStoreProvider owns the ONE real /events SSE connection + REST
 * pollers against src/command_center.rs (see lib/store.tsx). The CommandUI
 * app consumes those slices via useSyncExternalStore and renders ONLY real
 * backend data in LIVE mode; the client-side simulator is opt-in via the
 * SIM switch and clearly labelled.
 */
export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${outfit.variable} ${jetbrainsMono.variable}`}>
      <body>
        <DashboardStoreProvider>{children}</DashboardStoreProvider>
      </body>
    </html>
  );
}
