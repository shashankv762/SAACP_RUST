import type { Metadata } from "next";
import { Outfit, JetBrains_Mono } from "next/font/google";
import { Nav } from "@/components/Nav";
import { GlobalOverlays } from "@/components/GlobalOverlays";
import { DashboardStoreProvider } from "@/lib/store";
import "./globals.css";

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

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${outfit.variable} ${jetbrainsMono.variable}`}>
      <body>
        <DashboardStoreProvider>
          <Nav />
          {children}
          <GlobalOverlays />
        </DashboardStoreProvider>
      </body>
    </html>
  );
}
