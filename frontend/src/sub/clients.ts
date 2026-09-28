/**
 * Client apps the page offers a one-tap import for.
 *
 * Only apps whose import scheme is documented by the app itself are listed (ADR-079). A
 * guessed scheme either does nothing when tapped or, worse, opens the app and does something
 * other than add the subscription. Everything else is served by the copy button and the QR
 * code, which every client accepts.
 */
export interface ClientApp {
  name: string;
  platforms: string;
  href: (subscriptionUrl: string, title: string) => string;
}

const enc = encodeURIComponent;

/** withFormat pins the format, for apps whose User-Agent the panel might not recognise. */
function withFormat(url: string, format: string): string {
  return `${url}?format=${format}`;
}

export const clientApps: ClientApp[] = [
  {
    // hiddify://import/<url>#<name>, per the Hiddify URL-scheme page. It reads every format.
    name: "Hiddify",
    platforms: "Android · iOS · Windows · macOS · Linux",
    href: (url, title) => `hiddify://import/${url}#${enc(title)}`,
  },
  {
    // sing-box://import-remote-profile?url=<encoded>#<encoded name>, per the sing-box docs for
    // its graphical clients (SFA, SFI, SFM).
    name: "sing-box",
    platforms: "Android · iOS · macOS",
    href: (url, title) => `sing-box://import-remote-profile?url=${enc(withFormat(url, "singbox"))}#${enc(title)}`,
  },
  {
    // v2rayng://install-config?url=<encoded>. [ПРОВЕРИТЬ] Reported by v2rayNG users to import
    // once rather than register an updating subscription; the copy button does the latter.
    name: "v2rayNG",
    platforms: "Android",
    href: (url) => `v2rayng://install-config?url=${enc(url)}`,
  },
  {
    // clash://install-config?url=<encoded>, the scheme Clash Verge Rev and other mihomo
    // front ends register.
    name: "Clash Verge / mihomo",
    platforms: "Windows · macOS · Linux",
    href: (url) => `clash://install-config?url=${enc(withFormat(url, "clash"))}`,
  },
];

/** Files the page offers for download: the formats a person, not a client, might want. */
export const downloadFormats = [
  { label: "Clash / mihomo (YAML)", format: "clash" },
  { label: "sing-box (JSON)", format: "singbox" },
] as const;
