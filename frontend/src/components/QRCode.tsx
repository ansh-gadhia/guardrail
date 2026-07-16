import { useEffect, useState } from "react";
import QRCodeLib from "qrcode";
import { cn } from "./ui";

/**
 * QRCode renders any string as a scannable QR entirely in the browser — nothing
 * is sent to a server, which matters here because the value is an otpauth:// URI
 * carrying the TOTP secret. It's always drawn black-on-white on a white plate so
 * it scans regardless of the app theme (authenticator cameras want high contrast
 * and a quiet zone, not our dark surface). Rendered at 2× and downscaled for
 * crisp modules on high-DPI screens.
 */
export function QRCode({ value, size = 200, className }: { value: string; size?: number; className?: string }) {
  const [src, setSrc] = useState("");
  const [err, setErr] = useState(false);

  useEffect(() => {
    let cancelled = false;
    // Wrapped in try/catch, not just .catch(): toDataURL throws SYNCHRONOUSLY for
    // a non-string ("String required as first argument") rather than returning a
    // rejected promise, so a .catch() alone lets the error escape the effect and
    // take out the whole page via the error boundary. A missing value is a bug
    // worth fixing at the source, but it must degrade to "use the setup key
    // below" — never to a screen the user cannot get past.
    const run = async () => {
      try {
        const url = await QRCodeLib.toDataURL(value, {
          errorCorrectionLevel: "M",
          margin: 2,
          width: size * 2,
          color: { dark: "#0a0f14", light: "#ffffff" },
        });
        if (!cancelled) {
          setSrc(url);
          setErr(false);
        }
      } catch {
        if (!cancelled) setErr(true);
      }
    };
    void run();
    return () => {
      cancelled = true;
    };
  }, [value, size]);

  if (err) {
    return (
      <div
        className={cn("grid place-items-center rounded-xl border border-line bg-surface-2 text-center text-xs text-muted", className)}
        style={{ width: size, height: size }}
      >
        Couldn't render the QR. Use the setup key below.
      </div>
    );
  }
  return (
    <div className={cn("rounded-xl bg-white p-3 shadow-sm ring-1 ring-black/5", className)} style={{ width: size + 24, height: size + 24 }}>
      {src ? (
        <img src={src} alt="Authenticator setup QR code" width={size} height={size} className="h-full w-full" />
      ) : (
        <div className="h-full w-full animate-pulse rounded-md bg-black/5" />
      )}
    </div>
  );
}
