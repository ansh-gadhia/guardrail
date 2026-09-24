import { useEffect, useRef, useState, type CSSProperties } from "react";
import brandMark from "@/assets/brand-mark.png";
import { cn } from "./ui";

/**
 * The sign-in page's schematic: GuardRail at work, drawn live.
 *
 * People on the left, the vault in the middle behind its gate, privileged
 * systems on the right. Sessions travel it one at a time, as light, through the
 * four steps every GuardRail session takes — a request reaches the gate; the
 * gate opens and the vault's dial turns; the credential is injected inside the
 * vault, and the session leaves it sealed; the target lights up and records.
 * The step bar beneath follows along, so the diagram explains itself.
 *
 * The person signing in is on it too. Submitting the form sends their own pulse
 * from the form's edge, past "You", to the gate, where it waits for the server:
 * the gate opens and the vault unlocks, it breaks against a red gate, or it
 * holds on amber for a second factor. That is the one thing on this page that
 * is theirs, and the rest of the scene gives way to it.
 *
 * Everything moves through refs in one requestAnimationFrame loop; React only
 * re-renders when the step changes. With reduced motion the scene is drawn
 * still and the steps are written out.
 */

// "cancel" withdraws an attempt that is waiting at the gate — somebody went back
// from the second-factor step.
export type Verdict = "pending" | "mfa" | "granted" | "denied" | "cancel";
export interface RailSignal {
  attempt: number; // 0 = nobody has tried yet
  verdict: Verdict;
}

type Phase = 0 | 1 | 2 | 3; // request, approve, broker, record

export const STEPS = [
  { label: "Request", desc: "Someone asks to reach a system they hold no keys to." },
  { label: "Approve", desc: "An approver lets it through the gate, or policy does on their behalf." },
  { label: "Broker", desc: "GuardRail supplies the credential itself. Nobody ever sees it." },
  { label: "Record", desc: "The session is recorded from start to finish, for the audit trail." },
] as const;

// ---- Geometry (viewBox units) -------------------------------------------------
const W = 640;
const H = 380;
const PX = 64; // people column
const SX = 588; // systems column
const C = { x: 334, y: 190 }; // vault centre
const E = { x: 240, y: 190 }; // the gate
const X = { x: 428, y: 190 }; // where sessions leave the vault
const PEOPLE_Y = [74, 190, 306];
const YOU = 1;
const SYSTEMS = [
  { y: 52, label: "Linux server", glyph: "server" },
  { y: 144, label: "Windows host", glyph: "desktop" },
  { y: 236, label: "Firewall", glyph: "wall" },
  { y: 328, label: "Database", glyph: "db" },
] as const;

const inRail = (y: number) =>
  y === C.y
    ? `M -90 ${y} L ${E.x} ${E.y}` // yours comes in from the form, past the panel's edge
    : `M ${PX + 17} ${y} C ${PX + 100} ${y} ${E.x - 96} ${E.y} ${E.x} ${E.y}`;
const outRail = (y: number) => `M ${X.x} ${X.y} C ${X.x + 76} ${X.y} ${SX - 104} ${y} ${SX - 32} ${y}`;
const THROUGH = `M ${E.x} ${E.y} L ${X.x} ${X.y}`;

// ---- Timing (ms) ---------------------------------------------------------------
const T = {
  firstRun: 1700, // after the page's draw-in
  in: 1150,
  gate: 620,
  through: 420,
  out: 1000,
  record: 2300,
  fade: 650,
  pause: 450,
  youIn: 700,
  open: 260,
  enter: 240,
  unlock: 560,
  burst: 950,
};

const ease = (k: number) => (k < 0.5 ? 4 * k * k * k : 1 - Math.pow(-2 * k + 2, 3) / 2);

interface Run {
  you: boolean;
  person: number;
  system: number;
  stage: string;
  since: number;
  entered: boolean;
  progress: number;
}

export function RailScene({
  signal,
  present,
  onUnlocked,
  reduced,
}: {
  signal: RailSignal;
  // Somebody is at the form. "You" lights up before anything is sent, so the
  // scene notices the person in front of it.
  present: boolean;
  onUnlocked: () => void;
  reduced: boolean;
}) {
  const svgRef = useRef<SVGSVGElement>(null);
  const signalRef = useRef(signal);
  const presentRef = useRef(present);
  const unlockedRef = useRef(onUnlocked);
  signalRef.current = signal;
  presentRef.current = present;
  unlockedRef.current = onUnlocked;
  const [phase, setPhase] = useState<Phase>(0);

  useEffect(() => {
    const svg = svgRef.current;
    if (!svg || reduced) return;
    const q = <E extends Element>(sel: string) => svg.querySelector(sel) as E;
    const qa = <E extends Element>(sel: string) => Array.from(svg.querySelectorAll(sel)) as E[];

    const head = q<SVGGElement>(".rs-head");
    const trails = qa<SVGPathElement>(".rs-trail");
    const gate = q<SVGGElement>(".rs-gate");
    const vault = q<SVGGElement>(".rs-vault");
    const dial = q<SVGGElement>(".rs-dial");
    const ring = q<SVGCircleElement>(".rs-ring");
    const key = q<SVGGElement>(".rs-key");
    const stream = q<SVGPathElement>(".rs-stream");
    const through = q<SVGPathElement>(".rs-through");
    const inPaths = qa<SVGPathElement>("[data-in]");
    const outPaths = qa<SVGPathElement>("[data-out]");
    const people = qa<SVGGElement>("[data-person]");
    const systems = qa<SVGGElement>("[data-system]");

    let seg: SVGPathElement = inPaths[0];
    let segLen = 0;
    let dialDeg = 0;
    let run: Run | null = null;
    let next = performance.now() + T.firstRun;
    let seen = signalRef.current.attempt;
    let lastPerson = 2;
    let lastSystem = -1;
    let lastPhase: Phase = 0;
    let prev = performance.now();
    let raf = 0;

    const phaseTo = (p: Phase) => {
      if (p !== lastPhase) {
        lastPhase = p;
        setPhase(p);
      }
    };
    const setSeg = (p: SVGPathElement) => {
      seg = p;
      segLen = p.getTotalLength();
      const d = p.getAttribute("d") ?? "";
      for (const t of trails) t.setAttribute("d", d);
    };
    const place = (dist: number, trail: number) => {
      const pt = seg.getPointAtLength(Math.max(0, Math.min(segLen, dist)));
      head.setAttribute("transform", `translate(${pt.x.toFixed(1)} ${pt.y.toFixed(1)})`);
      trails.forEach((t, i) => {
        const len = Math.max(0, trail * (i === 0 ? 1 : 0.45));
        t.style.strokeDasharray = `${len} ${segLen + len + 1}`;
        t.style.strokeDashoffset = `${-(dist - len)}`;
      });
    };
    const tone = (v: string) => {
      head.dataset.tone = v;
      for (const t of trails) t.dataset.tone = v;
    };
    const show = (on: boolean) => {
      head.dataset.on = on ? "1" : "0";
      for (const t of trails) t.dataset.on = on ? "1" : "0";
    };
    const flash = (el: Element, cls: string) => {
      el.classList.remove("flash-grant", "flash-deny");
      void el.getBoundingClientRect(); // restart the animation
      el.classList.add(cls);
    };
    const turn = (deg: number) => {
      dialDeg += deg;
      dial.style.transform = `rotate(${dialDeg}deg)`;
    };
    const reset = () => {
      show(false);
      delete head.dataset.hold;
      delete head.dataset.burst;
      gate.dataset.state = "closed";
      key.dataset.on = "0";
      stream.dataset.on = "0";
      people.forEach((p) => (p.dataset.active = "0"));
      systems.forEach((s) => (s.dataset.live = "0"));
    };
    const go = (r: Run, stage: string, now: number) => {
      r.stage = stage;
      r.since = now;
      r.entered = false;
    };
    const ambient = (now: number): Run => {
      // Alternate the two other people; "You" is kept for the person signing in.
      const person = lastPerson === 0 ? 2 : 0;
      let system = Math.floor(Math.random() * SYSTEMS.length);
      if (system === lastSystem) system = (system + 1) % SYSTEMS.length;
      lastPerson = person;
      lastSystem = system;
      return { you: false, person, system, stage: "in", since: now, entered: false, progress: 0 };
    };

    const stepAmbient = (r: Run, now: number, el: number) => {
      const enter = !r.entered;
      r.entered = true;
      switch (r.stage) {
        case "in": {
          if (enter) {
            setSeg(inPaths[r.person]);
            tone("req");
            show(true);
            people[r.person].dataset.active = "1";
            phaseTo(0);
          }
          place(ease(Math.min(1, el / T.in)) * segLen, 130);
          if (el >= T.in) go(r, "gate", now);
          break;
        }
        case "gate": {
          if (enter) {
            gate.dataset.state = "open";
            flash(ring, "flash-grant");
            turn(30);
            phaseTo(1);
          }
          place(segLen, 130 * (1 - Math.min(1, el / T.gate)));
          if (el >= T.gate) {
            people[r.person].dataset.active = "0";
            go(r, "through", now);
          }
          break;
        }
        case "through": {
          if (enter) {
            setSeg(through);
            show(false);
            key.dataset.on = "1";
            tone("sealed");
            phaseTo(2);
          }
          place(Math.min(1, el / T.through) * segLen, 0);
          if (el >= T.through) {
            gate.dataset.state = "closed";
            go(r, "out", now);
          }
          break;
        }
        case "out": {
          if (enter) {
            setSeg(outPaths[r.system]);
            show(true);
          }
          place(ease(Math.min(1, el / T.out)) * segLen, 150);
          if (el > T.out * 0.6) key.dataset.on = "0";
          if (el >= T.out) go(r, "record", now);
          break;
        }
        case "record": {
          if (enter) {
            show(false);
            systems[r.system].dataset.live = "1";
            stream.setAttribute("d", outPaths[r.system].getAttribute("d") ?? "");
            stream.dataset.on = "1";
            phaseTo(3);
          }
          if (el >= T.record) go(r, "fade", now);
          break;
        }
        case "fade": {
          if (enter) {
            systems[r.system].dataset.live = "0";
            stream.dataset.on = "0";
          }
          if (el >= T.fade) {
            run = null;
            next = now + T.pause;
          }
          break;
        }
      }
    };

    const stepYou = (r: Run, now: number, el: number, dt: number, verdict: Verdict) => {
      if (verdict === "cancel" && r.stage !== "done") {
        reset();
        run = null;
        next = now + T.pause;
        return;
      }
      const enter = !r.entered;
      r.entered = true;
      switch (r.stage) {
        case "in": {
          if (enter) {
            setSeg(inPaths[YOU]);
            tone("req");
            show(true);
            people[YOU].dataset.active = "1";
            phaseTo(0);
          }
          // An answer that arrives early hurries the pulse to the gate rather
          // than making anybody wait on an animation.
          const settled = verdict === "granted" || verdict === "denied";
          r.progress = Math.min(1, r.progress + (dt / T.youIn) * (settled ? 3 : 1));
          place(ease(r.progress) * segLen, 150);
          if (r.progress >= 1) go(r, "hold", now);
          break;
        }
        case "hold": {
          place(segLen, 150 * Math.max(0, 1 - el / 400));
          if (verdict === "granted") go(r, "open", now);
          else if (verdict === "denied") go(r, "burst", now);
          else {
            head.dataset.hold = "1";
            tone(verdict === "mfa" ? "mfa" : "req");
            gate.dataset.state = verdict === "mfa" ? "mfa" : "wait";
            phaseTo(verdict === "mfa" ? 1 : 0);
          }
          break;
        }
        case "open": {
          if (enter) {
            delete head.dataset.hold;
            gate.dataset.state = "open";
            flash(ring, "flash-grant");
            tone("grant");
            turn(90);
            phaseTo(1);
          }
          if (el >= T.open) go(r, "enter", now);
          break;
        }
        case "enter": {
          if (enter) {
            setSeg(through);
            phaseTo(2);
          }
          place(Math.min(1, el / T.enter) * (C.x - E.x), 40);
          if (el >= T.enter) go(r, "unlock", now);
          break;
        }
        case "unlock": {
          if (enter) {
            show(false);
            vault.dataset.state = "unlock";
            turn(180);
          }
          if (el >= T.unlock) {
            go(r, "done", now);
            unlockedRef.current();
          }
          break;
        }
        case "burst": {
          if (enter) {
            delete head.dataset.hold;
            gate.dataset.state = "deny";
            flash(ring, "flash-deny");
            tone("deny");
            head.dataset.burst = "1";
          }
          if (el >= T.burst) {
            reset();
            run = null;
            next = now + T.pause;
          }
          break;
        }
      }
    };

    const tick = (now: number) => {
      raf = requestAnimationFrame(tick);
      const dt = Math.min(64, now - prev); // a background tab must not jump
      prev = now;
      const sig = signalRef.current;
      if (sig.attempt !== seen) {
        seen = sig.attempt;
        reset();
        delete vault.dataset.state;
        run = { you: true, person: YOU, system: -1, stage: "in", since: now, entered: false, progress: 0 };
      }
      if (!run?.you) people[YOU].dataset.active = presentRef.current ? "1" : "0";
      if (!run) {
        if (now < next) return;
        run = ambient(now);
      }
      const el = now - run.since;
      if (run.you) stepYou(run, now, el, dt, sig.verdict);
      else stepAmbient(run, now, el);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [reduced]);

  return (
    <div className="flex min-h-0 flex-col">
      <svg
        ref={svgRef}
        viewBox={`0 0 ${W} ${H}`}
        // As tall as the panel can spare after the headline, steps and credit.
        className={cn("rail-scene max-h-[min(54vh,calc(100vh_-_23rem))] w-full", reduced && "rail-still")}
        role="img"
        aria-label="GuardRail at work: a person's request passes the gate to the vault, which supplies the credential, reaches a privileged system, and is recorded."
      >
        <defs>
          <radialGradient id="rs-vault-glow">
            <stop offset="0%" stopColor="rgb(45 212 191)" stopOpacity="0.28" />
            <stop offset="100%" stopColor="rgb(45 212 191)" stopOpacity="0" />
          </radialGradient>
          <filter id="rs-blur" x="-100%" y="-100%" width="300%" height="300%">
            <feGaussianBlur stdDeviation="5" />
          </filter>
        </defs>

        <circle cx={C.x} cy={C.y} r={150} fill="url(#rs-vault-glow)" className="rs-fade-in" />

        {/* rails */}
        {PEOPLE_Y.map((y, i) => (
          <path
            key={`in${i}`}
            data-in={i}
            d={inRail(y)}
            pathLength={1}
            className={cn("rs-rail", i === YOU && "rs-rail-you")}
            style={{ "--d": `${120 + i * 110}ms` } as CSSProperties}
          />
        ))}
        <path className="rs-rail rs-through" d={THROUGH} pathLength={1} style={{ "--d": "420ms" } as CSSProperties} />
        {SYSTEMS.map((s, i) => (
          <path
            key={`out${i}`}
            data-out={i}
            d={outRail(s.y)}
            pathLength={1}
            className="rs-rail"
            style={{ "--d": `${560 + i * 110}ms` } as CSSProperties}
          />
        ))}
        <path className="rs-stream" data-on="0" />
        <path className="rs-trail rs-trail-wide" data-on="0" />
        <path className="rs-trail rs-trail-fine" data-on="0" />

        {/* the gate */}
        <g transform={`translate(${E.x} ${E.y})`}>
          <g className="rs-gate rs-pop" data-state="closed" style={{ "--d": "700ms" } as CSSProperties}>
            <rect className="rs-gate-bar rs-gate-top" x={-2.5} y={-24} width={5} height={17} rx={2.5} />
            <rect className="rs-gate-bar rs-gate-bottom" x={-2.5} y={7} width={5} height={17} rx={2.5} />
          </g>
        </g>

        {/* the vault */}
        <g transform={`translate(${C.x} ${C.y})`}>
          <g className="rs-vault">
            <g className="rs-dial">
              <circle r={92} fill="none" /> {/* keeps the dial's box centred while it turns */}
              <circle r={80} className="rs-dial-ticks" />
              <circle r={80} className="rs-dial-major" />
              <rect x={-1.5} y={-86} width={3} height={9} rx={1.5} className="rs-dial-mark" />
            </g>
            <circle r={62} className="rs-ring" />
            <circle r={52} className="rs-disc" />
            <image
              href={brandMark}
              x={-34}
              y={-31}
              width={68}
              height={62.4}
              className="rs-emblem"
              preserveAspectRatio="xMidYMid meet"
            />
            <circle r={62} className="rs-flash" />
            <circle r={62} className="rs-shock" />
          </g>
        </g>
        <g transform={`translate(${C.x + 52} ${C.y - 52})`}>
          <g className="rs-key" data-on="0">
            <circle r={12} />
            <circle cx={-3.5} r={3} className="rs-key-glyph" />
            <path d="M -0.5 0 H 6.5 M 3.8 0 V 3 M 6.5 0 V 2.6" className="rs-key-glyph" />
          </g>
        </g>

        {/* people */}
        {PEOPLE_Y.map((y, i) => (
          <g key={`p${i}`} transform={`translate(${PX} ${y})`}>
            <g className="rs-person rs-pop" data-person={i} data-active="0" style={{ "--d": `${60 + i * 110}ms` } as CSSProperties}>
              <circle r={17} className="rs-node" />
              <circle cy={-4} r={3.6} className="rs-glyph" />
              <path d="M -6.5 8 C -6.5 2.5 6.5 2.5 6.5 8" className="rs-glyph" />
              {i === YOU && (
                <text y={36} textAnchor="middle" className="rs-label rs-label-you">
                  You
                </text>
              )}
            </g>
          </g>
        ))}

        {/* systems */}
        {SYSTEMS.map((s, i) => (
          <g key={`s${i}`} transform={`translate(${SX} ${s.y})`}>
            <g className="rs-system rs-pop" data-system={i} data-live="0" style={{ "--d": `${700 + i * 110}ms` } as CSSProperties}>
              <rect x={-31} y={-17} width={62} height={34} rx={9} className="rs-node" />
              <g transform="translate(-9 -9) scale(0.75)" className="rs-glyph">
                <Glyph kind={s.glyph} />
              </g>
              <circle cx={24} cy={-10} r={3.2} className="rs-rec" />
              <text y={33} textAnchor="middle" className="rs-label">
                {s.label}
              </text>
            </g>
          </g>
        ))}

        {/* the session in flight, above everything */}
        <g className="rs-head" data-on="0" data-tone="req">
          <circle r={15} className="rs-head-glow" filter="url(#rs-blur)" />
          <circle r={9} className="rs-head-seal" />
          <circle r={4.4} className="rs-head-core" />
          <circle r={4} className="rs-head-burst" />
        </g>
      </svg>

      <Steps phase={phase} reduced={reduced} />
    </div>
  );
}

function Steps({ phase, reduced }: { phase: Phase; reduced: boolean }) {
  if (reduced) {
    return (
      <ol className="mt-6 grid grid-cols-2 gap-x-8 gap-y-4">
        {STEPS.map((s) => (
          <li key={s.label}>
            <div className="font-display text-sm font-semibold text-white">{s.label}</div>
            <p className="mt-0.5 text-[13px] leading-5 text-slate-400">{s.desc}</p>
          </li>
        ))}
      </ol>
    );
  }
  return (
    <div className="rs-steps-in mt-6">
      <ol className="relative grid grid-cols-4">
        <span className="absolute inset-x-0 top-0 h-px bg-white/10" aria-hidden />
        <span
          className="rs-steps-lit absolute left-0 top-0 h-px"
          style={{ width: `${((phase + 1) / STEPS.length) * 100}%` }}
          aria-hidden
        />
        {STEPS.map((s, i) => (
          <li
            key={s.label}
            data-state={i < phase ? "done" : i === phase ? "now" : "next"}
            className="rs-step relative pt-3 font-display text-sm font-semibold tracking-tight"
            aria-current={i === phase ? "step" : undefined}
          >
            <span className="rs-step-dot absolute -top-[3px] left-0 h-[7px] w-[7px] rounded-full" aria-hidden />
            {s.label}
          </li>
        ))}
      </ol>
      <p key={phase} className="mt-2 min-h-[2.5rem] max-w-md animate-fadein text-[13px] leading-5 text-slate-400">
        {STEPS[phase].desc}
      </p>
    </div>
  );
}

// 24×24 line glyphs for the systems' kinds.
function Glyph({ kind }: { kind: (typeof SYSTEMS)[number]["glyph"] }) {
  switch (kind) {
    case "server":
      return (
        <>
          <rect x={3} y={4} width={18} height={7} rx={2} />
          <rect x={3} y={13} width={18} height={7} rx={2} />
          <path d="M7 7.5h.01M7 16.5h.01" />
        </>
      );
    case "desktop":
      return (
        <>
          <rect x={2.5} y={4} width={19} height={12.5} rx={2} />
          <path d="M9 20.5h6M12 16.5v4" />
        </>
      );
    case "wall":
      return (
        <>
          <rect x={3} y={4} width={18} height={16} rx={2} />
          <path d="M3 9.3h18M3 14.6h18M9 4v5.3M15 9.3v5.3M9 14.6V20" />
        </>
      );
    case "db":
      return (
        <>
          <ellipse cx={12} cy={6} rx={8} ry={3} />
          <path d="M4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3" />
        </>
      );
  }
}
