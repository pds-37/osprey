import React from 'react';
import {
  Shield,
  ArrowRight,
  Flame,
  CheckCircle2,
  Terminal,
  GitPullRequest,
  Sparkles,
  Layers,
  Lock,
  ChevronRight,
  Play,
  FileImage,
  Cloud,
  FileCode,
} from 'lucide-react';

interface LandingPageProps {
  onEnterApp: () => void;
  onRunDemoAndEnter: () => void;
}

export const LandingPage: React.FC<LandingPageProps> = ({
  onEnterApp,
  onRunDemoAndEnter,
}) => {
  return (
    <div className="min-h-screen bg-black text-neutral-200 selection:bg-neutral-800 selection:text-white font-sans flex flex-col">
      {/* Top Navbar */}
      <header className="border-b border-neutral-900 bg-black/90 backdrop-blur sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-14 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="w-8 h-8 rounded-lg bg-neutral-900 border border-neutral-800 flex items-center justify-center text-white">
              <Shield className="w-4 h-4 text-white" />
            </div>
            <div className="flex items-center space-x-2">
              <span className="font-bold text-sm tracking-tight text-white">Osprey</span>
              <span className="px-1.5 py-0.2 rounded text-[10px] font-mono font-medium bg-neutral-900 text-neutral-400 border border-neutral-800">
                v2.0
              </span>
            </div>
          </div>

          <div className="flex items-center space-x-3">
            <a
              href="https://github.com"
              target="_blank"
              rel="noreferrer"
              className="text-xs text-neutral-400 hover:text-white transition-colors hidden sm:block font-mono"
            >
              GitHub
            </a>
            <button
              onClick={onEnterApp}
              className="flex items-center space-x-1.5 px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-white hover:bg-neutral-200 text-black transition-all shadow-sm"
            >
              <span>Launch Control Plane</span>
              <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <main className="flex-1">
        <section className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 pt-20 pb-16 text-center space-y-6">
          {/* Badge */}
          <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-neutral-950 border border-neutral-800 text-neutral-300 text-[11px] font-mono mb-2">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
            <span>Open-Source Project Extension · Live Workspace Scanner</span>
          </div>

          {/* Main Title */}
          <h1 className="text-4xl sm:text-6xl font-extrabold text-white tracking-tight max-w-4xl mx-auto leading-[1.1]">
            "Upstream fixed the bug." <br />
            <span className="text-neutral-400 font-normal">
              Why your production containers are still vulnerable.
            </span>
          </h1>

          {/* Subtitle */}
          <p className="text-sm sm:text-base text-neutral-400 max-w-2xl mx-auto leading-relaxed">
            Modern applications don’t just run your code. They run thousands of transitive packages 4 layers deep.
            Osprey is the open-source security control plane that correlates software supply chains with runtime ingress,
            cloud identities, and deterministic adversary attack paths.
          </p>

          {/* Call to Actions */}
          <div className="flex flex-col sm:flex-row items-center justify-center gap-3 pt-4">
            <button
              onClick={onEnterApp}
              className="w-full sm:w-auto px-6 py-2.5 rounded-xl text-xs font-semibold bg-white hover:bg-neutral-200 text-black transition-all flex items-center justify-center space-x-2 shadow-lg"
            >
              <span>Enter Security Dashboard</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>

            <button
              onClick={onRunDemoAndEnter}
              className="w-full sm:w-auto px-6 py-2.5 rounded-xl text-xs font-semibold bg-neutral-900 hover:bg-neutral-800 text-white border border-neutral-800 transition-all flex items-center justify-center space-x-2 font-mono"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>Scan Live Codebase & Trace Paths</span>
            </button>
          </div>
        </section>

        {/* The .HEIC Case Study Section */}
        <section className="border-y border-neutral-900 bg-neutral-950/60 py-16">
          <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 space-y-10">
            <div className="text-center space-y-2 max-w-2xl mx-auto">
              <span className="text-[10px] font-mono text-neutral-400 uppercase tracking-widest">
                The Real-World Motivation
              </span>
              <h2 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">
                The Anatomy of the .HEIC Supply Chain Exploit
              </h2>
              <p className="text-xs text-neutral-400">
                How an image parser library you never installed directly can compromise your AWS production storage.
              </p>
            </div>

            {/* Visual Exploit Timeline */}
            <div className="grid grid-cols-1 md:grid-cols-6 gap-3 pt-4">
              {/* Step 1 */}
              <div className="p-4 rounded-xl bg-black border border-neutral-900 space-y-2">
                <div className="flex items-center justify-between text-neutral-500 text-[10px] font-mono">
                  <span>STEP 01</span>
                  <FileImage className="w-3.5 h-3.5 text-neutral-400" />
                </div>
                <h3 className="text-xs font-semibold text-white">Public Ingress</h3>
                <p className="text-[11px] text-neutral-400 leading-relaxed">
                  Attacker uploads crafted malicious <code className="text-neutral-200 font-mono">.heic</code> payload to unauthenticated endpoint (<code className="text-neutral-200 font-mono">POST /upload</code>).
                </p>
              </div>

              {/* Step 2 */}
              <div className="p-4 rounded-xl bg-black border border-neutral-900 space-y-2">
                <div className="flex items-center justify-between text-neutral-500 text-[10px] font-mono">
                  <span>STEP 02</span>
                  <Layers className="w-3.5 h-3.5 text-neutral-400" />
                </div>
                <h3 className="text-xs font-semibold text-white">Transitive Link</h3>
                <p className="text-[11px] text-neutral-400 leading-relaxed">
                  Web app invokes <code className="text-neutral-200 font-mono">ImageMagick</code>, which dynamically links system C library <code className="text-neutral-200 font-mono">libheif.so.1</code>.
                </p>
              </div>

              {/* Step 3 */}
              <div className="p-4 rounded-xl bg-black border border-red-900/60 space-y-2">
                <div className="flex items-center justify-between text-red-400 text-[10px] font-mono">
                  <span>STEP 03 · CVE</span>
                  <Flame className="w-3.5 h-3.5 text-red-400" />
                </div>
                <h3 className="text-xs font-semibold text-white">Memory Corruption</h3>
                <p className="text-[11px] text-neutral-400 leading-relaxed">
                  Heap buffer overflow in <code className="text-red-400 font-mono">libheif/box.cc</code> (CVE-2023-44398) grants arbitrary RCE inside pod.
                </p>
              </div>

              {/* Step 4 */}
              <div className="p-4 rounded-xl bg-black border border-amber-900/60 space-y-2">
                <div className="flex items-center justify-between text-amber-400 text-[10px] font-mono">
                  <span>STEP 04 · LAG</span>
                  <Terminal className="w-3.5 h-3.5 text-amber-400" />
                </div>
                <h3 className="text-xs font-semibold text-white">The Propagation Trap</h3>
                <p className="text-[11px] text-neutral-400 leading-relaxed">
                  Upstream fixed it & Debian packaged 1.19.8, but your base image <code className="text-amber-400 font-mono">python:3.11-slim</code> never updated.
                </p>
              </div>

              {/* Step 5 */}
              <div className="p-4 rounded-xl bg-black border border-neutral-900 space-y-2">
                <div className="flex items-center justify-between text-neutral-500 text-[10px] font-mono">
                  <span>STEP 05</span>
                  <Cloud className="w-3.5 h-3.5 text-neutral-400" />
                </div>
                <h3 className="text-xs font-semibold text-white">IAM Pivot</h3>
                <p className="text-[11px] text-neutral-400 leading-relaxed">
                  Pod inherits attached K8s ServiceAccount token with AWS IAM role permissions (<code className="text-neutral-200 font-mono">s3:PutObject</code>).
                </p>
              </div>

              {/* Step 6 */}
              <div className="p-4 rounded-xl bg-black border border-emerald-900/60 space-y-2">
                <div className="flex items-center justify-between text-emerald-400 text-[10px] font-mono">
                  <span>STEP 06 · RESOLVE</span>
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                </div>
                <h3 className="text-xs font-semibold text-white">Osprey Closes Path</h3>
                <p className="text-[11px] text-neutral-400 leading-relaxed">
                  Proposes non-destructive Dockerfile PR, requires human gate, rescans production: <strong className="text-emerald-400">Attack Path CLOSED</strong>.
                </p>
              </div>
            </div>
          </div>
        </section>

        {/* Feature Grid: Core Differentiators */}
        <section className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-20 space-y-12">
          <div className="text-center space-y-2 max-w-2xl mx-auto">
            <span className="text-[10px] font-mono text-neutral-400 uppercase tracking-widest">Architecture</span>
            <h2 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">
              Why Osprey is Not Just Another CVE Dashboard
            </h2>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* Pillar 1 */}
            <div className="p-6 rounded-xl bg-neutral-950 border border-neutral-900 space-y-3">
              <div className="w-8 h-8 rounded-lg bg-neutral-900 border border-neutral-800 flex items-center justify-center text-white">
                <Layers className="w-4 h-4 text-white" />
              </div>
              <h3 className="text-sm font-semibold text-white">3-State Dependency Tracking</h3>
              <p className="text-xs text-neutral-400 leading-relaxed">
                Never assumes manifests equal production. Strictly distinguishes <strong className="text-neutral-200">Declared</strong> (manifests), <strong className="text-neutral-200">Installed</strong> (container image filesystem), and <strong className="text-neutral-200">Running</strong> (live memory).
              </p>
            </div>

            {/* Pillar 2 */}
            <div className="p-6 rounded-xl bg-neutral-950 border border-neutral-900 space-y-3">
              <div className="w-8 h-8 rounded-lg bg-neutral-900 border border-neutral-800 flex items-center justify-center text-white">
                <Flame className="w-4 h-4 text-white" />
              </div>
              <h3 className="text-sm font-semibold text-white">Deterministic Attack Path Engine</h3>
              <p className="text-xs text-neutral-400 leading-relaxed">
                Connects external internet ingress points (<code className="text-neutral-300 font-mono">POST /upload</code>) through vulnerable parsers directly to target cloud crown jewels (AWS S3, RDS, Secrets).
              </p>
            </div>

            {/* Pillar 3 */}
            <div className="p-6 rounded-xl bg-neutral-950 border border-neutral-900 space-y-3">
              <div className="w-8 h-8 rounded-lg bg-neutral-900 border border-neutral-800 flex items-center justify-center text-white">
                <Terminal className="w-4 h-4 text-white" />
              </div>
              <h3 className="text-sm font-semibold text-white">Upstream Commit Heuristics</h3>
              <p className="text-xs text-neutral-400 leading-relaxed">
                Early-warning detection on upstream commits prior to CVE publication. Catches integer overflow fixes, bounds calculation changes, and memory protections weeks ahead of NVD.
              </p>
            </div>

            {/* Pillar 4 */}
            <div className="p-6 rounded-xl bg-neutral-950 border border-neutral-900 space-y-3">
              <div className="w-8 h-8 rounded-lg bg-neutral-900 border border-neutral-800 flex items-center justify-center text-white">
                <GitPullRequest className="w-4 h-4 text-white" />
              </div>
              <h3 className="text-sm font-semibold text-white">Zero Autonomous Destruction</h3>
              <p className="text-xs text-neutral-400 leading-relaxed">
                AI never touches production directly. All remediation is generated as clean Pull Request git diffs requiring human engineer authorization, CI/CD validation, and post-fix verification.
              </p>
            </div>

            {/* Pillar 5 */}
            <div className="p-6 rounded-xl bg-neutral-950 border border-neutral-900 space-y-3">
              <div className="w-8 h-8 rounded-lg bg-neutral-900 border border-neutral-800 flex items-center justify-center text-white">
                <Sparkles className="w-4 h-4 text-white" />
              </div>
              <h3 className="text-sm font-semibold text-white">Evidence-Grounded AI Copilot</h3>
              <p className="text-xs text-neutral-400 leading-relaxed">
                Strict prompt-injection defenses with delimiter fencing. AI synthesizes threat narratives strictly citing deterministic graph edges and CVE records — zero ungrounded hallucinations.
              </p>
            </div>

            {/* Pillar 6 */}
            <div className="p-6 rounded-xl bg-neutral-950 border border-neutral-900 space-y-3">
              <div className="w-8 h-8 rounded-lg bg-neutral-900 border border-neutral-800 flex items-center justify-center text-white">
                <Lock className="w-4 h-4 text-white" />
              </div>
              <h3 className="text-sm font-semibold text-white">6-Stage Patch Propagation</h3>
              <p className="text-xs text-neutral-400 leading-relaxed">
                Tracks the fix from Upstream Fix ➔ Security Advisory ➔ Distro Package ➔ Base Image Rebuild ➔ App Image Rebuild ➔ Production Deployment, pinning down the exact bottleneck.
              </p>
            </div>
          </div>
        </section>

        {/* Live Diff Preview Section */}
        <section className="border-t border-neutral-900 bg-neutral-950/40 py-16">
          <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 space-y-6">
            <div className="text-center space-y-2">
              <span className="text-[10px] font-mono text-neutral-400 uppercase tracking-widest">
                Actionable Remediation
              </span>
              <h2 className="text-xl sm:text-2xl font-bold text-white tracking-tight">
                From Attack Path to Pull Request in 1 Click
              </h2>
            </div>

            <div className="rounded-xl overflow-hidden border border-neutral-900 bg-black shadow-2xl">
              <div className="bg-neutral-950 px-4 py-2 border-b border-neutral-900 flex items-center justify-between text-xs text-neutral-400">
                <span className="font-mono text-[11px] flex items-center space-x-1.5">
                  <FileCode className="w-3.5 h-3.5 text-neutral-500" />
                  <span>Dockerfile — Proposed Non-destructive Upgrade</span>
                </span>
                <span className="text-[10px] font-mono text-emerald-400 bg-emerald-950/40 px-2 py-0.5 rounded border border-emerald-900/50">
                  Ready for Approval
                </span>
              </div>
              <pre className="p-4 text-xs font-mono overflow-x-auto leading-relaxed text-neutral-300">
                <span className="text-neutral-500">@@ -8,3 +8,3 @@</span>{'\n'}
                <span className="text-neutral-400"> FROM python:3.11-slim</span>{'\n'}
                <span className="text-red-400 bg-red-950/20 block">-RUN apt-get update && apt-get install -y libheif1=1.19.7-1</span>
                <span className="text-emerald-400 bg-emerald-950/20 block">+RUN apt-get update && apt-get install -y libheif1=1.19.8-1~deb12u1</span>
                <span className="text-neutral-400"> COPY . /app</span>
              </pre>
            </div>

            {/* Bottom CTA Banner */}
            <div className="p-6 rounded-2xl bg-neutral-950 border border-neutral-900 text-center space-y-3">
              <h3 className="text-base font-bold text-white">Get Started with Osprey</h3>
              <p className="text-xs text-neutral-400 max-w-lg mx-auto">
                Trace transitive dependencies, query live OSV advisories, and analyze complete attack paths in seconds.
              </p>
              <button
                onClick={onEnterApp}
                className="px-6 py-2.5 rounded-xl text-xs font-semibold bg-white hover:bg-neutral-200 text-black transition-all inline-flex items-center space-x-2"
              >
                <span>Launch Interactive Dashboard</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        </section>
      </main>

      {/* Minimal Footer */}
      <footer className="border-t border-neutral-900 py-6 text-center text-xs text-neutral-500 font-mono">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
          <span>Osprey v2.0 — Open-Source Supply Chain & Attack Path Control Plane</span>
          <div className="flex items-center space-x-4">
            <button onClick={onEnterApp} className="hover:text-neutral-300 transition-colors">
              App
            </button>
            <span>•</span>
            <span className="text-neutral-400">Built for modern DevSecOps</span>
          </div>
        </div>
      </footer>
    </div>
  );
};
