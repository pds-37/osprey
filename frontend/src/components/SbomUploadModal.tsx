import React, { useState } from 'react';
import { X, Upload, AlertCircle, Sparkles } from 'lucide-react';
import { uploadSbomJson, scanLocalWorkspace } from '../api';

interface SbomUploadModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
}

const SAMPLE_CYCLONEDX = {
  bomFormat: "CycloneDX",
  specVersion: "1.4",
  serialNumber: "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  version: 1,
  metadata: {
    component: {
      name: "media-upload-service",
      version: "3.2.0",
      type: "application",
      purl: "pkg:generic/media-upload-service@3.2.0"
    }
  },
  components: [
    {
      name: "fastapi",
      version: "0.110.0",
      type: "library",
      purl: "pkg:pypi/fastapi@0.110.0",
      licenses: [{ license: { id: "MIT" } }]
    },
    {
      name: "pillow",
      version: "10.2.0",
      type: "library",
      purl: "pkg:pypi/pillow@10.2.0"
    },
    {
      name: "pydantic",
      version: "2.6.4",
      type: "library",
      purl: "pkg:pypi/pydantic@2.6.4"
    }
  ],
  dependencies: [
    {
      ref: "pkg:generic/media-upload-service@3.2.0",
      dependsOn: ["pkg:pypi/fastapi@0.110.0", "pkg:pypi/pillow@10.2.0"]
    },
    {
      ref: "pkg:pypi/fastapi@0.110.0",
      dependsOn: ["pkg:pypi/pydantic@2.6.4"]
    }
  ]
};

const SAMPLE_SPDX = {
  spdxVersion: "SPDX-2.3",
  dataLicense: "CC0-1.0",
  SPDXID: "SPDXRef-DOCUMENT",
  name: "image-processor-container",
  packages: [
    {
      SPDXID: "SPDXRef-ImageMagick",
      name: "imagemagick",
      versionInfo: "7.1.1-29",
      licenseConcluded: "Apache-2.0",
      externalRefs: [
        {
          referenceCategory: "PACKAGE-MANAGER",
          referenceType: "purl",
          referenceLocator: "pkg:deb/debian/imagemagick@7.1.1-29"
        }
      ]
    },
    {
      SPDXID: "SPDXRef-libheif",
      name: "libheif",
      versionInfo: "1.19.7",
      licenseConcluded: "LGPL-3.0",
      externalRefs: [
        {
          referenceCategory: "PACKAGE-MANAGER",
          referenceType: "purl",
          referenceLocator: "pkg:deb/debian/libheif@1.19.7"
        }
      ]
    }
  ],
  relationships: [
    {
      spdxElementId: "SPDXRef-ImageMagick",
      relatedSpdxElement: "SPDXRef-libheif",
      relationshipType: "DEPENDS_ON"
    }
  ]
};

const SAMPLE_SYFT = {
  schema: { version: "1.1.0" },
  id: "syft-scan-discourse-prod",
  source: {
    type: "image",
    target: "registry.company.internal/discourse-prod:latest"
  },
  artifacts: [
    {
      id: "art-1",
      name: "libheif1",
      version: "1.19.7-1",
      type: "deb",
      purl: "pkg:deb/debian/libheif1@1.19.7-1"
    },
    {
      id: "art-2",
      name: "imagemagick-6.q16",
      version: "8:6.9.11.60+dfsg-1.6",
      type: "deb",
      purl: "pkg:deb/debian/imagemagick-6.q16@8:6.9.11.60"
    }
  ]
};

export const SbomUploadModal: React.FC<SbomUploadModalProps> = ({ isOpen, onClose, onSuccess }) => {
  const [app, setApp] = useState('media-upload-service');
  const [env, setEnv] = useState('production');
  const [state, setState] = useState('INSTALLED');
  const [jsonText, setJsonText] = useState(JSON.stringify(SAMPLE_CYCLONEDX, null, 2));
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const parsed = JSON.parse(jsonText);
      await uploadSbomJson({
        content: parsed,
        application: app,
        environment: env,
        state: state,
      });
      onSuccess();
      onClose();
    } catch (err: any) {
      setError(err.message || 'Invalid JSON format or ingestion failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/85 backdrop-blur-md">
      <div className="bg-neutral-950 border border-neutral-900 w-full max-w-2xl rounded-xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="px-5 py-3.5 border-b border-neutral-900 flex items-center justify-between">
          <div className="flex items-center space-x-2.5">
            <div className="w-7 h-7 rounded-md bg-neutral-900 border border-neutral-800 flex items-center justify-center text-white">
              <Upload className="w-3.5 h-3.5 text-neutral-300" />
            </div>
            <div>
              <h2 className="text-sm font-semibold text-white">Ingest SBOM Document</h2>
              <p className="text-[11px] text-neutral-400">CycloneDX (1.4/1.5), SPDX (2.2/2.3), or Syft JSON</p>
            </div>
          </div>
          <button onClick={onClose} className="p-1 rounded text-neutral-500 hover:text-white hover:bg-neutral-900">
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Form Body */}
        <form onSubmit={handleSubmit} className="p-5 space-y-3.5 overflow-y-auto">
          {/* Real Workspace Manifest Quick Ingestion */}
          <div className="p-3 rounded-lg bg-neutral-900/50 border border-neutral-800 flex items-center justify-between">
            <div className="flex items-center space-x-2.5">
              <div className="w-7 h-7 rounded bg-white/10 flex items-center justify-center text-white">
                <Sparkles className="w-3.5 h-3.5 text-neutral-300" />
              </div>
              <div>
                <p className="text-xs font-medium text-white">Live Workspace Manifest Scanner</p>
                <p className="text-[11px] text-neutral-400">Scan actual <span className="font-mono text-neutral-300">frontend/package.json</span> and ingest into Knowledge Graph</p>
              </div>
            </div>
            <button
              type="button"
              disabled={loading}
              onClick={async () => {
                setLoading(true);
                setError(null);
                try {
                  await scanLocalWorkspace();
                  onSuccess();
                  onClose();
                } catch (err: any) {
                  setError(err.message || 'Failed to scan local manifests');
                } finally {
                  setLoading(false);
                }
              }}
              className="px-3 py-1.5 bg-neutral-100 hover:bg-white text-black font-semibold text-xs rounded transition-colors disabled:opacity-50 flex items-center space-x-1.5"
            >
              <span>{loading ? 'Scanning...' : 'Scan Local Repo'}</span>
            </button>
          </div>

          {error && (
            <div className="p-2.5 rounded-lg bg-black border border-red-900/50 text-red-400 text-xs flex items-center space-x-2 font-mono">
              <AlertCircle className="w-3.5 h-3.5 flex-shrink-0" />
              <span>{error}</span>
            </div>
          )}

          <div className="grid grid-cols-3 gap-2.5">
            <div>
              <label className="block text-[10px] font-mono uppercase text-neutral-400 mb-1">Target Application</label>
              <input
                type="text"
                value={app}
                onChange={(e) => setApp(e.target.value)}
                className="w-full bg-black border border-neutral-900 rounded-md px-2.5 py-1.5 text-xs text-white focus:outline-none focus:border-neutral-700 font-mono"
                required
              />
            </div>
            <div>
              <label className="block text-[10px] font-mono uppercase text-neutral-400 mb-1">Environment</label>
              <select
                value={env}
                onChange={(e) => setEnv(e.target.value)}
                className="w-full bg-black border border-neutral-900 rounded-md px-2.5 py-1.5 text-xs text-white focus:outline-none focus:border-neutral-700 font-mono"
              >
                <option value="production">Production</option>
                <option value="staging">Staging</option>
                <option value="development">Development</option>
              </select>
            </div>
            <div>
              <label className="block text-[10px] font-mono uppercase text-neutral-400 mb-1">Observed State</label>
              <select
                value={state}
                onChange={(e) => setState(e.target.value)}
                className="w-full bg-black border border-neutral-900 rounded-md px-2.5 py-1.5 text-xs text-white focus:outline-none focus:border-neutral-700 font-mono"
              >
                <option value="INSTALLED">INSTALLED (Container/OS)</option>
                <option value="RUNNING">RUNNING (Live Workload)</option>
                <option value="DECLARED">DECLARED (Manifest/Lockfile)</option>
              </select>
            </div>
          </div>

          <div>
            <div className="flex items-center justify-between mb-1.5">
              <label className="text-[10px] font-mono uppercase text-neutral-400">Raw SBOM JSON</label>
              <div className="flex space-x-1">
                <button
                  type="button"
                  onClick={() => { setJsonText(JSON.stringify(SAMPLE_CYCLONEDX, null, 2)); setApp('media-upload-service'); }}
                  className="px-2 py-0.5 rounded text-[10px] font-mono bg-neutral-900 hover:bg-neutral-800 text-neutral-300 border border-neutral-800"
                >
                  CycloneDX
                </button>
                <button
                  type="button"
                  onClick={() => { setJsonText(JSON.stringify(SAMPLE_SPDX, null, 2)); setApp('image-processor'); }}
                  className="px-2 py-0.5 rounded text-[10px] font-mono bg-neutral-900 hover:bg-neutral-800 text-neutral-300 border border-neutral-800"
                >
                  SPDX
                </button>
                <button
                  type="button"
                  onClick={() => { setJsonText(JSON.stringify(SAMPLE_SYFT, null, 2)); setApp('discourse-prod'); }}
                  className="px-2 py-0.5 rounded text-[10px] font-mono bg-neutral-900 hover:bg-neutral-800 text-neutral-300 border border-neutral-800"
                >
                  Syft
                </button>
              </div>
            </div>
            <textarea
              value={jsonText}
              onChange={(e) => setJsonText(e.target.value)}
              rows={11}
              className="w-full bg-black font-mono text-xs text-neutral-300 border border-neutral-900 rounded-lg p-3 focus:outline-none focus:border-neutral-700 leading-relaxed"
              required
            />
          </div>

          <div className="pt-2 flex justify-end space-x-2">
            <button
              type="button"
              onClick={onClose}
              className="px-3 py-1.5 text-xs text-neutral-400 hover:text-white"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading}
              className="px-4 py-1.5 text-xs font-semibold bg-white hover:bg-neutral-200 text-black rounded-lg transition-all disabled:opacity-50"
            >
              {loading ? 'Normalizing & Parsing...' : 'Ingest & Correlate'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
