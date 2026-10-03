import React, { useState } from 'react';
import { X, Upload, AlertCircle } from 'lucide-react';
import { uploadSbomJson } from '../api';

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
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm">
      <div className="bg-[#0f172a] border border-slate-700 w-full max-w-2xl rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="w-8 h-8 rounded-lg bg-blue-500/10 flex items-center justify-center text-blue-400">
              <Upload className="w-4 h-4" />
            </div>
            <div>
              <h2 className="text-base font-bold text-white">Ingest SBOM Document</h2>
              <p className="text-xs text-slate-400">CycloneDX (1.4/1.5), SPDX (2.2/2.3), or Syft JSON</p>
            </div>
          </div>
          <button onClick={onClose} className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Form Body */}
        <form onSubmit={handleSubmit} className="p-6 space-y-4 overflow-y-auto">
          {error && (
            <div className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs flex items-center space-x-2">
              <AlertCircle className="w-4 h-4 flex-shrink-0" />
              <span>{error}</span>
            </div>
          )}

          <div className="grid grid-cols-3 gap-3">
            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1">Target Application</label>
              <input
                type="text"
                value={app}
                onChange={(e) => setApp(e.target.value)}
                className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white focus:outline-none focus:border-blue-500"
                required
              />
            </div>
            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1">Environment</label>
              <select
                value={env}
                onChange={(e) => setEnv(e.target.value)}
                className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white focus:outline-none focus:border-blue-500"
              >
                <option value="production">Production</option>
                <option value="staging">Staging</option>
                <option value="development">Development</option>
              </select>
            </div>
            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1">Dependency State</label>
              <select
                value={state}
                onChange={(e) => setState(e.target.value)}
                className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white focus:outline-none focus:border-blue-500"
              >
                <option value="INSTALLED">INSTALLED (Container/Image)</option>
                <option value="RUNNING">RUNNING (Live Workload)</option>
                <option value="DECLARED">DECLARED (Manifest/Lockfile)</option>
              </select>
            </div>
          </div>

          <div>
            <div className="flex items-center justify-between mb-1.5">
              <label className="text-xs font-semibold text-slate-300">Raw SBOM JSON</label>
              <div className="flex space-x-1.5">
                <button
                  type="button"
                  onClick={() => { setJsonText(JSON.stringify(SAMPLE_CYCLONEDX, null, 2)); setApp('media-upload-service'); }}
                  className="px-2 py-0.5 rounded text-[11px] bg-slate-800 hover:bg-slate-700 text-slate-300"
                >
                  Preset: CycloneDX
                </button>
                <button
                  type="button"
                  onClick={() => { setJsonText(JSON.stringify(SAMPLE_SPDX, null, 2)); setApp('image-processor'); }}
                  className="px-2 py-0.5 rounded text-[11px] bg-slate-800 hover:bg-slate-700 text-slate-300"
                >
                  Preset: SPDX
                </button>
                <button
                  type="button"
                  onClick={() => { setJsonText(JSON.stringify(SAMPLE_SYFT, null, 2)); setApp('discourse-prod'); }}
                  className="px-2 py-0.5 rounded text-[11px] bg-slate-800 hover:bg-slate-700 text-slate-300"
                >
                  Preset: Syft
                </button>
              </div>
            </div>
            <textarea
              value={jsonText}
              onChange={(e) => setJsonText(e.target.value)}
              rows={12}
              className="w-full bg-slate-950 font-mono text-xs text-slate-200 border border-slate-800 rounded-xl p-3 focus:outline-none focus:border-blue-500 leading-relaxed"
              required
            />
          </div>

          <div className="pt-2 flex justify-end space-x-3">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-xs font-semibold text-slate-400 hover:text-white"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading}
              className="px-5 py-2 text-xs font-semibold bg-blue-600 hover:bg-blue-500 text-white rounded-xl shadow-lg shadow-blue-600/25 transition-all disabled:opacity-50"
            >
              {loading ? 'Normalizing & Building Graph...' : 'Ingest & Correlate'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
