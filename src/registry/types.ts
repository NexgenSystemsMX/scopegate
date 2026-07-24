/**
 * Registry types (EPIC-12): the `registry/v1` manifest format and the signed
 * index that anchors it. A manifest maps 1:1 to an UpstreamConfig — only
 * `version`, `description`, `docs` and `setup` are registry-level metadata.
 */
import type { UpstreamAuth, UpstreamConfig } from "../config/config.js";

/** Human-facing instruction for one required secret ref (never a value). */
export interface RegistryManifestSecret {
  /** Vault ref NAME the human must deposit (`scopegate secret add <ref>`). */
  ref: string;
  /** Where to obtain the value + the exact CLI command to deposit it. */
  hint: string;
}

export interface RegistryManifest {
  version: "registry/v1";
  /** Must match the index key and the manifest file basename. */
  name: string;
  description: string;
  transport: UpstreamConfig["transport"];
  auth: UpstreamAuth;
  /** M14.4: optional passthrough knobs (validated like scopegate.yaml). */
  exposeTools?: string[];
  attestation?: boolean;
  pool?: UpstreamConfig["pool"];
  docs?: string;
  setup?: {
    secrets?: RegistryManifestSecret[];
  };
}

export interface RegistryIndexEntry {
  /** File name relative to the registry root (basename only — no paths). */
  file: string;
  /** Hex sha256 over the exact manifest bytes. */
  sha256: string;
  signature?: string;
}

export interface RegistryIndex {
  version: number;
  updatedAt: string;
  manifests: Record<string, RegistryIndexEntry>;
}
