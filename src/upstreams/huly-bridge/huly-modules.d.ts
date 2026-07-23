/**
 * Ambient declarations for the @hcengineering/* packages used by huly-bridge.
 * The installed tarballs (0.7.423) point their "types" field at a types/
 * folder that is not shipped, so TypeScript cannot resolve declarations.
 * They are CJS packages consumed via default import + destructure (the same
 * interop pattern as the kimi-tag reference). Declaring them as untyped
 * modules keeps the build strict-clean without new dependencies.
 */
declare module "@hcengineering/api-client";
declare module "@hcengineering/core";
declare module "@hcengineering/text";
declare module "@hcengineering/text-markdown";
