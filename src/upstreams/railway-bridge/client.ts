/**
 * railway-bridge client (EPIC-16): semantic interface over the Railway public
 * GraphQL API (backboard) plus the factory the MCP server uses to pick a
 * backend:
 *
 *   createRailwayClient(env)
 *     RAILWAY_MOCK=1  → in-memory mock (mock-client.ts) — tests & local e2e
 *     otherwise       → real client over the backboard GraphQL API (native
 *                       fetch, ZERO new npm dependencies)
 *
 * Connection contract (frozen):
 *   RAILWAY_TOKEN    Railway API token, injected by the gateway at spawn from
 *                    the vault (registry/railway.yaml, auth type env). It is
 *                    NEVER logged and NEVER embedded in error messages.
 *   RAILWAY_API_URL  optional GraphQL endpoint (default DEFAULT_API_URL).
 *   RAILWAY_MOCK=1   in-memory mock, no network (the token is not validated).
 *
 * GraphQL query/mutation shapes are verified against the official Railway API
 * cookbook (railwayapp/docs, content/docs/integrations/api/*):
 *   projects / project(id) with services+environments connections,
 *   deployments(input, first:1), deploymentLogs, variables, domains,
 *   serviceInstanceDeployV2(serviceId, environmentId) → deployment id scalar,
 *   deploymentRedeploy(id) → Deployment.
 *
 * Redaction contract (frozen): variables_list NEVER returns values — any value
 * the API returns is replaced by REDACTED inside this client, before anything
 * leaves the bridge.
 */
import { createMockClient } from "./mock-client.js";

export const DEFAULT_API_URL = "https://backboard.railway.com/graphql/v2";
export const REDACTED = "[redacted]";
export const REQUEST_TIMEOUT_MS = 15_000;

// --- Semantic output shapes (compact JSON — the frozen response contract) ---

export interface RailwayServiceRef {
  id: string;
  name: string;
}

export interface RailwayProjectServices {
  id: string;
  name: string;
  services: RailwayServiceRef[];
}

export interface RailwayDeploymentInfo {
  id: string;
  status: string;
  createdAt: string;
  url: string | null;
}

export interface RailwayServiceStatus {
  projectId: string;
  project: string;
  serviceId: string;
  service: string;
  environment: string;
  deployment: RailwayDeploymentInfo | null;
}

export interface RailwayDeployAccepted {
  accepted: boolean;
  kind: "deploy" | "redeploy";
  deploymentId: string | null;
  projectId: string;
  project: string;
  serviceId: string;
  service: string;
  environment: string;
}

export interface RailwayLogLine {
  timestamp: string;
  severity: string;
  message: string;
}

export interface RailwayLogs {
  projectId: string;
  project: string;
  serviceId: string;
  service: string;
  deploymentId: string;
  count: number;
  logs: RailwayLogLine[];
}

export interface RailwayVariableEntry {
  name: string;
  /** Always REDACTED — values never leave the bridge. */
  value: string;
}

export interface RailwayVariables {
  projectId: string;
  project: string;
  serviceId: string;
  service: string;
  environment: string;
  count: number;
  variables: RailwayVariableEntry[];
}

export interface RailwayDomainStatus {
  projectId: string;
  project: string;
  serviceId: string;
  service: string;
  environment: string;
  serviceDomains: Array<{ id: string; domain: string }>;
  customDomains: Array<{ id: string; domain: string; dnsStatus: string | null }>;
}

// --- The bridge client contract (real and mock both implement it) ---

export interface RailwayBridgeClient {
  connect: () => Promise<void>;
  close: () => Promise<void>;

  listServices: (projectId?: string) => Promise<RailwayProjectServices[]>;
  getServiceStatus: (service: string, projectId?: string) => Promise<RailwayServiceStatus>;
  deploy: (service: string, projectId?: string) => Promise<RailwayDeployAccepted>;
  redeploy: (service: string, projectId?: string) => Promise<RailwayDeployAccepted>;
  getLogs: (service: string, lines?: number, projectId?: string) => Promise<RailwayLogs>;
  listVariables: (service: string, projectId?: string) => Promise<RailwayVariables>;
  getDomains: (service: string, projectId?: string) => Promise<RailwayDomainStatus>;
}

/** Resolved service anchor: everything a tool needs to talk to the API. */
interface ResolvedService {
  projectId: string;
  project: string;
  serviceId: string;
  service: string;
  environmentId: string;
  environment: string;
}

// --- Actionable, secret-free error messages (shared real/mock verbatim) ---

export function authErrorMessage(): string {
  return (
    "Railway rejected the API token — deposit a valid token in the vault " +
    "(scopegate secret add railway_token; create it in Railway dashboard → Tokens). " +
    "The token is injected by the gateway as env and never leaves the bridge"
  );
}

function isAuthError(message: string): boolean {
  return /unauthorized|not authorized|forbidden|invalid (api )?(token|key)|authentication/i.test(message);
}

export function projectNotFoundMessage(projectId: string): string {
  return `Project not found: "${projectId}" — use list_services (without projectId) to see the accessible projects`;
}

export function serviceNotFoundMessage(service: string, project?: string, available?: string[]): string {
  if (project !== undefined) {
    const known = available !== undefined && available.length > 0 ? available.join(", ") : "(none)";
    return `Service not found: "${service}" in project "${project}" — available services: ${known} (use list_services)`;
  }
  return `Service not found: "${service}" in any accessible project — use list_services to see what exists`;
}

export function ambiguousServiceMessage(service: string, projects: string[]): string {
  return `Service "${service}" is ambiguous — it exists in projects ${projects
    .map((p) => `"${p}"`)
    .join(", ")}; pass "projectId" to disambiguate`;
}

export function noDeploymentsMessage(service: string, action: string): string {
  return `Service "${service}" has no deployments yet — ${action}`;
}

// --- GraphQL shapes (verified against the Railway API cookbook) ---

const PROJECTS_QUERY = `query {
  projects {
    edges {
      node {
        id
        name
        services { edges { node { id name } } }
        environments { edges { node { id name } } }
      }
    }
  }
}`;

const PROJECT_QUERY = `query project($id: String!) {
  project(id: $id) {
    id
    name
    services { edges { node { id name } } }
    environments { edges { node { id name } } }
  }
}`;

const DEPLOYMENTS_QUERY = `query deployments($input: DeploymentListInput!, $first: Int) {
  deployments(input: $input, first: $first) {
    edges { node { id status createdAt url staticUrl } }
  }
}`;

const LOGS_QUERY = `query deploymentLogs($deploymentId: String!, $limit: Int) {
  deploymentLogs(deploymentId: $deploymentId, limit: $limit) {
    timestamp
    message
    severity
  }
}`;

const VARIABLES_QUERY = `query variables($projectId: String!, $environmentId: String!, $serviceId: String) {
  variables(projectId: $projectId, environmentId: $environmentId, serviceId: $serviceId)
}`;

const DOMAINS_QUERY = `query domains($projectId: String!, $environmentId: String!, $serviceId: String!) {
  domains(projectId: $projectId, environmentId: $environmentId, serviceId: $serviceId) {
    serviceDomains { id domain }
    customDomains { id domain status { dnsRecords { status } } }
  }
}`;

const DEPLOY_MUTATION = `mutation serviceInstanceDeployV2($serviceId: String!, $environmentId: String!) {
  serviceInstanceDeployV2(serviceId: $serviceId, environmentId: $environmentId)
}`;

const REDEPLOY_MUTATION = `mutation deploymentRedeploy($id: String!) {
  deploymentRedeploy(id: $id) { id status }
}`;

interface GqlService {
  id: string;
  name: string;
}

interface GqlEnvironment {
  id: string;
  name: string;
}

interface GqlProject {
  id: string;
  name: string;
  services: { edges: Array<{ node: GqlService }> } | null;
  environments: { edges: Array<{ node: GqlEnvironment }> } | null;
}

function edgeNodes<T>(conn: { edges: Array<{ node: T }> } | null | undefined): T[] {
  return (conn?.edges ?? []).map((e) => e.node);
}

function toProjectServices(p: GqlProject): RailwayProjectServices {
  const services = edgeNodes(p.services)
    .map((s) => ({ id: s.id, name: s.name }))
    .sort((a, b) => a.name.localeCompare(b.name));
  return { id: p.id, name: p.name, services };
}

function matchService(services: GqlService[], ref: string): GqlService | undefined {
  const needle = ref.trim().toLowerCase();
  return services.find((s) => s.id === ref) ?? services.find((s) => s.name.toLowerCase() === needle);
}

function pickEnvironment(projectName: string, envs: GqlEnvironment[]): GqlEnvironment {
  if (envs.length === 0) {
    throw new Error(`Project "${projectName}" has no environments — create one in the Railway dashboard first`);
  }
  return envs.find((e) => e.name.toLowerCase() === "production") ?? envs[0];
}

// --- Real client -------------------------------------------------------------

export interface RealClientOptions {
  token: string;
  apiUrl: string;
}

export class RealRailwayClient implements RailwayBridgeClient {
  constructor(private readonly opts: RealClientOptions) {}

  /** Stateless HTTP: there is no socket to open (kept for interface parity). */
  async connect(): Promise<void> {}
  async close(): Promise<void> {}

  /**
   * One GraphQL POST. The token travels only in the Authorization header and
   * NEVER appears in thrown messages; auth failures (HTTP 401/403 or GraphQL
   * "unauthorized"-style errors) are normalized to authErrorMessage().
   */
  private async graphql<T>(query: string, variables?: Record<string, unknown>): Promise<T> {
    let res: Response;
    try {
      res = await fetch(this.opts.apiUrl, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${this.opts.token}`,
        },
        body: JSON.stringify({ query, variables }),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (/abort|timeout/i.test(msg)) {
        throw new Error(
          `Railway API request timed out after ${REQUEST_TIMEOUT_MS / 1000}s — retry, or check RAILWAY_API_URL and the network`,
        );
      }
      throw new Error(`Railway API request failed (${msg}) — check RAILWAY_API_URL and the network`);
    }
    if (res.status === 401 || res.status === 403) {
      throw new Error(authErrorMessage());
    }
    if (!res.ok) {
      throw new Error(`Railway API returned HTTP ${res.status} — check RAILWAY_API_URL and the token scope`);
    }
    let body: { data?: T; errors?: Array<{ message?: string }> };
    try {
      body = (await res.json()) as { data?: T; errors?: Array<{ message?: string }> };
    } catch {
      throw new Error("Railway API returned a non-JSON response — check RAILWAY_API_URL");
    }
    if (Array.isArray(body.errors) && body.errors.length > 0) {
      const message = body.errors.map((e) => e?.message ?? "unknown error").join("; ");
      if (isAuthError(message)) throw new Error(authErrorMessage());
      throw new Error(`Railway API error: ${message}`);
    }
    if (body.data === undefined || body.data === null) {
      throw new Error("Railway API returned no data");
    }
    return body.data;
  }

  private async fetchProject(projectId: string): Promise<GqlProject> {
    const data = await this.graphql<{ project: GqlProject | null }>(PROJECT_QUERY, { id: projectId });
    if (data.project === null) throw new Error(projectNotFoundMessage(projectId));
    return data.project;
  }

  private async resolveService(serviceRef: string, projectId?: string): Promise<ResolvedService> {
    if (projectId !== undefined && projectId.trim() !== "") {
      const project = await this.fetchProject(projectId);
      const services = edgeNodes(project.services);
      const svc = matchService(services, serviceRef);
      if (svc === undefined) {
        throw new Error(
          serviceNotFoundMessage(serviceRef, project.name, services.map((s) => s.name)),
        );
      }
      const env = pickEnvironment(project.name, edgeNodes(project.environments));
      return {
        projectId: project.id,
        project: project.name,
        serviceId: svc.id,
        service: svc.name,
        environmentId: env.id,
        environment: env.name,
      };
    }

    const data = await this.graphql<{ projects: { edges: Array<{ node: GqlProject }> } }>(PROJECTS_QUERY);
    const projects = data.projects.edges.map((e) => e.node);
    const matches: Array<{ project: GqlProject; service: GqlService }> = [];
    for (const project of projects) {
      const svc = matchService(edgeNodes(project.services), serviceRef);
      if (svc !== undefined) matches.push({ project, service: svc });
    }
    if (matches.length === 0) throw new Error(serviceNotFoundMessage(serviceRef));
    if (matches.length > 1) {
      throw new Error(ambiguousServiceMessage(serviceRef, matches.map((m) => m.project.name)));
    }
    const m = matches[0];
    const env = pickEnvironment(m.project.name, edgeNodes(m.project.environments));
    return {
      projectId: m.project.id,
      project: m.project.name,
      serviceId: m.service.id,
      service: m.service.name,
      environmentId: env.id,
      environment: env.name,
    };
  }

  private async latestDeployment(r: ResolvedService): Promise<RailwayDeploymentInfo | null> {
    const data = await this.graphql<{
      deployments: { edges: Array<{ node: { id: string; status: string; createdAt: string; url: string | null; staticUrl: string | null } }> };
    }>(DEPLOYMENTS_QUERY, {
      input: { projectId: r.projectId, serviceId: r.serviceId, environmentId: r.environmentId },
      first: 1,
    });
    const node = data.deployments.edges[0]?.node;
    if (node === undefined) return null;
    return { id: node.id, status: node.status, createdAt: node.createdAt, url: node.url ?? node.staticUrl ?? null };
  }

  async listServices(projectId?: string): Promise<RailwayProjectServices[]> {
    if (projectId !== undefined && projectId.trim() !== "") {
      return [toProjectServices(await this.fetchProject(projectId))];
    }
    const data = await this.graphql<{ projects: { edges: Array<{ node: GqlProject }> } }>(PROJECTS_QUERY);
    return data.projects.edges.map((e) => toProjectServices(e.node)).sort((a, b) => a.name.localeCompare(b.name));
  }

  async getServiceStatus(service: string, projectId?: string): Promise<RailwayServiceStatus> {
    const r = await this.resolveService(service, projectId);
    const deployment = await this.latestDeployment(r);
    return {
      projectId: r.projectId,
      project: r.project,
      serviceId: r.serviceId,
      service: r.service,
      environment: r.environment,
      deployment,
    };
  }

  async deploy(service: string, projectId?: string): Promise<RailwayDeployAccepted> {
    const r = await this.resolveService(service, projectId);
    const data = await this.graphql<{ serviceInstanceDeployV2: string | null }>(DEPLOY_MUTATION, {
      serviceId: r.serviceId,
      environmentId: r.environmentId,
    });
    return {
      accepted: true,
      kind: "deploy",
      deploymentId: data.serviceInstanceDeployV2 ?? null,
      projectId: r.projectId,
      project: r.project,
      serviceId: r.serviceId,
      service: r.service,
      environment: r.environment,
    };
  }

  async redeploy(service: string, projectId?: string): Promise<RailwayDeployAccepted> {
    const r = await this.resolveService(service, projectId);
    const latest = await this.latestDeployment(r);
    if (latest === null) {
      throw new Error(noDeploymentsMessage(r.service, "use deploy to trigger the first one"));
    }
    const data = await this.graphql<{ deploymentRedeploy: { id: string } | null }>(REDEPLOY_MUTATION, {
      id: latest.id,
    });
    return {
      accepted: true,
      kind: "redeploy",
      deploymentId: data.deploymentRedeploy?.id ?? latest.id,
      projectId: r.projectId,
      project: r.project,
      serviceId: r.serviceId,
      service: r.service,
      environment: r.environment,
    };
  }

  async getLogs(service: string, lines?: number, projectId?: string): Promise<RailwayLogs> {
    const r = await this.resolveService(service, projectId);
    const latest = await this.latestDeployment(r);
    if (latest === null) {
      throw new Error(noDeploymentsMessage(r.service, "nothing to read logs from; use deploy first"));
    }
    const limit = lines !== undefined && lines > 0 ? Math.floor(lines) : 100;
    const data = await this.graphql<{ deploymentLogs: Array<{ timestamp: string; message: string; severity: string }> | null }>(
      LOGS_QUERY,
      { deploymentId: latest.id, limit },
    );
    const logs = (data.deploymentLogs ?? []).map((l) => ({
      timestamp: l.timestamp,
      severity: l.severity,
      message: l.message,
    }));
    return {
      projectId: r.projectId,
      project: r.project,
      serviceId: r.serviceId,
      service: r.service,
      deploymentId: latest.id,
      count: logs.length,
      logs,
    };
  }

  async listVariables(service: string, projectId?: string): Promise<RailwayVariables> {
    const r = await this.resolveService(service, projectId);
    const data = await this.graphql<{ variables: Record<string, unknown> | null }>(VARIABLES_QUERY, {
      projectId: r.projectId,
      environmentId: r.environmentId,
      serviceId: r.serviceId,
    });
    // HARD REDACTION: only NAMES leave the bridge — any value the API returned
    // is replaced by REDACTED right here (frozen contract, registry/railway.yaml).
    const names = Object.keys(data.variables ?? {}).sort((a, b) => a.localeCompare(b));
    const variables = names.map((name) => ({ name, value: REDACTED }));
    return {
      projectId: r.projectId,
      project: r.project,
      serviceId: r.serviceId,
      service: r.service,
      environment: r.environment,
      count: variables.length,
      variables,
    };
  }

  async getDomains(service: string, projectId?: string): Promise<RailwayDomainStatus> {
    const r = await this.resolveService(service, projectId);
    const data = await this.graphql<{
      domains: {
        serviceDomains: Array<{ id: string; domain: string }> | null;
        customDomains: Array<{ id: string; domain: string; status: { dnsRecords: Array<{ status: string }> | null } | null }> | null;
      } | null;
    }>(DOMAINS_QUERY, {
      projectId: r.projectId,
      environmentId: r.environmentId,
      serviceId: r.serviceId,
    });
    const serviceDomains = (data.domains?.serviceDomains ?? []).map((d) => ({ id: d.id, domain: d.domain }));
    const customDomains = (data.domains?.customDomains ?? []).map((d) => {
      const records = d.status?.dnsRecords ?? [];
      const dnsStatus =
        records.length === 0 ? null : records.every((rec) => rec.status === "VALID") ? "VALID" : records.map((rec) => rec.status).join(",");
      return { id: d.id, domain: d.domain, dnsStatus };
    });
    return {
      projectId: r.projectId,
      project: r.project,
      serviceId: r.serviceId,
      service: r.service,
      environment: r.environment,
      serviceDomains,
      customDomains,
    };
  }
}

// --- Factory -------------------------------------------------------------------

/**
 * Picks the backend from the environment (frozen contract):
 *   RAILWAY_MOCK=1 → in-memory mock (no network, token not validated);
 *   otherwise      → real client (requires RAILWAY_TOKEN; RAILWAY_API_URL optional).
 */
export function createRailwayClient(env: NodeJS.ProcessEnv = process.env): RailwayBridgeClient {
  if (env.RAILWAY_MOCK === "1") return createMockClient();
  const token = env.RAILWAY_TOKEN;
  if (token === undefined || token.trim() === "") {
    throw new Error(
      "railway-bridge: missing required env RAILWAY_TOKEN — deposit a Railway API token in the vault " +
        "(scopegate secret add railway_token); the gateway injects it as env at spawn " +
        "(or set RAILWAY_MOCK=1 for the in-memory mock)",
    );
  }
  const apiUrl = env.RAILWAY_API_URL !== undefined && env.RAILWAY_API_URL.trim() !== "" ? env.RAILWAY_API_URL.trim() : DEFAULT_API_URL;
  return new RealRailwayClient({ token, apiUrl });
}
