import { randomUUID } from 'node:crypto';
import type { AuditReport, Dependency, VulnMatch } from '../types.ts';
import { ENGINE_NAME, ENGINE_VERSION } from '../version.ts';

const enc = encodeURIComponent;

/** Package URL (purl) for a dependency. Unresolved ranges get no version. */
export function purlFor(dep: Dependency): string {
  const version = dep.resolved ? `@${enc(dep.version)}` : '';
  switch (dep.ecosystem) {
    case 'npm': {
      if (dep.name.startsWith('@') && dep.name.includes('/')) {
        const [scope, name] = dep.name.split('/', 2) as [string, string];
        return `pkg:npm/${enc(scope)}/${enc(name)}${version}`;
      }
      return `pkg:npm/${enc(dep.name)}${version}`;
    }
    case 'Packagist': {
      const [vendor, name] = dep.name.split('/', 2);
      return name ? `pkg:composer/${enc(vendor as string)}/${enc(name)}${version}` : `pkg:composer/${enc(dep.name)}${version}`;
    }
    case 'PyPI':
      return `pkg:pypi/${enc(dep.name.toLowerCase().replace(/[-_.]+/g, '-'))}${version}`;
    case 'NuGet':
      return `pkg:nuget/${enc(dep.name)}${version}`;
  }
}

const refFor = (dep: Dependency): string => `${dep.ecosystem}:${dep.name}@${dep.version}`;

function splitName(dep: Dependency): { group?: string; name: string } {
  if ((dep.ecosystem === 'npm' && dep.name.startsWith('@')) || dep.ecosystem === 'Packagist') {
    const i = dep.name.indexOf('/');
    if (i > 0) return { group: dep.name.slice(0, i), name: dep.name.slice(i + 1) };
  }
  return { name: dep.name };
}

/**
 * CycloneDX 1.5 JSON SBOM. Covers the EU Cyber Resilience Act's machine-readable SBOM duty
 * (top-level dependencies at minimum), and includes known vulnerabilities when the scan ran online.
 */
export function toCycloneDx(
  report: AuditReport,
  deps: Dependency[],
  vulns: VulnMatch[] = [],
  options: { serialNumber?: string } = {},
): Record<string, unknown> {
  const components = deps.map((d) => {
    const { group, name } = splitName(d);
    return {
      type: 'library',
      'bom-ref': refFor(d),
      ...(group ? { group } : {}),
      name,
      version: d.version,
      purl: purlFor(d),
      scope: d.dev ? 'excluded' : 'required',
      properties: [
        { name: 'prohori:resolved', value: String(d.resolved) },
        { name: 'prohori:direct', value: String(d.direct) },
        { name: 'prohori:source', value: d.source },
      ],
    };
  });

  const bom: Record<string, unknown> = {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber: options.serialNumber ?? `urn:uuid:${randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: report.scannedAt,
      tools: { components: [{ type: 'application', name: ENGINE_NAME, version: ENGINE_VERSION }] },
      component: { type: 'application', 'bom-ref': 'root', name: report.project.name },
    },
    components,
    dependencies: [{ ref: 'root', dependsOn: deps.filter((d) => d.direct).map(refFor) }],
  };

  if (vulns.length) {
    bom.vulnerabilities = vulns.map((v) => ({
      'bom-ref': `vuln:${v.id}:${refFor(v.dependency)}`,
      id: v.id,
      source: { name: 'OSV', url: `https://osv.dev/vulnerability/${enc(v.id)}` },
      ratings: [{ severity: v.severity }],
      description: v.summary,
      ...(v.fixedIn ? { recommendation: `Upgrade ${v.dependency.name} to ${v.fixedIn} or later.` } : {}),
      affects: [{ ref: refFor(v.dependency) }],
    }));
  }
  return bom;
}
