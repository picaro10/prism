import type { Analyzer, AnalyzerResult, ProjectScan, FileReader, Finding } from '../core/types.js';
import { basename, extname } from 'node:path';

/**
 * ConsistencyAnalyzer — Detects the "many hands / many models" fingerprint.
 *
 * Not a bug hunter — a smell detector. Code assembled by multiple people or
 * AI models over time drifts: file names follow three different conventions,
 * Spanish and English mix inside identifiers, tabs and spaces coexist. None
 * of these break the build, but together they signal a project that was never
 * held to a single standard.
 *
 * Reports at the PROJECT level (the global pattern), not file-by-file, to keep
 * the signal high and the noise low — PRISM's north star is credibility.
 *
 * Checks:
 * - CON-001: Mixed file-naming conventions within a language
 * - CON-002: Mixed natural language (Spanish + English) in code
 * - CON-003: Inconsistent indentation (tabs vs spaces) across the codebase
 */
export class ConsistencyAnalyzer implements Analyzer {
  readonly name = 'consistency';
  readonly category = 'consistency' as const;
  readonly description = 'Detects naming, language, and formatting inconsistency across the codebase';

  async analyze(scan: ProjectScan, readFile: FileReader): Promise<AnalyzerResult> {
    const findings: Finding[] = [];
    let score = 10;

    const sourceFiles = scan.files.filter((f) => isAnalyzableSource(f));

    // --- CON-001: Mixed file-naming conventions ---
    const namingFinding = checkNamingConventions(sourceFiles);
    if (namingFinding) {
      findings.push(namingFinding);
      score -= 1.5;
    }

    // --- CON-002 & CON-003 need file contents ---
    const mixedLangFiles: string[] = [];
    const indentStyles = { tabs: 0, spaces: 0, mixed: 0 };

    for (const file of sourceFiles) {
      let content: string;
      try {
        content = await readFile(file);
      } catch {
        continue;
      }

      // CON-002: mixed Spanish + English inside one file
      const spanish = detectSpanishTokens(content);
      if (spanish.length >= 2 && hasEnglishIdentifiers(content)) {
        mixedLangFiles.push(file);
      }

      // CON-003: indentation style per file
      const indent = detectIndentation(content);
      if (indent === 'tabs') indentStyles.tabs++;
      else if (indent === 'spaces') indentStyles.spaces++;
      else if (indent === 'mixed') indentStyles.mixed++;
    }

    if (mixedLangFiles.length > 0) {
      const shown = mixedLangFiles.slice(0, 8);
      // Always low severity: language mixing is a soft signal. A localized
      // product (Spanish domain vocabulary) is a legitimate, consistent choice —
      // only the intelligence layer can tell that apart from careless drift.
      // The static layer flags; it does not condemn.
      findings.push({
        id: 'CON-002',
        category: 'consistency',
        severity: 'low',
        title: `Mixed natural language (Spanish + English) in ${mixedLangFiles.length} file(s)`,
        description:
          'Spanish and English appear together inside identifiers/comments. This can be the fingerprint of code written partly by hand and partly by an AI model — or an intentional choice for a localized domain. Worth a human/LLM review to decide which.',
        suggestion:
          'If unintentional, standardize on one language for code identifiers. If the Spanish is deliberate domain vocabulary, this is fine — consider it informational.',
        meta: { files: shown, total: mixedLangFiles.length },
      });
      score -= Math.min(1, 0.1 * mixedLangFiles.length);
    }

    // CON-003: codebase mixes indentation styles
    const distinctStyles = [indentStyles.tabs, indentStyles.spaces].filter((n) => n > 0).length;
    if (indentStyles.mixed > 0 || distinctStyles > 1) {
      findings.push({
        id: 'CON-003',
        category: 'consistency',
        severity: 'low',
        title: 'Inconsistent indentation across the codebase',
        description: `Indentation is not uniform: ${indentStyles.spaces} file(s) use spaces, ${indentStyles.tabs} use tabs, ${indentStyles.mixed} mix both within a single file.`,
        suggestion: 'Adopt one indentation style and enforce it with an editorconfig or formatter.',
        meta: { ...indentStyles },
      });
      score -= 0.5;
    }

    // --- Positive signal ---
    if (findings.length === 0 && sourceFiles.length > 5) {
      score = Math.min(10, score + 0.3);
    }

    return {
      category: 'consistency',
      score: Math.max(0, Math.min(10, Math.round(score * 10) / 10)),
      findings,
      summary: buildSummary(findings, sourceFiles.length),
    };
  }
}

// ============================================================
// Helpers
// ============================================================

const CODE_EXTENSIONS = ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.py', '.rs', '.go', '.java'];

function isAnalyzableSource(path: string): boolean {
  return CODE_EXTENSIONS.includes(extname(path));
}

export type NamingConvention = 'kebab' | 'snake' | 'camel' | 'pascal' | 'lower' | 'other';

/**
 * Classify a file's base name (without extension) into a naming convention.
 */
export function classifyNamingConvention(name: string): NamingConvention {
  if (name.includes('-')) return 'kebab';
  if (name.includes('_')) return 'snake';
  if (/^[A-Z][a-zA-Z0-9]*$/.test(name) && /[a-z]/.test(name)) return 'pascal';
  if (/^[a-z][a-zA-Z0-9]*[A-Z]/.test(name)) return 'camel';
  if (/^[a-z][a-z0-9]*$/.test(name)) return 'lower';
  return 'other';
}

/**
 * CON-001: detect when source files of the same language mix naming conventions.
 * 'lower' (single-word names like index, utils) is convention-neutral and is
 * not counted as a distinct style — it coexists with anything.
 */
function checkNamingConventions(files: string[]): Finding | null {
  const byLang = new Map<string, Map<NamingConvention, number>>();

  for (const file of files) {
    const ext = extname(file);
    const stem = basename(file, ext);
    const convention = classifyNamingConvention(stem);
    if (convention === 'lower' || convention === 'other') continue;

    if (!byLang.has(ext)) byLang.set(ext, new Map());
    const counts = byLang.get(ext)!;
    counts.set(convention, (counts.get(convention) ?? 0) + 1);
  }

  const offenders: string[] = [];
  for (const [ext, counts] of byLang) {
    if (counts.size > 1) {
      const breakdown = [...counts.entries()].map(([conv, n]) => `${conv} (${n})`).join(', ');
      offenders.push(`${ext}: ${breakdown}`);
    }
  }

  if (offenders.length === 0) return null;

  return {
    id: 'CON-001',
    category: 'consistency',
    severity: 'low',
    title: 'Mixed file-naming conventions',
    description: `Source files mix naming conventions within the same language. ${offenders.join(' · ')}. Inconsistent file naming makes a codebase harder to navigate and signals multiple unaligned authors.`,
    suggestion: 'Pick one file-naming convention per language (e.g. kebab-case for TS modules) and rename outliers.',
    meta: { offenders },
  };
}

/**
 * Distinctly-Spanish tokens common in code. Excludes English/Spanish
 * homographs (error, total, final, real, control, ...) to avoid false hits.
 */
const SPANISH_WORDS = new Set([
  'usuario',
  'usuarios',
  'contrasena',
  'contraseña',
  'archivo',
  'archivos',
  'datos',
  'fecha',
  'fechas',
  'nombre',
  'nombres',
  'correo',
  'pedido',
  'pedidos',
  'producto',
  'productos',
  'factura',
  'facturas',
  'mensaje',
  'mensajes',
  'guardar',
  'buscar',
  'crear',
  'eliminar',
  'borrar',
  'actualizar',
  'enviar',
  'recibir',
  'cliente',
  'clientes',
  'servidor',
  'servicio',
  'servicios',
  'configuracion',
  'configuración',
  'respuesta',
  'solicitud',
  'ejemplo',
  'prueba',
  'pruebas',
  'valor',
  'valores',
  'lista',
  'listas',
  'cuenta',
  'cuentas',
  'tarjeta',
  'pago',
  'pagos',
  'precio',
  'cantidad',
  'resumen',
  'detalle',
  'detalles',
  'registro',
  'ingreso',
  'salida',
  'esto',
  'guarda',
  'devuelve',
  'obtener',
  'calcular',
  'validar',
  'mostrar',
  'cargar',
  'limpiar',
]);

/**
 * Tokenize source content into lowercase words, splitting on non-letters AND
 * camelCase boundaries, then return the distinctly-Spanish tokens found.
 */
export function detectSpanishTokens(content: string): string[] {
  const found = new Set<string>();
  for (const word of tokenizeWords(content)) {
    if (SPANISH_WORDS.has(word)) found.add(word);
  }
  return [...found];
}

/** Whether the content contains identifiers/words that look English (heuristic). */
function hasEnglishIdentifiers(content: string): boolean {
  const english = new Set([
    'function',
    'const',
    'return',
    'class',
    'import',
    'export',
    'def',
    'self',
    'value',
    'data',
    'name',
    'user',
    'get',
    'set',
    'create',
    'update',
    'delete',
    'list',
    'result',
    'response',
    'request',
    'error',
    'true',
    'false',
    'this',
  ]);
  for (const word of tokenizeWords(content)) {
    if (english.has(word)) return true;
  }
  return false;
}

/** Split text into lowercased word tokens, breaking camelCase apart. */
function tokenizeWords(content: string): string[] {
  // Split camelCase/PascalCase: insert a space before interior capitals.
  const spaced = content.replace(/([a-z0-9])([A-Z])/g, '$1 $2');
  const matches = spaced.match(/[A-Za-zÁÉÍÓÚáéíóúÑñ]+/g) ?? [];
  return matches.map((w) => w.toLowerCase());
}

export type IndentStyle = 'tabs' | 'spaces' | 'mixed' | 'none';

/**
 * Determine the indentation style of a file from its indented lines.
 */
export function detectIndentation(content: string): IndentStyle {
  let tabs = 0;
  let spaces = 0;
  for (const line of content.split('\n')) {
    if (/^\t/.test(line)) tabs++;
    else if (/^ {2,}/.test(line)) spaces++;
  }
  if (tabs > 0 && spaces > 0) return 'mixed';
  if (tabs > 0) return 'tabs';
  if (spaces > 0) return 'spaces';
  return 'none';
}

function buildSummary(findings: Finding[], fileCount: number): string {
  if (findings.length === 0) {
    return `${fileCount} source files · naming, language, and formatting are consistent`;
  }
  return `${findings.length} consistency issue(s) across ${fileCount} source files: ${findings
    .map((f) => f.id)
    .join(', ')}`;
}
