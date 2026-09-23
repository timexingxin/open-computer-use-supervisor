import { extractCanonicalExecutable } from '../../core/identity.mjs';

/**
 * Checks whether a command or path belongs to a standalone user-facing ZCode application.
 *
 * @param {string} command
 * @param {string} [comm='']
 * @returns {boolean}
 */
export function isStandaloneUserZCode(command, comm = '') {
  const canonical = extractCanonicalExecutable(command, comm);
  if (!canonical) return false;
  if (/ZCode\.app\/Contents\/MacOS\/ZCode$/i.test(canonical)) {
    // If not invoked as a headless bridge runner or helper
    if (!command.includes('--launcher-pid') && !command.includes('zcode-cua-bridge')) {
      return true;
    }
  }
  return false;
}

/**
 * Checks whether a command line represents a ZCode CUA Helper daemon.
 *
 * @param {string} command
 * @returns {boolean}
 */
export function isZCodeCuaHelper(command) {
  return command.includes('ZCode Computer Use') || (command.includes('--launcher-pid') && command.includes('--socket'));
}
