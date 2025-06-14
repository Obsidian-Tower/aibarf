// src/utils/validators.js

export function validatePassword(pw) {
  const errs = [];
  if (pw.length < 8) errs.push('At least 8 chars');
  if (!/[A-Za-z]/.test(pw)) errs.push('Must contain letters');
  if (!/[0-9]/.test(pw)) errs.push('Must contain a number');
  return errs;
}
