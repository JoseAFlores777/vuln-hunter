// LAB vuln-hunter — vulnerabilidades PLANTADAS (no usar en prod)
export default function Page({ userBio }) {
  // PLANTADA: XSS via dangerouslySetInnerHTML con input de usuario (A03/A05, CWE-79)
  return <div dangerouslySetInnerHTML={{ __html: userBio }} />;
}

// PLANTADA: secreto expuesto al cliente por prefijo NEXT_PUBLIC_ (A02)
export const API_SECRET = process.env.NEXT_PUBLIC_API_SECRET;
